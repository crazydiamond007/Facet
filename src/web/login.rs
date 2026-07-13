//! Login: password + TOTP → session cookie.

use axum::Form;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;

use crate::audit::{self, Event};
use crate::auth::Outcome;
use crate::state::AppState;
use crate::web::limit::client_ip;

/// Double-submit CSRF cookie. Readable by JS on purpose. The defence is that
/// an attacker on another origin cannot *read* it to copy into the form body,
/// not that it is secret from our own page.
const CSRF_COOKIE: &str = "facet_csrf";
const CSRF_FIELD: &str = "__CSRF_TOKEN__";

/// Deliberately identical for every failure mode. Telling the user "wrong TOTP"
/// would confirm they had already guessed the password.
const GENERIC_FAILURE: &str = "Incorrect password or code.";

#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
    code: String,
    csrf: String,
}

/// GET /login: issue a CSRF token and stamp it into the form.
pub async fn page(State(state): State<AppState>, jar: CookieJar) -> Response {
    // Already signed in? Skip the form.
    if state.auth.session(&jar).is_some() {
        return Redirect::to("/").into_response();
    }

    let (Some(token), Some(page)) = (random_token(), super::assets::raw("login.html")) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "login unavailable").into_response();
    };

    let html = String::from_utf8_lossy(&page).replace(CSRF_FIELD, &token);
    let jar = jar.add(csrf_cookie(&state, token));

    (jar, Html(html)).into_response()
}

/// POST /login
pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    // Not simply `peer.ip()`: behind a tunnel that is 127.0.0.1 for everyone,
    // and an audit log that answers "who logged in, from where" with "localhost"
    // every time is not answering the question.
    let ip = client_ip(&headers, peer, state.config.server.trust_forwarded_for);

    // CSRF first: the cookie the browser sent must match the field in the body.
    // A cross-origin form can cause the cookie to ride along, but cannot read
    // it to populate the field.
    let cookie_token = jar.get(CSRF_COOKIE).map(|c| c.value().to_string());
    let csrf_ok = cookie_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected.as_bytes(), form.csrf.as_bytes()));

    if !csrf_ok {
        audit::log(Event::LoginFailed { ip, reason: "csrf" });
        return error_page(
            &state,
            jar,
            StatusCode::FORBIDDEN,
            "Session expired. Please try again.",
        );
    }

    // argon2 is intentionally slow; keep it off the async runtime's threads.
    let auth = state.auth.clone();
    let password = form.password;
    let code = form.code;

    let outcome =
        match tokio::task::spawn_blocking(move || auth.authenticate(&password, &code)).await {
            Ok(outcome) => outcome,
            Err(err) => {
                tracing::error!(%err, "auth task panicked");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            }
        };

    match outcome {
        Outcome::Ok { token, jti } => {
            audit::log(Event::LoginSucceeded {
                ip,
                session: jti.clone(),
            });

            // The CSRF cookie is spent. Delete it through the same builder that
            // created it: a removal whose attributes do not match the original
            // (here, `Path=/`) targets a different cookie and does nothing.
            let jar = jar
                .add(session_cookie(&state, token))
                .remove(csrf_cookie(&state, String::new()));

            (jar, Redirect::to("/")).into_response()
        }

        Outcome::LockedOut { retry_after } => {
            audit::log(Event::LoginFailed {
                ip,
                reason: "locked_out",
            });

            let minutes = retry_after.as_secs().div_ceil(60);
            error_page(
                &state,
                jar,
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many failed attempts. Try again in {minutes} minute(s)."),
            )
        }

        failure => {
            audit::log(Event::LoginFailed {
                ip,
                reason: failure.reason(),
            });
            error_page(&state, jar, StatusCode::UNAUTHORIZED, GENERIC_FAILURE)
        }
    }
}

/// POST /logout: drop the cookie. The JWT itself stays valid until it expires
/// (that is the cost of a stateless token), but the browser no longer holds it.
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(claims) = state.auth.session(&jar) {
        audit::log(Event::Logout {
            session: claims.jti,
        });
    }

    // The removal must carry the *same attributes* as the cookie it deletes.
    // See `session_cookie`: get this wrong and logout silently does nothing.
    (
        jar.remove(session_cookie(&state, String::new())),
        Redirect::to("/login"),
    )
        .into_response()
}

/// Re-render the login page with an error banner.
///
/// This must mint a *fresh* CSRF token and set the matching cookie: the failed
/// POST consumed the last one, and a form whose token has no cookie behind it
/// would fail CSRF on every retry, locking the user out with a confusing
/// "session expired" instead of letting them fix their typo.
fn error_page(state: &AppState, jar: CookieJar, status: StatusCode, message: &str) -> Response {
    let (Some(token), Some(page)) = (random_token(), super::assets::raw("login.html")) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "login unavailable").into_response();
    };

    let html = String::from_utf8_lossy(&page)
        .replace(CSRF_FIELD, &token)
        .replace("__ERROR__", &html_escape(message));

    let jar = jar.add(csrf_cookie(state, token));

    (status, jar, Html(html)).into_response()
}

/// The session cookie, attributes and all.
///
/// **One function builds it and one function deletes it, on purpose.** A cookie
/// is deleted by re-sending it with the same attributes and an expiry in the
/// past, and if any attribute differs the browser treats it as a *different*
/// cookie and quietly ignores the deletion.
///
/// That is not a theoretical risk here, it is a bug we shipped. Under TLS the
/// cookie is named `__Host-facet_session`, and the `__Host-` prefix is enforced
/// by the browser: a `Set-Cookie` carrying that prefix without `Secure`, or with
/// a `Domain`, or with a `Path` other than `/`, is rejected outright. Logout was
/// hand-rolling a bare cookie with only `Path` set, so the browser threw the
/// deletion away, the session survived, and the sign out button did nothing at
/// all. The hardening measure broke the thing it was hardening.
///
/// So the attributes live here, once, and both callers go through them.
fn session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(state.auth.cookie_name(), token);
    cookie.set_http_only(true); // JS cannot read it, so XSS cannot steal it
    cookie.set_secure(state.auth.secure_cookies()); // required by the __Host- prefix
    cookie.set_same_site(SameSite::Strict); // no cross-site request carries it
    cookie.set_path("/"); // required by the __Host- prefix
    cookie.set_max_age(
        time::Duration::try_from(state.auth.session_ttl()).unwrap_or(time::Duration::HOUR),
    );
    cookie
}

fn csrf_cookie(state: &AppState, token: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(CSRF_COOKIE, token);
    cookie.set_http_only(false); // the form needs it; see CSRF_COOKIE
    cookie.set_secure(state.auth.secure_cookies());
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::minutes(15));
    cookie
}

/// `None` if the OS CSPRNG failed. That must abort the request: returning a
/// predictable token would quietly disable CSRF protection instead of loudly
/// breaking it.
fn random_token() -> Option<String> {
    use base64::Engine as _;

    let mut bytes = [0u8; 32];
    if let Err(err) = getrandom::fill(&mut bytes) {
        tracing::error!(%err, "OS random number generator failed");
        return None;
    }

    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
