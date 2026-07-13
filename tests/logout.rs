//! Signing out has to actually sign you out.
//!
//! These tests run against a server configured as it is in production, with
//! `secure_cookies` on, because that is the only configuration in which the bug
//! they guard against can appear.
//!
//! A cookie is deleted by re-sending it with matching attributes and an expiry
//! in the past. If any attribute differs, the browser treats it as a *different*
//! cookie and quietly ignores the deletion. Under TLS the session cookie is
//! named `__Host-facet_session`, and the `__Host-` prefix is enforced by the
//! browser: a `Set-Cookie` with that prefix and no `Secure`, or a `Path` other
//! than `/`, is rejected outright.
//!
//! Logout used to send exactly such a cookie. The browser threw it away, the
//! session survived, and the sign out button did nothing.

mod common;

use reqwest::StatusCode;
use reqwest::header::{COOKIE, SET_COOKIE};

/// A server that believes it is behind TLS, so it uses `__Host-` cookies.
///
/// It is still served over plain HTTP for the test's convenience, which is fine
/// because these tests read the `Set-Cookie` headers directly rather than
/// letting a cookie jar apply them.
async fn serve_secure() -> common::Server {
    let (mut config, secret) = common::test_config(common::interactive_shell());
    config.tls = facet::config::Tls {
        enabled: true,
        ..Default::default()
    };
    common::serve(config, secret).await
}

/// Every `Set-Cookie` on a response, as raw strings.
fn set_cookies(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

fn find<'a>(cookies: &'a [String], name: &str) -> &'a str {
    cookies
        .iter()
        .find(|cookie| cookie.starts_with(name))
        .unwrap_or_else(|| panic!("no {name} cookie in {cookies:?}"))
}

/// Log in without a cookie jar, and hand back the raw session cookie header.
async fn login_raw(server: &common::Server) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let page = client
        .get(format!("http://{}/login", server.addr))
        .send()
        .await
        .expect("GET /login");

    let csrf_header = find(&set_cookies(&page), "facet_csrf").to_owned();
    let csrf_value = csrf_header
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("csrf cookie value");

    let html = page.text().await.expect("body");
    let marker = r#"name="csrf" value=""#;
    let start = html.find(marker).expect("csrf field") + marker.len();
    let token = &html[start..start + html[start..].find('"').expect("quote")];

    let response = client
        .post(format!("http://{}/login", server.addr))
        .header(COOKIE, format!("facet_csrf={csrf_value}"))
        .form(&[
            ("password", common::PASSWORD),
            ("code", &server.totp_code()),
            ("csrf", token),
        ])
        .send()
        .await
        .expect("POST /login");

    assert_eq!(response.status(), StatusCode::SEE_OTHER, "login failed");
    find(&set_cookies(&response), "__Host-facet_session").to_owned()
}

#[tokio::test]
async fn the_session_cookie_is_host_prefixed_and_secure() {
    let server = serve_secure().await;
    let cookie = login_raw(&server).await;

    // The prefix is only meaningful if the attributes it demands are present.
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("Path=/"), "{cookie}");
    assert!(
        !cookie.contains("Domain"),
        "__Host- forbids Domain: {cookie}"
    );
}

#[tokio::test]
async fn logout_sends_a_deletion_the_browser_will_accept() {
    // This is the regression test. The deletion must repeat every attribute of
    // the cookie it is deleting, or the browser ignores it and the user stays
    // signed in.
    let server = serve_secure().await;
    let session = login_raw(&server).await;
    let pair = session.split(';').next().expect("cookie pair");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let response = client
        .post(format!("http://{}/logout", server.addr))
        .header(COOKIE, pair)
        .send()
        .await
        .expect("POST /logout");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let deletion = find(&set_cookies(&response), "__Host-facet_session").to_owned();

    assert!(
        deletion.contains("Secure"),
        "the __Host- prefix requires Secure; without it the browser rejects this \
         deletion outright and the user stays signed in: {deletion}"
    );
    assert!(
        deletion.contains("Path=/"),
        "the __Host- prefix requires Path=/: {deletion}"
    );
    assert!(
        deletion.contains("Max-Age=0") || deletion.contains("Expires="),
        "a deletion has to expire the cookie: {deletion}"
    );
}

#[tokio::test]
async fn a_signed_out_session_cannot_reach_the_terminal() {
    // The behavioural half: after logging out, the browser holds nothing that
    // opens a shell.
    let server = common::serve_default().await;
    let client = common::client(); // keeps cookies, like a browser

    common::login(&client, &server).await;

    // Signed in: the terminal page is served.
    let before = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("GET /");
    assert_eq!(before.status(), StatusCode::OK);

    client
        .post(format!("http://{}/logout", server.addr))
        .send()
        .await
        .expect("POST /logout");

    // Signed out: bounced to the login page.
    let after = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("GET /");

    assert_eq!(
        after.status(),
        StatusCode::SEE_OTHER,
        "the terminal was still reachable after signing out"
    );
    assert_eq!(
        after
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

#[tokio::test]
async fn the_spent_csrf_cookie_is_deleted_on_a_successful_login() {
    // Same class of bug: a removal whose Path does not match the original
    // targets a different cookie and does nothing.
    let server = serve_secure().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let page = client
        .get(format!("http://{}/login", server.addr))
        .send()
        .await
        .expect("GET /login");

    let csrf_header = find(&set_cookies(&page), "facet_csrf").to_owned();
    let csrf_value = csrf_header
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("csrf value");

    let html = page.text().await.expect("body");
    let marker = r#"name="csrf" value=""#;
    let start = html.find(marker).expect("csrf field") + marker.len();
    let token = &html[start..start + html[start..].find('"').expect("quote")];

    let response = client
        .post(format!("http://{}/login", server.addr))
        .header(COOKIE, format!("facet_csrf={csrf_value}"))
        .form(&[
            ("password", common::PASSWORD),
            ("code", &server.totp_code()),
            ("csrf", token),
        ])
        .send()
        .await
        .expect("POST /login");

    let deletion = find(&set_cookies(&response), "facet_csrf").to_owned();
    assert!(
        deletion.contains("Path=/"),
        "the CSRF cookie was set with Path=/, so its deletion needs it too: {deletion}"
    );
}
