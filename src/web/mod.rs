//! HTTP surface: routes, security headers, and the WebSocket upgrade.

pub mod api;
pub mod assets;
pub mod login;
pub mod ws;

use axum::Router;
use axum::http::{HeaderName, HeaderValue, header};
use axum::routing::{delete, get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Locked down as far as xterm.js allows.
///
/// `style-src` needs `'unsafe-inline'`: xterm.js injects a `<style>` element at
/// runtime to size the character grid. That is the one concession. Scripts,
/// frames, objects and remote origins are all denied, and since this app never
/// renders untrusted HTML there is no injection surface for it to widen.
const CSP: &str = "default-src 'none'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     base-uri 'none'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// A login form is a few hundred bytes. Anything larger is not a login form.
const MAX_BODY: usize = 8 * 1024;

pub fn router(state: AppState) -> Router {
    // Public: the login page and the health check. Everything else requires a
    // session, enforced inside the handlers by the `Authenticated` extractor
    // (`/ws`) or an explicit redirect (`/`).
    Router::new()
        .route("/", get(assets::index))
        .route("/login", get(login::page).post(login::submit))
        .route("/logout", post(login::logout))
        .route("/assets/{*path}", get(assets::asset))
        .route("/ws", get(ws::handler))
        .route("/api/terminals", get(api::list))
        .route("/api/terminals/{id}", delete(api::close))
        .route("/healthz", get(healthz))
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(header_layer(header::CONTENT_SECURITY_POLICY, CSP))
        .layer(header_layer(
            HeaderName::from_static("x-content-type-options"),
            "nosniff",
        ))
        .layer(header_layer(header::REFERRER_POLICY, "no-referrer"))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn header_layer(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
}

/// Unauthenticated on purpose, so a tunnel or a container orchestrator can
/// probe it. It reveals nothing but liveness.
async fn healthz() -> &'static str {
    "ok"
}
