//! Static assets, compiled into the binary by `rust-embed`.
//!
//! Nothing is read from disk at runtime, so there is no static-file handler to
//! path-traverse: a request either names an asset that was embedded at build
//! time or it 404s.

use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

/// Raw bytes of an embedded asset, for the handful of places that need to
/// template one before serving it (the login page's CSRF field).
pub fn raw(path: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
    Assets::get(path).map(|file| file.data)
}

/// The terminal page. Behind the session check: an unauthenticated visitor gets
/// the login form, never the app shell.
pub async fn index(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    jar: axum_extra::extract::CookieJar,
    headers: HeaderMap,
) -> Response {
    if state.auth.session(&jar).is_none() {
        return axum::response::Redirect::to("/login").into_response();
    }
    serve("index.html", &headers)
}

pub async fn asset(Path(path): Path<String>, headers: HeaderMap) -> Response {
    serve(&path, &headers)
}

fn serve(path: &str, headers: &HeaderMap) -> Response {
    let Some(file) = Assets::get(path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    // rust-embed hands us a content hash for free; it makes a perfectly good
    // strong ETag, so reloads cost a 304 instead of re-sending ~400KB of
    // xterm.js on every page load.
    let etag = format!("\"{}\"", hex(&file.metadata.sha256_hash()));

    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|candidate| candidate.trim() == etag));

    if fresh {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type(path).to_string()),
            (header::ETAG, etag),
            // Revalidate every time: the ETag makes that cheap, and it means a
            // rebuilt binary never serves a stale UI against a new protocol.
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        file.data,
    )
        .into_response()
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}
