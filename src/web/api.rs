//! Small JSON API for tab management. Session-gated like everything else.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::Authenticated;
use crate::state::AppState;
use crate::terminal::Info;

/// GET /api/terminals: what the browser draws its tab bar from.
///
/// This is how tabs survive a page reload: the terminals are server-side and
/// outlive the socket, so the client just asks what exists and reattaches.
pub async fn list(_: Authenticated, State(state): State<AppState>) -> Json<Vec<Info>> {
    Json(state.terminals.list())
}

/// DELETE /api/terminals/{id}: close a tab for real.
///
/// Distinct from merely detaching: this kills the shell. Removing the terminal
/// drops its `Pty`, whose `Drop` kills the child.
pub async fn close(
    _: Authenticated,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if state.terminals.remove(&id) {
        tracing::info!(terminal = %id, "terminal closed by the client");
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
