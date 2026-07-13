//! Typed errors. Anything that can surface on a request or WebSocket path lives
//! here so those paths never need `unwrap`/`expect`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// `portable-pty` reports failures as `anyhow::Error`, so we flatten to a
    /// string at the boundary rather than leaking `anyhow` into our types.
    #[error("pty error: {0}")]
    Pty(String),

    #[error("the terminal session has already ended")]
    SessionClosed,

    #[error("bad request: {0}")]
    BadRequest(String),
}

impl Error {
    pub fn pty(err: impl std::fmt::Display) -> Self {
        Self::Pty(err.to_string())
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::SessionClosed => StatusCode::GONE,
            Self::Config(_) | Self::Io(_) | Self::Pty(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();

        // Log the detail, return a generic body: internal errors must not
        // describe our filesystem or shell configuration to a caller.
        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
            (status, "internal server error").into_response()
        } else {
            tracing::debug!(error = %self, "request rejected");
            (status, self.to_string()).into_response()
        }
    }
}
