//! facet: a single-binary, authenticated web terminal.
//!
//! The crate is split into a library and a thin binary so that integration
//! tests can build a real server in-process.
//!
//! ```text
//! browser ⇄ WSS ⇄ axum ⇄ ws::bridge ⇄ pty master ⇄ shell
//!                   │
//!                   └── auth (argon2 + TOTP) → JWT cookie → Authenticated
//! ```

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod pty;
pub mod screen;
pub mod setup;
pub mod state;
pub mod terminal;
pub mod tls;
pub mod web;

pub use error::{Error, Result};
