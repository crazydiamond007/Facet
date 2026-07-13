//! Append-only audit log.
//!
//! Every authentication decision and every terminal session start/stop, with a
//! timestamp and an IP. Emitted to the tracing subscriber always, and appended
//! as JSON lines to a file when one is configured, so that shipping the log
//! somewhere is `tail -f` and nothing more.
//!
//! `log` is infallible on purpose. An audit sink that can fail a request would
//! be a denial-of-service lever; a failing sink is loud in the logs instead.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

use parking_lot::Mutex;
use serde::Serialize;

static SINK: OnceLock<Option<Mutex<File>>> = OnceLock::new();

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    LoginSucceeded {
        ip: IpAddr,
        session: String,
    },
    LoginFailed {
        ip: IpAddr,
        reason: &'static str,
    },
    Logout {
        session: String,
    },
    /// A pty was opened under an authenticated session.
    TerminalOpened {
        ip: IpAddr,
        session: String,
        terminal: String,
        shell: String,
    },
    TerminalClosed {
        ip: IpAddr,
        session: String,
        terminal: String,
        exit_code: Option<u32>,
    },
    /// A WebSocket upgrade we refused, and why.
    UpgradeRejected {
        ip: IpAddr,
        reason: &'static str,
    },
}

/// Point the audit log at a file. Call once, at startup.
pub fn init(path: Option<&Path>) -> std::io::Result<()> {
    let sink = match path {
        Some(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            tracing::info!(path = %path.display(), "audit log");
            Some(Mutex::new(file))
        }
        None => None,
    };

    // A second call is a programming error, not a runtime condition; ignore it.
    let _ = SINK.set(sink);
    Ok(())
}

pub fn log(event: Event) {
    let at = timestamp();

    match &event {
        Event::LoginSucceeded { ip, session } => {
            tracing::info!(target: "audit", %ip, %session, "login succeeded")
        }
        Event::LoginFailed { ip, reason } => {
            tracing::warn!(target: "audit", %ip, reason, "login failed")
        }
        Event::Logout { session } => tracing::info!(target: "audit", %session, "logout"),
        Event::TerminalOpened {
            ip,
            session,
            terminal,
            shell,
        } => tracing::info!(target: "audit", %ip, %session, %terminal, %shell, "terminal opened"),
        Event::TerminalClosed {
            ip,
            session,
            terminal,
            exit_code,
        } => {
            tracing::info!(target: "audit", %ip, %session, %terminal, ?exit_code, "terminal closed")
        }
        Event::UpgradeRejected { ip, reason } => {
            tracing::warn!(target: "audit", %ip, reason, "websocket upgrade rejected")
        }
    }

    let Some(Some(file)) = SINK.get() else {
        return;
    };

    #[derive(Serialize)]
    struct Line<'a> {
        at: &'a str,
        #[serde(flatten)]
        event: &'a Event,
    }

    let Ok(mut json) = serde_json::to_vec(&Line {
        at: &at,
        event: &event,
    }) else {
        tracing::error!("could not serialize audit event");
        return;
    };
    json.push(b'\n');

    let mut file = file.lock();
    if let Err(err) = file.write_all(&json).and_then(|()| file.flush()) {
        // Losing an audit record is serious, but failing the user's request
        // over it would let a full disk lock them out of their own machine.
        tracing::error!(%err, "could not write to the audit log");
    }
}

fn timestamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}
