//! The WebSocket ⇄ PTY bridge.
//!
//! Wire protocol, deliberately minimal:
//!
//! | Direction       | Frame  | Meaning                                     |
//! |-----------------|--------|---------------------------------------------|
//! | client → server | binary | raw stdin bytes for the shell               |
//! | client → server | text   | JSON control message (currently: `resize`)  |
//! | server → client | binary | raw stdout/stderr bytes from the shell      |
//! | server → client | text   | JSON control (`attached`, `exit`, `error`)  |
//!
//! Splitting data (binary) from control (text) means terminal bytes are never
//! parsed, escaped, or base64'd; they pass through untouched, which is what
//! makes full ANSI colour and control sequences work for free.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;

use crate::audit::{self, Event};
use crate::auth::Authenticated;
use crate::error::Result;
use crate::pty::Size;
use crate::state::AppState;
use crate::terminal::{Attachment, Terminal};
use crate::web::limit::client_ip;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Resize { cols: u16, rows: u16 },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    /// Sent first. Tells the client which terminal it got (it may have asked for
    /// a new one, or reattached to an existing one) and which shell is running
    /// in it, so the status bar reports the truth rather than a guess.
    Attached {
        terminal: String,
        shell: String,
        replayed: usize,
    },
    Exit {
        code: u32,
    },
    Error {
        message: String,
    },
    /// The session behind this socket was signed out or expired.
    ///
    /// Distinct from `error` because the client must react differently: a plain
    /// close makes it reconnect, and reconnecting with a dead session just earns
    /// it a 401 on a loop. This tells it to stop and go and sign in.
    SessionEnded {
        reason: &'static str,
    },
}

impl ServerMsg {
    fn into_frame(self) -> Message {
        // A control message that cannot be serialized is a bug in our own
        // types, not something a client can provoke; degrade rather than panic.
        match serde_json::to_string(&self) {
            Ok(json) => Message::Text(json.into()),
            Err(_) => Message::Text(r#"{"type":"error","message":"internal"}"#.into()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Params {
    /// Reattach to this terminal. Absent (or unknown) means "give me a new one".
    terminal: Option<String>,
    /// Initial geometry, so the first prompt is drawn at the right width
    /// instead of at 80x24 and then reflowing.
    cols: Option<u16>,
    rows: Option<u16>,
}

impl Params {
    fn size(&self) -> Size {
        let default = Size::default();
        Size {
            cols: self.cols.unwrap_or(default.cols),
            rows: self.rows.unwrap_or(default.rows),
        }
        .sanitized()
    }
}

/// Upgrade to a terminal.
///
/// Three gates, all before any pty work happens:
///
/// 1. [`Authenticated`]: a valid, unexpired session cookie, or 401.
/// 2. [`origin_allowed`]: the browser's `Origin` matches where it connected.
/// 3. The upgrade itself.
///
/// The `Authenticated` extractor is what makes an unauthenticated shell
/// unreachable: it runs before this body does, so there is no path through this
/// function that reaches a pty without a verified session.
pub async fn handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Authenticated(claims): Authenticated,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Response {
    let ip = client_ip(&headers, peer, state.config.server.trust_forwarded_for);

    if !origin_allowed(&headers, &state) {
        audit::log(Event::UpgradeRejected {
            ip,
            reason: "origin",
        });
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let session = claims.jti;

    ws.on_upgrade(move |socket| async move {
        if let Err(err) = bridge(socket, state, params, ip, session).await {
            tracing::warn!(%err, "terminal session ended with error");
        }
    })
}

/// Cross-site WebSocket hijacking defence.
///
/// A `SameSite=Strict` session cookie is already not sent on a cross-site
/// handshake, so this is belt-and-braces, but it is the belt that catches a
/// browser or proxy that gets the cookie rules wrong, and it costs one header
/// comparison.
///
/// A *missing* `Origin` is refused rather than waved through. Browsers always
/// send it on a WebSocket upgrade, so anything without one is not the client
/// this app is for.
fn origin_allowed(headers: &HeaderMap, state: &AppState) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };

    if state
        .config
        .server
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return true;
    }

    // Same-origin: the Origin's authority must equal the Host we were reached
    // on. Scheme is not compared: behind a TLS-terminating tunnel the browser
    // legitimately says https while we speak plain http on loopback.
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };

    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .is_some_and(|authority| authority == host)
}

async fn bridge(
    socket: WebSocket,
    state: AppState,
    params: Params,
    ip: IpAddr,
    session: String,
) -> Result<()> {
    let size = params.size();

    // Reattach if the client named a terminal we still have; otherwise spawn a
    // fresh one. An unknown id falls through to "new" rather than erroring:
    // it just means the shell exited or was reaped while the browser was away.
    let (terminal, reattached) = match params
        .terminal
        .as_deref()
        .and_then(|id| state.terminals.get(id))
    {
        Some(terminal) => (terminal, true),
        None => match state.terminals.create(size) {
            Ok(terminal) => (terminal, false),
            Err(err) => {
                let (mut sink, _) = socket.split();
                let msg = ServerMsg::Error {
                    message: "could not start shell".into(),
                };
                let _ = sink.send(msg.into_frame()).await;
                let _ = sink.send(Message::Close(None)).await;
                return Err(err);
            }
        },
    };

    let attachment = terminal.attach();

    // The browser window may be a different size than it was last time.
    attachment.resize(size)?;

    audit::log(Event::TerminalOpened {
        ip,
        session: session.clone(),
        terminal: terminal.id.clone(),
        shell: state.config.shell.program.clone(),
    });

    // Whatever happens below (clean exit, error, browser vanishing), the close
    // event fires, because it is tied to this guard's Drop.
    let _closed = TerminalClosed {
        ip,
        session: session.clone(),
        terminal: terminal.id.clone(),
        exit_code: parking_lot::Mutex::new(None),
    };

    tracing::info!(
        terminal = %terminal.id,
        reattached,
        replay = attachment.replay.len(),
        "attached"
    );

    let result = pump(socket, &terminal, &state, &session, attachment, &_closed).await;

    // Dropping `attachment` (inside `pump`) detaches but leaves the shell
    // running, which is the whole point: the next connection reattaches.
    result
}

/// How often an established socket re-checks that its session still exists.
///
/// The cookie is checked once, at the upgrade, and then never again: a WebSocket
/// sends no further headers, so without this the socket would outlive both its
/// own expiry and an explicit sign-out.
///
/// This interval *is* the window in which a revoked session keeps its shell, so
/// it wants to be short. The check is one hashmap lookup, so there is no cost
/// pushing back: five seconds is chosen to be small, not to be affordable.
const SESSION_CHECK: std::time::Duration = std::time::Duration::from_secs(5);

async fn pump(
    socket: WebSocket,
    terminal: &Terminal,
    state: &AppState,
    session: &str,
    mut attachment: Attachment,
    closed: &TerminalClosed,
) -> Result<()> {
    let (mut sink, mut stream) = socket.split();

    let mut session_check = tokio::time::interval(SESSION_CHECK);

    // Tell the client which terminal it is talking to, then replay what it
    // missed. Order matters: the id must arrive before the bytes, so the client
    // can label the tab before it starts painting into it.
    let replay = std::mem::take(&mut attachment.replay);
    let announce = ServerMsg::Attached {
        terminal: terminal.id.clone(),
        shell: state.config.shell.program.clone(),
        replayed: replay.len(),
    };

    if sink.send(announce.into_frame()).await.is_err() {
        return Ok(());
    }

    if !replay.is_empty() && sink.send(Message::Binary(replay)).await.is_err() {
        return Ok(());
    }

    loop {
        tokio::select! {
            // Still signed in? Asked on a timer because nothing else will tell
            // us: the browser sends no headers on an open socket, so a sign-out
            // in another tab, or the token simply lapsing, would otherwise leave
            // this shell attached to a session that no longer exists.
            //
            // The shell itself is left running. This detaches the *socket*, and
            // the terminal stays in the registry, so signing back in reattaches
            // to the same shell rather than losing the work in it.
            _ = session_check.tick() => {
                if !state.auth.is_live(session) {
                    tracing::info!(terminal = %terminal.id, "session ended; detaching socket");

                    let msg = ServerMsg::SessionEnded { reason: "signed out or expired" };
                    let _ = sink.send(msg.into_frame()).await;
                    let _ = sink.send(Message::Close(None)).await;
                    return Ok(());
                }
            }

            live = attachment.next_output() => {
                match live {
                    Ok(bytes) => {
                        if sink.send(Message::Binary(bytes)).await.is_err() {
                            // Browser vanished mid-write. The shell lives on.
                            return Ok(());
                        }
                    }
                    // The pump dropped the sender: the shell exited.
                    Err(RecvError::Closed) => break,
                    // We could not keep up. Rather than showing a corrupt
                    // screen, tell the client to reconnect. It will get a
                    // clean scrollback replay.
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(terminal = %terminal.id, missed, "attachment lagged");
                        break;
                    }
                }
            }

            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Binary(bytes))) => attachment.pty().write(bytes).await?,
                    Some(Ok(Message::Text(text))) => {
                        if let Err(err) = control(&attachment, text.as_str()) {
                            tracing::debug!(%err, "ignoring bad control message");
                        }
                    }
                    // Client closed, the stream ended, or the socket errored.
                    // Detach, but leave the shell running.
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(err)) => {
                        tracing::debug!(%err, "websocket error");
                        return Ok(());
                    }
                    // Ping/Pong are answered by axum itself.
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    // The shell exited. We do not know its code here (the terminal owns the
    // pty), so report a clean exit and let the client close the tab.
    *closed.exit_code.lock() = Some(0);
    let _ = sink.send(ServerMsg::Exit { code: 0 }.into_frame()).await;
    let _ = sink.send(Message::Close(None)).await;

    Ok(())
}

/// Emits the "terminal closed" audit record from `Drop`.
///
/// The bridge has several exit paths: clean shell exit, socket error, browser
/// disappearing mid-write. Hanging the audit record off `Drop` means none of
/// them can forget to write one, and a future edit that adds a fourth exit path
/// cannot regress it either.
struct TerminalClosed {
    ip: IpAddr,
    session: String,
    terminal: String,
    exit_code: parking_lot::Mutex<Option<u32>>,
}

impl Drop for TerminalClosed {
    fn drop(&mut self) {
        audit::log(Event::TerminalClosed {
            ip: self.ip,
            session: std::mem::take(&mut self.session),
            terminal: std::mem::take(&mut self.terminal),
            exit_code: *self.exit_code.lock(),
        });
    }
}

/// Apply a client control message. Malformed input is rejected, never fatal:
/// a buggy client must not be able to kill a session.
fn control(attachment: &Attachment, text: &str) -> Result<()> {
    let msg: ClientMsg = serde_json::from_str(text)
        .map_err(|e| crate::error::Error::BadRequest(format!("bad control message: {e}")))?;

    match msg {
        ClientMsg::Resize { cols, rows } => {
            let size = Size { cols, rows }.sanitized();
            tracing::trace!(cols = size.cols, rows = size.rows, "resize");
            attachment.resize(size)
        }
    }
}
