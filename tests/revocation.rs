//! Signing out has to revoke the *token*, not just the browser's copy of it.
//!
//! tests/logout.rs proves the cookie is deleted in a way the browser accepts.
//! That is necessary and it is not sufficient, and the distinction is the whole
//! reason this file exists.
//!
//! A JWT is self-contained: it carries its own proof of authenticity, so anyone
//! holding one can use it without our permission. Deleting the cookie takes the
//! token away from the browser and from nothing else. Anything that captured it
//! along the way (a dev tools pane on a shared machine, a proxy log, a synced
//! browser profile) kept a working key to the shell until the token expired, an
//! hour later by default.
//!
//! So these tests never use a cookie jar. They hold the raw token, exactly as a
//! thief would, and present it after the owner has signed out.

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use reqwest::header::{COOKIE, LOCATION};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

/// A client that does not follow redirects and keeps no cookies, so every
/// request below carries exactly the credential we hand it and nothing else.
fn bare_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

/// Sign in and walk away with the raw `name=value` cookie pair: the token
/// itself, detached from any browser.
async fn steal_token(server: &common::Server) -> String {
    let client = common::client();
    common::session_cookie(&client, server).await
}

async fn logout(server: &common::Server, token: &str) {
    let response = bare_client()
        .post(format!("http://{}/logout", server.addr))
        .header(COOKIE, token)
        .send()
        .await
        .expect("POST /logout");

    assert_eq!(response.status(), StatusCode::SEE_OTHER, "logout failed");
}

/// Try to open a terminal socket with this token. `Ok` means the shell was
/// handed over.
async fn open_terminal(
    server: &common::Server,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    let mut request = format!("ws://{}/ws?cols=80&rows=24", server.addr)
        .into_client_request()
        .expect("build request");
    request
        .headers_mut()
        .insert(header::COOKIE, token.parse().expect("cookie"));
    request
        .headers_mut()
        .insert(header::ORIGIN, server.origin().parse().expect("origin"));

    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
}

#[tokio::test]
async fn a_stolen_token_stops_working_the_moment_the_owner_signs_out() {
    // The regression test. Before the session registry this asserted 200: the
    // token outlived the logout that was supposed to kill it, for as long as an
    // hour, and nothing the owner could do would take it back short of editing
    // the config and restarting the server.
    let server = common::serve_default().await;
    let token = steal_token(&server).await;

    // The token works, so we know we are testing a real credential.
    let before = bare_client()
        .get(format!("http://{}/", server.addr))
        .header(COOKIE, token.clone())
        .send()
        .await
        .expect("GET /");
    assert_eq!(before.status(), StatusCode::OK, "the token never worked");

    logout(&server, &token).await;

    // Same token, same signature, still unexpired. It must be refused anyway.
    let after = bare_client()
        .get(format!("http://{}/", server.addr))
        .header(COOKIE, token)
        .send()
        .await
        .expect("GET /");

    assert_eq!(
        after.status(),
        StatusCode::SEE_OTHER,
        "a token captured before logout still opened the terminal page; \
         signing out revokes nothing"
    );
    assert_eq!(
        after.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

#[tokio::test]
async fn a_stolen_token_cannot_open_a_shell_after_the_owner_signs_out() {
    // The one that actually matters. The page is cosmetic; this is the shell.
    let server = common::serve_default().await;
    let token = steal_token(&server).await;

    logout(&server, &token).await;

    assert!(
        open_terminal(&server, &token).await.is_err(),
        "a revoked token was handed a shell"
    );
}

#[tokio::test]
async fn an_open_terminal_is_detached_when_the_session_is_signed_out() {
    // The other half of the leak. Revoking the token stops it opening *new*
    // sockets, but a socket that was already open sends no further cookies, so
    // nothing would ever re-check it: the shell you left running would stay
    // attached to a session that no longer exists.
    let server = common::serve_default().await;
    let token = steal_token(&server).await;

    let mut socket = open_terminal(&server, &token)
        .await
        .expect("the socket should open while the session is live");

    logout(&server, &token).await;

    // The socket must notice by itself, without the client saying anything.
    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(Ok(message)) = socket.next().await {
            if let Message::Text(text) = message
                && text.contains("session_ended")
            {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the socket to notice the session had ended");

    assert!(
        ended,
        "the socket closed without telling the client why; it will try to \
         reconnect and loop on a 401"
    );
}

#[tokio::test]
async fn a_live_session_is_not_disturbed_by_the_session_check() {
    // The check runs every few seconds against every open socket. If it were
    // wrong in the other direction it would tear down healthy terminals, which
    // is a worse bug than the one it fixes: it would look like a flaky shell.
    let server = common::serve_default().await;
    let token = steal_token(&server).await;

    let mut socket = open_terminal(&server, &token)
        .await
        .expect("socket should open");

    // Comfortably more than one check interval.
    let ended = tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(Ok(message)) = socket.next().await {
            if let Message::Text(text) = message
                && text.contains("session_ended")
            {
                return true;
            }
        }
        false
    })
    .await;

    assert!(
        ended.is_err() || ended == Ok(false),
        "the session check killed a session that was still perfectly valid"
    );

    // And the shell is still there and still listening.
    socket
        .send(Message::Binary(b"echo A$((6*7))Z\r".to_vec().into()))
        .await
        .expect("send");

    let saw = tokio::time::timeout(Duration::from_secs(15), async {
        let mut seen = String::new();
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Binary(bytes) => {
                    // ConPTY will not proceed until something answers its
                    // cursor-position query; a real terminal does it by reflex.
                    if common::wants_cursor_report(&bytes) {
                        let _ = socket.send(Message::Binary(common::DSR_REPLY.into())).await;
                    }
                    seen.push_str(&String::from_utf8_lossy(&bytes));
                    // Not the text we sent: a pty echoes keystrokes, so matching
                    // on the command would pass even if the shell were dead.
                    if seen.contains("A42Z") {
                        return true;
                    }
                }
                Message::Text(text) if text.contains("session_ended") => return false,
                _ => {}
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    assert!(
        saw,
        "the shell stopped responding while the session was live"
    );
}

#[tokio::test]
async fn signing_out_does_not_kill_the_shell_you_left_running() {
    // A deliberate choice, so it gets a test rather than a comment. Terminals
    // outlive their sockets by design: that is what makes reattaching work at
    // all. Signing out detaches the socket and leaves the shell, so signing back
    // in finds the work still there rather than a fresh prompt.
    let server = common::serve_default().await;
    let token = steal_token(&server).await;

    let socket = open_terminal(&server, &token)
        .await
        .expect("socket should open");

    let terminals_before = server.state.terminals.list().len();
    assert_eq!(terminals_before, 1, "expected the one terminal we opened");

    logout(&server, &token).await;
    drop(socket);

    // Give the socket time to notice and detach.
    tokio::time::sleep(Duration::from_secs(8)).await;

    assert_eq!(
        server.state.terminals.list().len(),
        1,
        "signing out reaped a running shell; reattaching after signing back in \
         would land on a fresh prompt and the work would be gone"
    );
}
