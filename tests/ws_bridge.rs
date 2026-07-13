//! The full path a browser takes: WebSocket → axum → pty → shell → back.

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Log in, then open an authenticated socket. Every test below needs both,
/// because the WebSocket is the shell and it is gated on a session.
async fn connect(server: &common::Server) -> Socket {
    let client = common::client();
    let cookie = common::session_cookie(&client, server).await;

    let mut request = format!("ws://{}/ws?cols=80&rows=24", server.addr)
        .into_client_request()
        .expect("build request");
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().expect("cookie"));
    request
        .headers_mut()
        .insert(header::ORIGIN, server.origin().parse().expect("origin"));

    let (socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("websocket upgrade accepted");
    socket
}

/// Accumulate terminal output until `needle` shows up, or fail on timeout.
async fn read_until(socket: &mut Socket, needle: &str) -> String {
    let search = async {
        let mut seen = String::new();
        while let Some(Ok(msg)) = socket.next().await {
            match msg {
                Message::Binary(bytes) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                Message::Close(_) => break,
                _ => continue,
            }
            if seen.contains(needle) {
                return seen;
            }
        }
        seen
    };

    match tokio::time::timeout(Duration::from_secs(10), search).await {
        Ok(seen) if seen.contains(needle) => seen,
        Ok(seen) => panic!("stream ended without {needle:?}; saw: {seen:?}"),
        Err(_) => panic!("timed out waiting for {needle:?}"),
    }
}

/// Type a line into the shell.
async fn send_line(socket: &mut Socket, line: &str) {
    socket
        .send(Message::Binary(format!("{line}\r\n").into_bytes().into()))
        .await
        .expect("send stdin");
}

/// Run a command whose *output* is textually different from what was typed, so
/// that the shell's terminal echo of our keystrokes cannot be mistaken for
/// proof that the command actually ran. `A42Z` can only come from execution.
async fn run_arithmetic_probe(socket: &mut Socket) -> String {
    #[cfg(windows)]
    {
        send_line(socket, "set /a v=6*7").await;
        send_line(socket, "echo A%v%Z").await;
    }
    #[cfg(not(windows))]
    {
        send_line(socket, "echo A$((6*7))Z").await;
    }
    read_until(socket, "A42Z").await
}

#[tokio::test]
async fn browser_gets_a_real_shell() {
    let server = common::serve_default().await;
    let mut socket = connect(&server).await;

    let output = run_arithmetic_probe(&mut socket).await;

    assert!(
        output.contains("A42Z"),
        "shell did not execute the command: {output:?}"
    );
}

#[tokio::test]
async fn shell_exit_closes_the_socket() {
    let server = common::serve_default().await;
    let mut socket = connect(&server).await;

    // Make sure the shell is up and listening before we ask it to leave.
    run_arithmetic_probe(&mut socket).await;
    send_line(&mut socket, "exit").await;

    // The child exiting must close the socket from the server side.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = socket.next().await {
            if matches!(msg, Message::Close(_)) {
                return true;
            }
        }
        // Stream ending is also a close, just a blunter one.
        true
    })
    .await;

    assert!(
        closed.is_ok(),
        "socket stayed open after the shell exited; teardown is not propagating"
    );
}

#[tokio::test]
async fn resize_control_message_reaches_the_pty() {
    let server = common::serve_default().await;
    let mut socket = connect(&server).await;
    run_arithmetic_probe(&mut socket).await;

    socket
        .send(Message::Text(
            r#"{"type":"resize","cols":132,"rows":47}"#.into(),
        ))
        .await
        .expect("send resize");

    // Ask the shell itself what size it thinks it is.
    #[cfg(not(windows))]
    {
        send_line(&mut socket, "stty size").await;
        let output = read_until(&mut socket, "47 132").await;
        assert!(output.contains("47 132"), "pty was not resized: {output:?}");
    }
    #[cfg(windows)]
    {
        // No `stty` on cmd.exe; the pty-level resize is covered in tests/pty.rs.
        // Here we only assert the control message did not kill the session.
        let output = run_arithmetic_probe(&mut socket).await;
        assert!(output.contains("A42Z"));
    }
}

#[tokio::test]
async fn malformed_control_message_does_not_kill_the_session() {
    let server = common::serve_default().await;
    let mut socket = connect(&server).await;

    for junk in [
        "not json at all",
        r#"{"type":"nope"}"#,
        r#"{"type":"resize"}"#,
        r#"{"type":"resize","cols":"wide","rows":null}"#,
    ] {
        socket
            .send(Message::Text(junk.into()))
            .await
            .expect("send junk");
    }

    // Session must still be alive and usable.
    let output = run_arithmetic_probe(&mut socket).await;
    assert!(
        output.contains("A42Z"),
        "junk control messages killed the session"
    );
}
