//! Terminals outlive their sockets: tabs, reattach, and scrollback replay.
//!
//! Unix-only, deliberately. These tests interrogate the shell in POSIX syntax
//! (`$$` for its own pid, `VAR=value`, `$(( ))` arithmetic) in order to prove
//! things that are otherwise hard to prove, above all that the *same process*
//! survives a reconnect. `cmd.exe` has no equivalent of `$$` at all.
//!
//! What is not covered here on Windows is the shell dialect, not the code path:
//! the registry under test is platform-independent Rust sitting on the same
//! `pty` abstraction that `tests/pty.rs` and `tests/ws_bridge.rs` do exercise
//! on Windows.
#![cfg(unix)]

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open an authenticated socket, optionally reattaching to a known terminal.
async fn connect(server: &common::Server, cookie: &str, terminal: Option<&str>) -> Socket {
    let mut url = format!("ws://{}/ws?cols=80&rows=24", server.addr);
    if let Some(id) = terminal {
        url.push_str(&format!("&terminal={id}"));
    }

    let mut request = url.into_client_request().expect("build request");
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().expect("cookie"));
    request
        .headers_mut()
        .insert(header::ORIGIN, server.origin().parse().expect("origin"));

    let (socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("upgrade accepted");
    socket
}

/// Read frames until `needle` appears in the terminal output.
async fn read_until(socket: &mut Socket, needle: &str) -> String {
    let search = async {
        let mut seen = String::new();
        while let Some(Ok(msg)) = socket.next().await {
            if let Message::Binary(bytes) = msg {
                seen.push_str(&String::from_utf8_lossy(&bytes));
                if seen.contains(needle) {
                    return seen;
                }
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

/// The server announces which terminal we attached to, before any output.
async fn attached_id(socket: &mut Socket) -> (String, usize) {
    let deadline = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(msg)) = socket.next().await {
            if let Message::Text(text) = msg {
                let value: serde_json::Value =
                    serde_json::from_str(&text).expect("control message is json");
                if value["type"] == "attached" {
                    return (
                        value["terminal"].as_str().expect("terminal id").to_string(),
                        value["replayed"].as_u64().expect("replayed") as usize,
                    );
                }
            }
        }
        panic!("socket closed before announcing the terminal");
    });

    deadline.await.expect("attach announcement")
}

async fn send_line(socket: &mut Socket, line: &str) {
    socket
        .send(Message::Binary(format!("{line}\r\n").into_bytes().into()))
        .await
        .expect("send stdin");
}

async fn terminal_list(
    client: &reqwest::Client,
    server: &common::Server,
) -> Vec<serde_json::Value> {
    client
        .get(format!("http://{}/api/terminals", server.addr))
        .send()
        .await
        .expect("GET /api/terminals")
        .json()
        .await
        .expect("json")
}

#[tokio::test]
async fn a_dropped_socket_leaves_the_shell_running_and_replays_on_reattach() {
    // This is the whole point of the design: close the laptop, come back, and
    // the shell, and whatever it printed while you were gone, is still there.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut socket = connect(&server, &cookie, None).await;
    let (id, replayed) = attached_id(&mut socket).await;
    assert_eq!(replayed, 0, "a brand new terminal has nothing to replay");

    // Leave a marker in the scrollback, then vanish mid-session.
    send_line(&mut socket, "echo BEFORE$((6*7))").await;
    read_until(&mut socket, "BEFORE42").await;
    drop(socket);

    // While we are away, the shell keeps running and keeps printing.
    let mut socket = connect(&server, &cookie, Some(&id)).await;
    let (same_id, replayed) = attached_id(&mut socket).await;

    assert_eq!(same_id, id, "reattached to a different terminal");
    assert!(
        replayed > 0,
        "expected scrollback to replay, got {replayed} bytes"
    );

    let replay = read_until(&mut socket, "BEFORE42").await;
    assert!(
        replay.contains("BEFORE42"),
        "scrollback did not replay what we did before disconnecting"
    );

    // And it is the *same shell*: shell variables set before the drop survive.
    send_line(&mut socket, "echo STILL$((6*7))").await;
    read_until(&mut socket, "STILL42").await;
}

#[tokio::test]
async fn the_same_shell_process_is_reused_across_a_reconnect() {
    // Stronger than replaying text: prove the *process* survived, by asking it
    // for its own pid before and after.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut socket = connect(&server, &cookie, None).await;
    let (id, _) = attached_id(&mut socket).await;

    // The two probes use *different* markers on purpose. Reusing one would be
    // worthless: the reattach replays the scrollback, so the first probe's
    // output comes back down the wire and we would happily "find" the old pid
    // without the shell having run anything at all.
    send_line(&mut socket, "echo pid=$$").await;
    let pid_before = read_pid(&mut socket, "pid=").await;
    drop(socket);

    let mut socket = connect(&server, &cookie, Some(&id)).await;
    attached_id(&mut socket).await;

    send_line(&mut socket, "echo again=$$").await;
    let pid_after = read_pid(&mut socket, "again=").await;

    assert_eq!(
        pid_before, pid_after,
        "the shell was restarted instead of reattached"
    );
}

/// Read until `marker` is followed by digits.
///
/// The digits are the point. A pty echoes your keystrokes, so the literal text
/// `echo pid=$$` comes back down the wire before the shell has run anything.
/// Waiting for `pid=` alone would match that echo and prove nothing. Only the
/// *executed* command produces `pid=` followed by a number.
async fn read_pid(socket: &mut Socket, marker: &str) -> String {
    let search = async {
        let mut seen = String::new();
        while let Some(Ok(msg)) = socket.next().await {
            if let Message::Binary(bytes) = msg {
                seen.push_str(&String::from_utf8_lossy(&bytes));
                if let Some(pid) = digits_after(&seen, marker) {
                    return Some(pid);
                }
            }
        }
        None
    };

    tokio::time::timeout(Duration::from_secs(10), search)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {marker:?} followed by a pid"))
        .unwrap_or_else(|| panic!("stream ended before {marker:?} produced a pid"))
}

fn digits_after(haystack: &str, marker: &str) -> Option<String> {
    haystack.split(marker).skip(1).find_map(|chunk| {
        let digits: String = chunk.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    })
}

#[tokio::test]
async fn several_terminals_run_at_once_and_are_independent() {
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut first = connect(&server, &cookie, None).await;
    let (first_id, _) = attached_id(&mut first).await;

    let mut second = connect(&server, &cookie, None).await;
    let (second_id, _) = attached_id(&mut second).await;

    assert_ne!(
        first_id, second_id,
        "the second tab reused the first terminal"
    );

    // Set a variable in one; it must not exist in the other.
    send_line(&mut first, "MARK=alpha; echo SET-$MARK").await;
    read_until(&mut first, "SET-alpha").await;

    // The trailing arithmetic is what makes this waitable. The echoed keystrokes
    // contain `GOT[$MARK]$((6*7))`, so waiting on `GOT[` would match the echo
    // before the shell ran. `]42` can only appear once the line has executed,
    // and it appears whether MARK leaked (`GOT[alpha]42`) or not (`GOT[]42`), so
    // we wait for execution and *then* assert which one it was.
    send_line(&mut second, "echo GOT[$MARK]$((6*7))").await;
    let output = read_until(&mut second, "]42").await;

    assert!(
        output.contains("GOT[]42"),
        "terminals share state; the second shell saw the first's variable: {output:?}"
    );

    assert_eq!(terminal_list(&client, &server).await.len(), 2);
}

#[tokio::test]
async fn the_api_lists_terminals_and_closing_one_kills_it() {
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut socket = connect(&server, &cookie, None).await;
    let (id, _) = attached_id(&mut socket).await;

    let listed = terminal_list(&client, &server).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"].as_str(), Some(id.as_str()));

    let response = client
        .delete(format!("http://{}/api/terminals/{id}", server.addr))
        .send()
        .await
        .expect("DELETE");
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);

    assert!(
        terminal_list(&client, &server).await.is_empty(),
        "closed terminal is still listed"
    );

    // Closing kills the shell, so the attached socket must fall over.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        while socket.next().await.is_some() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "socket stayed open after the terminal was closed"
    );
}

#[tokio::test]
async fn the_terminals_api_needs_a_session() {
    let server = common::serve_default().await;
    let anonymous = common::client(); // never logs in

    let response = anonymous
        .get(format!("http://{}/api/terminals", server.addr))
        .send()
        .await
        .expect("GET /api/terminals");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reattaching_to_an_unknown_terminal_gives_a_fresh_one() {
    // A terminal that was reaped or whose shell exited while we were away must
    // not 500 or hang; the client just gets a new shell.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut socket = connect(&server, &cookie, Some("does-not-exist")).await;
    let (id, replayed) = attached_id(&mut socket).await;

    assert_ne!(id, "does-not-exist");
    assert_eq!(replayed, 0);

    send_line(&mut socket, "echo NEW$((6*7))").await;
    read_until(&mut socket, "NEW42").await;
}

#[tokio::test]
async fn the_terminal_limit_is_enforced() {
    // Otherwise a buggy or hostile client could fork-bomb by opening tabs.
    let (mut config, secret) = common::test_config(common::interactive_shell());
    config.terminals.max = 2;

    let server = common::serve(config, secret).await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut first = connect(&server, &cookie, None).await;
    attached_id(&mut first).await;
    let mut second = connect(&server, &cookie, None).await;
    attached_id(&mut second).await;

    // The third must be refused, with an error frame, not a panic.
    let mut third = connect(&server, &cookie, None).await;

    let refused = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(msg)) = third.next().await {
            if let Message::Text(text) = msg
                && text.contains("\"error\"")
            {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out");

    assert!(refused, "the terminal limit was not enforced");
    assert_eq!(terminal_list(&client, &server).await.len(), 2);
}
