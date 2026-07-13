//! Reattaching while `vim`, `htop` or `less` is running.
//!
//! These programs use the alternate screen: a second buffer with no scrollback,
//! painted once and then updated only where it changed. Replaying a log of raw
//! bytes cannot reproduce that, because the paint is the first thing a capped
//! buffer evicts, and the diffs that remain refer to a screen the reattaching
//! client never had.
//!
//! Unix-only, in the same spirit as tests/terminals.rs: these drive a POSIX shell
//! with `printf` and `$(( ))`. The code under test is platform-independent Rust
//! and its logic is covered exhaustively by the unit tests in `src/screen.rs`.
#![cfg(unix)]

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// What a full-screen program puts on the alternate screen.
///
/// Built by the shell with arithmetic rather than typed literally, because a pty
/// echoes your keystrokes: if the marker appeared in the command line, it would
/// appear in the echo, and every assertion below would pass whether or not the
/// screen was ever reconstructed. `SCREEN42` can only exist if the shell ran the
/// line.
const MARKER: &str = "SCREEN42";

/// Enter the alternate screen, clear it, and paint the marker: what vim does on
/// startup, reduced to one line of shell.
const ENTER_AND_PAINT: &str = r"printf '\033[?1049h\033[H\033[2JSCREEN%d' $((6*7))";

/// Leave the alternate screen: what vim does when you `:q`.
const LEAVE: &str = r"printf '\033[?1049l'";

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

async fn attached_id(socket: &mut Socket) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(msg)) = socket.next().await {
            if let Message::Text(text) = msg {
                let value: serde_json::Value =
                    serde_json::from_str(&text).expect("control message is json");
                if value["type"] == "attached" {
                    return value["terminal"].as_str().expect("terminal id").to_string();
                }
            }
        }
        panic!("socket closed before announcing the terminal");
    })
    .await
    .expect("attach announcement")
}

async fn send_line(socket: &mut Socket, line: &str) {
    socket
        .send(Message::Binary(format!("{line}\r\n").into_bytes().into()))
        .await
        .expect("send stdin");
}

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

/// Everything the server sends a client that has just attached, up to the point
/// it goes quiet. That is the replay, which is what these tests are about.
async fn drain_replay(socket: &mut Socket) -> String {
    let mut seen = String::new();

    // Read until the output pauses. A replay arrives as one burst, so a short
    // silence means it is over.
    loop {
        match tokio::time::timeout(Duration::from_millis(700), socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                seen.push_str(&String::from_utf8_lossy(&bytes));
            }
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }

    seen
}

#[tokio::test]
async fn reattaching_to_a_full_screen_program_redraws_it() {
    // The bug this whole module exists for. Open a full-screen program, walk
    // away, come back: the program must be on the screen, not a blank terminal
    // or a spray of half-applied diffs.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut first = connect(&server, &cookie, None).await;
    let id = attached_id(&mut first).await;

    send_line(&mut first, ENTER_AND_PAINT).await;
    read_until(&mut first, MARKER).await;

    // Close the laptop lid.
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Come back to it.
    let mut second = connect(&server, &cookie, Some(&id)).await;
    let same = attached_id(&mut second).await;
    assert_eq!(same, id, "reattached to a different terminal");

    let replay = drain_replay(&mut second).await;

    assert!(
        replay.contains("\x1b[?1049h"),
        "the client was never told to enter the alternate screen, so it would \
         paint the program onto its normal screen and lose the scrollback \
         underneath when the program quits"
    );
    assert!(
        replay.contains(MARKER),
        "the full-screen program was not redrawn on reattach. Replay was: {replay:?}"
    );
}

#[tokio::test]
async fn what_a_full_screen_program_drew_never_enters_the_scrollback() {
    // A real terminal does not let you scroll back through vim after you quit
    // it, because the alternate screen has no scrollback. Neither should this.
    //
    // It is not only cosmetic: alternate-screen bytes in the history are diffs
    // with no paint in front of them, and replaying them into a normal screen is
    // what made reattaching look broken in the first place.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut first = connect(&server, &cookie, None).await;
    let id = attached_id(&mut first).await;

    // Something real in the scrollback, before the program runs.
    send_line(&mut first, "echo A$((6*7))Z").await;
    read_until(&mut first, "A42Z").await;

    send_line(&mut first, ENTER_AND_PAINT).await;
    read_until(&mut first, MARKER).await;

    // Quit it, as `:q` would.
    send_line(&mut first, LEAVE).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut second = connect(&server, &cookie, Some(&id)).await;
    attached_id(&mut second).await;
    let replay = drain_replay(&mut second).await;

    assert!(
        replay.contains("A42Z"),
        "the shell's own history was lost. Replay was: {replay:?}"
    );
    assert!(
        !replay.contains("\x1b[?1049h"),
        "the program has quit, but the client is still being sent into the \
         alternate screen, where it would sit looking at an empty buffer"
    );
    assert!(
        !replay.contains(MARKER),
        "what the program drew leaked into the scrollback. Replay was: {replay:?}"
    );
}

#[tokio::test]
async fn the_program_is_redrawn_even_after_its_paint_has_been_evicted() {
    // The real bug, reproduced honestly.
    //
    // Replaying raw bytes works for a *short* vim session, because the paint is
    // still sitting in the buffer. It falls apart in the case that actually
    // happens to people: you have been in vim for a while, it has sent thousands
    // of small diffs, and the original paint fell off the front of the ring long
    // ago. What is left is diffs referring to a screen the reattaching client
    // never had.
    //
    // So the history here is deliberately tiny, and the program is made to emit
    // far more than that in updates. Nothing that could reproduce the screen is
    // in the byte log any more. It has to be rebuilt.
    let (mut config, secret) = common::test_config(common::interactive_shell());
    config.terminals.scrollback_bytes = 256;
    let server = common::serve(config, secret).await;

    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut first = connect(&server, &cookie, None).await;
    let id = attached_id(&mut first).await;

    send_line(&mut first, ENTER_AND_PAINT).await;
    read_until(&mut first, MARKER).await;

    // The status line vim rewrites on every keystroke: individually meaningless,
    // collectively enough to evict everything that came before.
    send_line(
        &mut first,
        r"i=0; while [ $i -lt 300 ]; do printf '\033[24;1Hrow %d  ' $i; i=$((i+1)); done; printf 'DONE'",
    )
    .await;
    read_until(&mut first, "DONE").await;

    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut second = connect(&server, &cookie, Some(&id)).await;
    attached_id(&mut second).await;
    let replay = drain_replay(&mut second).await;

    assert!(
        replay.contains(MARKER),
        "the program's screen was gone: its paint had been evicted, so a replay \
         of the raw bytes had nothing left to redraw it with. Replay was: {replay:?}"
    );
}

#[tokio::test]
async fn a_live_socket_still_sees_the_program_as_it_happens() {
    // The reconstruction is for clients arriving late. A socket that never left
    // must keep getting the raw byte stream, untouched, or filtering the history
    // would have quietly broken the ordinary case of just using vim.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let mut socket = connect(&server, &cookie, None).await;
    attached_id(&mut socket).await;

    send_line(&mut socket, ENTER_AND_PAINT).await;
    let seen = read_until(&mut socket, MARKER).await;

    assert!(
        seen.contains("\x1b[?1049h"),
        "an attached socket did not receive the alternate screen switch, so vim \
         would draw over the user's shell history in front of them"
    );
}
