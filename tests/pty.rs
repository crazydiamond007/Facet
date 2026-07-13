//! PTY behaviour: it runs a real shell, and it cleans up after itself.

mod common;

use std::time::Duration;

use facet::pty::{self, Size};

/// Drain the pty until EOF, with a timeout so a hang fails loudly.
///
/// `pty` is what lets us behave like a terminal: on Windows, ConPTY opens by
/// asking where the cursor is and refuses to run the shell until it is told.
/// See `common::DSR`. Pass `None` only when the pty has deliberately been
/// dropped and there is nothing left to answer with.
async fn drain(
    pty: Option<&pty::Pty>,
    output: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
) -> String {
    let collect = async {
        let mut buf = Vec::new();
        while let Some(chunk) = output.recv().await {
            if let Some(pty) = pty
                && common::wants_cursor_report(&chunk)
            {
                let _ = pty
                    .write(bytes::Bytes::from_static(common::DSR_REPLY))
                    .await;
            }
            buf.extend_from_slice(&chunk);
        }
        buf
    };

    let buf = tokio::time::timeout(Duration::from_secs(15), collect)
        .await
        .expect("pty reached EOF before the timeout");

    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn runs_echo_hello() {
    let mut session =
        pty::spawn(&common::oneshot_shell("echo hello"), Size::default()).expect("spawn pty");

    let output = drain(Some(&session.pty), &mut session.output).await;

    assert!(
        output.contains("hello"),
        "expected 'hello' in pty output, got: {output:?}"
    );
}

#[tokio::test]
async fn reports_the_shell_exit_code() {
    let mut session =
        pty::spawn(&common::oneshot_shell("exit 3"), Size::default()).expect("spawn pty");

    // Drain first: the reader only sees EOF once the child is gone, so this
    // also proves we do not miss the exit signal by racing it.
    let _ = drain(Some(&session.pty), &mut session.output).await;

    let status = tokio::time::timeout(Duration::from_secs(10), session.exit)
        .await
        .expect("child was reaped before the timeout")
        .expect("exit status was delivered");

    assert_eq!(status.exit_code(), 3);
}

#[tokio::test]
async fn resize_is_visible_to_the_shell() {
    // `stty size` prints "<rows> <cols>", straight from the pty's geometry, so
    // this proves the resize actually reached the kernel and not just our state.
    #[cfg(windows)]
    let script = "exit 0"; // `stty` is not a thing on cmd.exe; covered on Unix.
    #[cfg(not(windows))]
    let script = "sleep 0.3; stty size";

    let mut session =
        pty::spawn(&common::oneshot_shell(script), Size { cols: 80, rows: 24 }).expect("spawn pty");

    session
        .pty
        .resize(Size {
            cols: 132,
            rows: 47,
        })
        .expect("resize");

    let output = drain(Some(&session.pty), &mut session.output).await;

    #[cfg(not(windows))]
    assert!(
        output.contains("47 132"),
        "expected the shell to see 47x132, got: {output:?}"
    );
    #[cfg(windows)]
    let _ = output;
}

#[tokio::test]
async fn dropping_the_pty_kills_the_child() {
    // A shell that would outlive the test if we failed to kill it.
    #[cfg(windows)]
    let script = "ping -n 60 127.0.0.1 > NUL";
    #[cfg(not(windows))]
    let script = "sleep 60";

    let mut session =
        pty::spawn(&common::oneshot_shell(script), Size::default()).expect("spawn pty");

    // This is the "socket closed" path: the handle goes away, and Drop must
    // take the child with it. Nothing is left to answer ConPTY's cursor query,
    // and nothing needs to be: killing the child is what ends the pty here.
    drop(session.pty);

    // If the child survived, the pty stays open and this never reaches EOF.
    let drained =
        tokio::time::timeout(Duration::from_secs(15), drain(None, &mut session.output)).await;

    assert!(
        drained.is_ok(),
        "pty did not reach EOF after drop; the child outlived its handle"
    );
}

#[tokio::test]
async fn absurd_geometry_is_clamped_rather_than_rejected() {
    // A hostile client must not be able to hand a zero-column pty to the kernel.
    let mut session = pty::spawn(&common::oneshot_shell("exit 0"), Size { cols: 0, rows: 0 })
        .expect("spawn pty with degenerate size");

    session
        .pty
        .resize(Size {
            cols: u16::MAX,
            rows: u16::MAX,
        })
        .expect("resize to absurd size is clamped, not fatal");

    let _ = drain(Some(&session.pty), &mut session.output).await;
}
