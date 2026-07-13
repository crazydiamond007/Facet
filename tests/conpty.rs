//! ConPTY, on Windows only.
//!
//! Windows is the platform where the pty lifetime rules differ, and it is not
//! the platform this was developed on, so it gets a test that says exactly what
//! it saw when it fails rather than just timing out.
//!
//! The specific hazard: ConPTY keeps its output pipe open for as long as the
//! pseudoconsole exists, so a reader will block forever after the shell exits
//! unless the master is closed. On Unix the child's exit closes the slave and
//! EOF arrives on its own. Getting this wrong hangs every session.
#![cfg(windows)]

mod common;

use std::time::Duration;

use facet::pty::{self, Size};

#[tokio::test]
async fn conpty_delivers_output_and_then_eof() {
    let mut session =
        pty::spawn(&common::oneshot_shell("echo hello"), Size::default()).expect("spawn");

    let mut bytes = Vec::new();

    let reached_eof = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(chunk) = session.output.recv().await {
            // Behave like a terminal: ConPTY will not run the shell until it is
            // told where the cursor is. See common::DSR.
            if common::wants_cursor_report(&chunk) {
                let _ = session
                    .pty
                    .write(bytes::Bytes::from_static(common::DSR_REPLY))
                    .await;
            }
            bytes.extend_from_slice(&chunk);
        }
    })
    .await
    .is_ok();

    let text = String::from_utf8_lossy(&bytes);

    // One assert, carrying everything needed to diagnose a failure from a CI
    // log on a machine we cannot attach a debugger to.
    assert!(
        reached_eof && text.contains("hello"),
        "ConPTY: reached_eof={reached_eof}, {} bytes, text={text:?}. \
         If reached_eof is false the master is outliving the child, and the \
         reader is blocked on a pipe ConPTY will never close.",
        bytes.len()
    );
}
