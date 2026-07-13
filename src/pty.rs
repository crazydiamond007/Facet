//! Cross-platform PTY: ConPTY on Windows, forkpty on Unix, via `portable-pty`.
//!
//! `portable-pty` is a blocking API, so the master's reader and writer each get
//! a dedicated OS thread that bridges into tokio channels. The async side never
//! blocks; the threads exit on their own when the pty closes.
//!
//! Lifetime rules, which are the whole ballgame for "no zombie processes":
//!
//! * The slave handle is dropped immediately after spawn. If we kept it, the
//!   pty would still have a writer open after the shell exits and our reader
//!   thread would block forever instead of seeing EOF.
//! * Dropping [`Pty`] kills the child. A closed WebSocket drops it, so a
//!   vanished browser cannot leave a shell running.
//! * The child is reaped by a dedicated waiter thread which reports the exit
//!   status back over a oneshot, so the socket can close when the shell does.

use std::io::{Read, Write};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use portable_pty::{
    Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system,
};
use tokio::sync::{mpsc, oneshot};

use crate::config::Shell;
use crate::error::{Error, Result};

const READ_BUF: usize = 8 * 1024;

/// Bounded so a slow browser backpressures the shell rather than letting us
/// buffer unbounded output (think `yes` or a large `cat`).
const OUTPUT_DEPTH: usize = 64;
const INPUT_DEPTH: usize = 64;

/// A live shell attached to a pty.
pub struct Pty {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    input: mpsc::Sender<Bytes>,
}

/// Everything a WebSocket task needs to drive one shell.
pub struct Session {
    pub pty: Pty,
    /// Bytes the shell wrote. Closes when the pty reaches EOF.
    pub output: mpsc::Receiver<Bytes>,
    /// Fires once the child has been reaped.
    pub exit: oneshot::Receiver<ExitStatus>,
}

/// Terminal geometry. Mirrors `PtySize` but keeps `portable_pty` out of our
/// public surface and out of the WebSocket protocol types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub cols: u16,
    pub rows: u16,
}

impl Default for Size {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

impl Size {
    /// Clamp to something a pty will actually accept. A hostile or buggy client
    /// must not be able to send us `0` (division-by-zero territory in some
    /// line disciplines) or absurd geometry.
    pub fn sanitized(self) -> Self {
        Self {
            cols: self.cols.clamp(1, 1000),
            rows: self.rows.clamp(1, 1000),
        }
    }

    fn to_pty_size(self) -> PtySize {
        PtySize {
            rows: self.rows,
            cols: self.cols,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

/// Spawn `shell` on a new pty of the given size.
pub fn spawn(shell: &Shell, size: Size) -> Result<Session> {
    let size = size.sanitized();

    let pair = native_pty_system()
        .openpty(size.to_pty_size())
        .map_err(Error::pty)?;

    let mut cmd = CommandBuilder::new(&shell.program);
    for arg in &shell.args {
        cmd.arg(arg);
    }
    for (key, value) in &shell.env {
        cmd.env(key, value);
    }
    match &shell.cwd {
        Some(dir) => cmd.cwd(dir),
        // No cwd configured: start in the user's home rather than inheriting
        // whatever directory the service happened to be launched from.
        None => {
            if let Some(home) = home_dir() {
                cmd.cwd(home);
            }
        }
    }
    // Advertise a capable terminal; xterm.js speaks 256-color and mouse.
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");

    let child = pair.slave.spawn_command(cmd).map_err(Error::pty)?;

    // Critical: release the slave now. Holding it would keep a writer open on
    // the pty forever, so the reader below would never observe EOF.
    drop(pair.slave);

    let killer = child.clone_killer();
    let reader = pair.master.try_clone_reader().map_err(Error::pty)?;
    let writer = pair.master.take_writer().map_err(Error::pty)?;
    let master = Arc::new(Mutex::new(pair.master));

    let (output_tx, output) = mpsc::channel::<Bytes>(OUTPUT_DEPTH);
    let (input, input_rx) = mpsc::channel::<Bytes>(INPUT_DEPTH);
    let (exit_tx, exit) = oneshot::channel();

    spawn_reader(reader, output_tx);
    spawn_writer(writer, input_rx);
    spawn_waiter(child, exit_tx);

    Ok(Session {
        pty: Pty {
            master,
            killer: Mutex::new(killer),
            input,
        },
        output,
        exit,
    })
}

/// Pump pty output into the async world. Blocking reads on a dedicated thread.
fn spawn_reader(mut reader: Box<dyn Read + Send>, tx: mpsc::Sender<Bytes>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; READ_BUF];
        loop {
            match reader.read(&mut buf) {
                // EOF: the shell exited and every writer is gone.
                Ok(0) => break,
                Ok(n) => {
                    // `blocking_send` is how a sync thread applies backpressure
                    // against an async consumer. An error means the WebSocket
                    // task is gone, so we are done.
                    if tx.blocking_send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    // On Windows a closing ConPTY surfaces as an error rather
                    // than a clean EOF; treat it as end-of-stream either way.
                    tracing::debug!(%err, "pty reader stopped");
                    break;
                }
            }
        }
        tracing::trace!("pty reader thread exiting");
    });
}

/// Pump WebSocket input into the pty. Dropping the writer signals EOF (^D) to
/// the shell, which happens automatically once `rx` closes.
fn spawn_writer(mut writer: Box<dyn Write + Send>, mut rx: mpsc::Receiver<Bytes>) {
    std::thread::spawn(move || {
        while let Some(chunk) = rx.blocking_recv() {
            if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
                break;
            }
        }
        tracing::trace!("pty writer thread exiting");
    });
}

/// Reap the child and report its status. Without this the process would linger
/// as a zombie on Unix after exiting.
fn spawn_waiter(mut child: Box<dyn Child + Send + Sync>, tx: oneshot::Sender<ExitStatus>) {
    std::thread::spawn(move || {
        let status = child
            .wait()
            .unwrap_or_else(|_| ExitStatus::with_exit_code(1));
        tracing::debug!(code = status.exit_code(), "shell exited");
        // Receiver may be gone if the socket closed first; nothing to do.
        let _ = tx.send(status);
    });
}

impl Pty {
    /// Feed bytes to the shell's stdin.
    pub async fn write(&self, bytes: Bytes) -> Result<()> {
        self.input
            .send(bytes)
            .await
            .map_err(|_| Error::SessionClosed)
    }

    /// Resize the pty. Delivers SIGWINCH on Unix; resizes the ConPTY buffer on
    /// Windows. Full-screen apps like vim redraw off the back of this.
    pub fn resize(&self, size: Size) -> Result<()> {
        self.master
            .lock()
            .resize(size.sanitized().to_pty_size())
            .map_err(Error::pty)
    }

    /// Kill the shell.
    ///
    /// Public because dropping the `Pty` is not always enough to reach it: an
    /// attached WebSocket holds an `Arc` to the owning terminal, so removing
    /// that terminal from the registry does not drop the `Pty` and the child
    /// would survive. Closing a tab has to say so explicitly.
    pub fn kill(&self) {
        if let Err(err) = self.killer.lock().kill() {
            // Already-exited children are the common case here, not a problem.
            tracing::trace!(%err, "kill on teardown");
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        self.kill();
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    let var = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let var = std::env::var_os("HOME");

    var.map(std::path::PathBuf::from).filter(|p| p.is_dir())
}
