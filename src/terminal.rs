//! Terminal registry: PTYs that outlive the WebSocket attached to them.
//!
//! The naive design ties one pty to one socket, so a dropped connection (a
//! closed laptop lid, a train tunnel, a Wi-Fi handover) kills the shell and
//! whatever was running in it. Here a [`Terminal`] is an independent, named
//! thing that a socket *attaches* to and detaches from. Reconnecting replays the
//! scrollback and picks up exactly where you left off.
//!
//! Two invariants hold this together:
//!
//! * **The pump always drains.** It reads the pty even when nothing is attached.
//!   If it stopped, the pty's bounded output channel would fill and the shell
//!   would block on write, and a detached `cargo build` would silently freeze.
//! * **Attach is atomic.** Subscribing to the live stream and snapshotting the
//!   scrollback happen under one lock, so a reconnecting client sees every byte
//!   exactly once: no gap, no duplicate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::pty::{self, Size};
use crate::screen::Screen;

pub type Id = String;

/// How many chunks a slow attachment may fall behind before it is told it
/// lagged. Generous: the cost of a slot is one `Bytes` handle.
const BROADCAST_DEPTH: usize = 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub id: Id,
    /// Unix seconds, so the browser can order tabs by age.
    pub created: u64,
    pub attached: bool,
}

/// One shell, one pty, any number of attached sockets over its lifetime.
pub struct Terminal {
    pub id: Id,
    created: SystemTime,
    pty: pty::Pty,
    shared: Mutex<Shared>,
    attachments: AtomicUsize,
    /// When the last socket detached. `None` while something is attached.
    detached_since: Mutex<Option<Instant>>,
}

struct Shared {
    /// What a reattaching client must be sent to catch up: the scrollback, plus
    /// a reconstruction of any full-screen program currently running. See
    /// [`crate::screen`] for why replaying the raw bytes is not enough.
    screen: Screen,
    /// `None` once this terminal is finished.
    ///
    /// Dropping the sender is what tells every attached socket the terminal is
    /// gone, and it has to be done *explicitly*, here, rather than left to
    /// `Terminal`'s `Drop`. An attached socket holds an `Arc<Terminal>` of its
    /// own, so the terminal cannot drop while anyone is listening: a socket
    /// waiting for `Drop` to close the channel would be waiting on itself.
    live: Option<broadcast::Sender<Bytes>>,
}

impl Shared {
    /// Absorb a chunk and fan it out to attached sockets, as one atomic step.
    /// `attach` takes the same lock, which is what makes replay exact.
    ///
    /// Sockets that are already attached get the raw bytes, untouched: they have
    /// been following along and their screens are already in step. Only a client
    /// arriving late needs the reconstruction.
    fn publish(&mut self, chunk: Bytes) {
        self.screen.ingest(&chunk);

        if let Some(live) = &self.live {
            // Err means nothing is attached right now. That is normal, not a
            // problem: the bytes are in the scrollback and will be replayed.
            let _ = live.send(chunk);
        }
    }

    /// End the live stream. Every attached receiver now sees `RecvError::Closed`.
    fn close(&mut self) {
        self.live = None;
    }
}

/// A socket's hold on a terminal. Dropping it detaches.
pub struct Attachment {
    terminal: Arc<Terminal>,
    /// Everything the terminal printed before we attached.
    pub replay: Bytes,
    /// Everything it prints from now on. `None` if the shell had already exited
    /// by the time we attached, a race we can lose, since `Manager::get` and
    /// `attach` are not one atomic step.
    pub live: Option<broadcast::Receiver<Bytes>>,
}

impl Attachment {
    /// The next chunk of live output, or `Closed` once the shell is gone.
    ///
    /// Folding the `None` case in here keeps the caller's `select!` honest: a
    /// terminal that died before we attached is simply one that closed
    /// immediately, not a special case to forget about.
    pub async fn next_output(&mut self) -> std::result::Result<Bytes, broadcast::error::RecvError> {
        match &mut self.live {
            Some(live) => live.recv().await,
            None => Err(broadcast::error::RecvError::Closed),
        }
    }
}

impl Attachment {
    pub fn pty(&self) -> &pty::Pty {
        &self.terminal.pty
    }

    /// Resize the terminal: the pty *and* the emulator behind it.
    ///
    /// Both, always. Telling only the pty would leave the emulator holding a
    /// screen of the old shape, and the next client to reattach would be sent a
    /// reconstruction at the wrong size.
    pub fn resize(&self, size: Size) -> Result<()> {
        self.terminal.resize(size)
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        let remaining = self
            .terminal
            .attachments
            .fetch_sub(1, Ordering::AcqRel)
            .saturating_sub(1);

        if remaining == 0 {
            *self.terminal.detached_since.lock() = Some(Instant::now());
            tracing::debug!(terminal = %self.terminal.id, "detached; shell left running");
        }
    }
}

pub struct Manager {
    terminals: Mutex<HashMap<Id, Arc<Terminal>>>,
    config: Arc<Config>,
}

impl Manager {
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        let manager = Arc::new(Self {
            terminals: Mutex::new(HashMap::new()),
            config,
        });

        Self::spawn_reaper(Arc::clone(&manager));
        manager
    }

    /// Spawn a shell and register it.
    pub fn create(self: &Arc<Self>, size: Size) -> Result<Arc<Terminal>> {
        let limits = &self.config.terminals;

        {
            let terminals = self.terminals.lock();
            if terminals.len() >= limits.max {
                return Err(Error::BadRequest(format!(
                    "already at the limit of {} terminals; close one first",
                    limits.max
                )));
            }
        }

        let session = pty::spawn(&self.config.shell, size)?;
        let id = uuid::Uuid::new_v4().to_string();
        let (live, _) = broadcast::channel(BROADCAST_DEPTH);

        let terminal = Arc::new(Terminal {
            id: id.clone(),
            created: SystemTime::now(),
            pty: session.pty,
            shared: Mutex::new(Shared {
                screen: Screen::new(size, limits.scrollback_bytes),
                live: Some(live),
            }),
            attachments: AtomicUsize::new(0),
            // Born detached: if the browser never attaches, the reaper collects
            // it rather than leaving an orphan shell running forever.
            detached_since: Mutex::new(Some(Instant::now())),
        });

        self.terminals
            .lock()
            .insert(id.clone(), Arc::clone(&terminal));

        Self::spawn_pump(Arc::clone(self), Arc::clone(&terminal), session.output);

        tracing::info!(terminal = %id, "terminal created");
        Ok(terminal)
    }

    /// Drain the pty forever, feeding scrollback and every attached socket.
    /// When it ends, the shell has exited: drop the terminal from the registry,
    /// which closes the broadcast and lets attached sockets notice.
    fn spawn_pump(
        manager: Arc<Self>,
        terminal: Arc<Terminal>,
        mut output: tokio::sync::mpsc::Receiver<Bytes>,
    ) {
        tokio::spawn(async move {
            while let Some(chunk) = output.recv().await {
                terminal.shared.lock().publish(chunk);
            }

            // The pty reached EOF: the shell is gone and its last bytes are in
            // the scrollback. Close the live stream so attached sockets find
            // out, then drop the terminal from the registry.
            tracing::info!(terminal = %terminal.id, "shell exited; terminal closing");
            terminal.shared.lock().close();
            manager.remove(&terminal.id);
        });
    }

    pub fn get(&self, id: &str) -> Option<Arc<Terminal>> {
        self.terminals.lock().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Info> {
        let mut infos: Vec<_> = self
            .terminals
            .lock()
            .values()
            .map(|terminal| Info {
                id: terminal.id.clone(),
                created: terminal
                    .created
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                attached: terminal.attachments.load(Ordering::Acquire) > 0,
            })
            .collect();

        infos.sort_by_key(|info| info.created);
        infos
    }

    /// Remove from the registry **and kill the shell**.
    ///
    /// The kill has to be explicit. Dropping our `Arc` is not enough: an
    /// attached WebSocket holds one too, and the pump task holds a third, so
    /// the `Pty` would not be dropped and the child would keep running with
    /// nothing pointing at it. Killing the shell is what makes the pty reach
    /// EOF, which ends the pump, which closes the broadcast, which finally lets
    /// the attached socket notice that its terminal is gone.
    pub fn remove(&self, id: &str) -> bool {
        let Some(terminal) = self.terminals.lock().remove(id) else {
            return false;
        };

        // Kill the shell, then tell anyone attached. Both steps are needed:
        // the kill because our `Arc` is not the only one, so dropping it would
        // not reap the child; the close because an attached socket is holding
        // an `Arc` of its own and would otherwise wait forever for a `Drop`
        // that its own existence prevents.
        terminal.pty.kill();
        terminal.shared.lock().close();
        true
    }

    /// Collect terminals nobody has been attached to for too long.
    ///
    /// Without this, every reconnect that the browser never comes back for
    /// would leak a shell. The window is generous (the whole point is to
    /// survive a closed laptop), but it is not infinite.
    fn spawn_reaper(manager: Arc<Self>) {
        let idle = Duration::from_secs(
            manager
                .config
                .terminals
                .detached_timeout_minutes
                .saturating_mul(60),
        );

        // Zero disables reaping: an explicit "I will clean up after myself".
        if idle.is_zero() {
            return;
        }

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;

                let expired: Vec<Id> = manager
                    .terminals
                    .lock()
                    .values()
                    .filter(|terminal| {
                        terminal
                            .detached_since
                            .lock()
                            .is_some_and(|since| since.elapsed() >= idle)
                    })
                    .map(|terminal| terminal.id.clone())
                    .collect();

                for id in expired {
                    tracing::info!(terminal = %id, "reaping terminal detached past the timeout");
                    manager.remove(&id);
                }
            }
        });
    }
}

impl Terminal {
    /// Attach a socket. Returns the scrollback to replay plus the live stream,
    /// captured atomically so the join is seamless.
    pub fn attach(self: &Arc<Self>) -> Attachment {
        let (live, replay) = {
            let shared = self.shared.lock();
            let live = shared.live.as_ref().map(broadcast::Sender::subscribe);
            let replay = Bytes::from(shared.screen.replay());
            (live, replay)
        };

        self.attachments.fetch_add(1, Ordering::AcqRel);
        *self.detached_since.lock() = None;

        Attachment {
            terminal: Arc::clone(self),
            replay,
            live,
        }
    }

    /// Resize the pty and keep the emulator in step with it.
    pub fn resize(&self, size: Size) -> Result<()> {
        self.pty.resize(size)?;
        self.shared.lock().screen.resize(size);
        Ok(())
    }
}
