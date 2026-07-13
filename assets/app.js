// facet: browser side of the terminal bridge.
//
// Protocol (mirror of src/web/ws.rs):
//   binary out  → keystrokes for the shell's stdin
//   binary in   → raw shell output, written straight to xterm
//   text out/in → JSON control ({type:"resize"} / {type:"attached"|"exit"|"error"})
//
// Terminal bytes never become JS strings on the way in. xterm.js has a stateful
// UTF-8 decoder, so handing it a Uint8Array lets a multi-byte character split
// across two WebSocket frames still render correctly. Decoding each frame here
// would corrupt exactly that case.
//
// Terminals live on the *server* and outlive their socket, so a tab is a view
// onto a server-side terminal. That is what lets a reload, or a dropped
// connection, reattach to a still-running shell rather than start a new one.

"use strict";

// The design's palette, as the terminal's own colours. Anything the shell
// prints in ANSI red lands on the same red as the chrome.
const THEME = {
  background: "#0f1216",
  foreground: "#cfe8d0",
  cursor: "#5fd75f",
  cursorAccent: "#0b0d10",
  selectionBackground: "rgba(95,215,95,0.28)",
  selectionForeground: "#d6f5d6",

  black: "#0b0d10",
  red: "#ea6962",
  green: "#8ae08a",
  yellow: "#e78a4e",
  blue: "#7daea3",
  magenta: "#d3869b",
  cyan: "#89b482",
  white: "#cfe8d0",

  brightBlack: "#4d5359",
  brightRed: "#ff8a82",
  brightGreen: "#5fd75f",
  brightYellow: "#f0a868",
  brightBlue: "#9ccfc4",
  brightMagenta: "#e8a7ba",
  brightCyan: "#a5d0a0",
  brightWhite: "#e6f5e6",
};

const encoder = new TextEncoder();

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/** Shorten a uuid to something a status bar can carry. */
function short(id) {
  return id ? id.replace(/-/g, "").slice(0, 6) : "";
}

/** `wsl.exe`, `/bin/bash`, `powershell.exe` → `wsl`, `bash`, `powershell`. */
function shellName(program) {
  if (!program) return "shell";
  const base = program.split(/[/\\]/).pop() ?? program;
  return base.replace(/\.exe$/i, "");
}

/** One tab: an xterm instance plus a socket onto one server-side terminal. */
class Tab {
  /** @param {string|null} id server terminal to reattach to, or null for new */
  constructor(app, id) {
    this.app = app;
    this.id = id; // confirmed (or assigned) by the server's `attached` message
    this.shell = "";
    this.state = "connecting";
    this.socket = null;
    this.exited = false;
    this.retry = 0;

    this.pane = document.createElement("div");
    this.pane.className = "pane";
    app.panes.appendChild(this.pane);

    this.button = document.createElement("button");
    this.button.type = "button";
    this.button.className = "tab";
    this.button.addEventListener("click", () => app.focus(this));

    this.dot = document.createElement("span");
    this.dot.className = "dot";
    this.dot.textContent = "●";

    this.name = document.createElement("span");
    this.name.className = "name";

    this.close = document.createElement("span");
    this.close.className = "close";
    this.close.textContent = "×";
    this.close.title = "Close terminal (kills the shell)";
    this.close.addEventListener("click", (event) => {
      event.stopPropagation(); // do not also select the tab we are closing
      app.close(this);
    });

    this.button.append(this.dot, this.name, this.close);
    app.tabsEl.appendChild(this.button);

    this.term = new Terminal({
      allowProposedApi: true,
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", ui-monospace, "Cascadia Code", Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.2,
      scrollback: 10000,
      theme: THEME,
      macOptionIsMeta: true,
    });

    this.fit = new FitAddon.FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open(this.pane);

    // WebGL is a large win on heavy output (a big build log, `yes`). It fails on
    // some GPUs and drivers, so fall back rather than break.
    try {
      this.term.loadAddon(new WebglAddon.WebglAddon());
    } catch (err) {
      console.warn("webgl renderer unavailable, using the DOM renderer", err);
    }

    this.term.attachCustomKeyEventHandler((event) => this.onKey(event));
    this.term.onData((data) => this.send(encoder.encode(data)));
    this.term.onBinary((data) => {
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff;
      this.send(bytes);
    });

    const onResize = debounce(() => this.resize(), 60);
    new ResizeObserver(onResize).observe(this.pane);

    this.fit.fit();
    this.connect();
  }

  setState(state) {
    this.state = state;
    this.render();
    this.app.renderStatus();
  }

  render() {
    const index = this.app.tabs.indexOf(this);
    this.button.dataset.state = this.state;
    this.button.classList.toggle("active", this.app.active === this);
    this.name.textContent = this.shell || `shell ${index + 1}`;
  }

  connect() {
    this.setState("connecting");
    if (this.app.active === this) this.app.showConnecting(true);

    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const { cols, rows } = this.term;
    const params = new URLSearchParams({ cols, rows });
    if (this.id) params.set("terminal", this.id);

    const socket = new WebSocket(`${scheme}//${location.host}/ws?${params}`);
    socket.binaryType = "arraybuffer";
    this.socket = socket;

    socket.onopen = () => {
      this.retry = 0;
      this.setState("open");
      if (this.app.active === this) {
        this.app.showConnecting(false);
        this.term.focus();
      }
      this.resize(true);
    };

    socket.onmessage = (event) => {
      if (typeof event.data === "string") this.onControl(event.data);
      else this.term.write(new Uint8Array(event.data));
    };

    socket.onclose = () => {
      if (this.exited) return; // shell is gone; there is nothing to reconnect to
      this.setState("closed");
      if (this.app.active === this) this.app.showConnecting(false);
      this.reconnectSoon();
    };
  }

  onControl(raw) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      return;
    }

    if (message.type === "attached") {
      const reattached = this.id === message.terminal && message.replayed > 0;
      this.id = message.terminal;
      this.shell = shellName(message.shell);

      // A replay repaints the whole screen, so clear first or the restored
      // scrollback is drawn on top of whatever was already there.
      if (message.replayed > 0) this.term.reset();

      this.render();
      this.app.renderStatus();
      if (reattached) this.app.toast(`reattached · replayed ${bytes(message.replayed)}`);
    } else if (message.type === "exit") {
      // The shell itself exited. Do not reconnect: there is nothing to go back
      // to, and reconnecting would silently spawn a *new* shell.
      this.exited = true;
      this.setState("exited");
      this.term.write("\r\n\x1b[38;2;107;138;111m[process completed]\x1b[0m\r\n");
    } else if (message.type === "error") {
      this.exited = true;
      this.setState("exited");
      this.term.write(`\r\n\x1b[38;2;234;105;98m[${message.message}]\x1b[0m\r\n`);
    } else if (message.type === "session_ended") {
      // Signed out (perhaps in another tab) or the token lapsed. `exited` first,
      // or `onclose` schedules a reconnect that can only ever earn a 401, and
      // the page sits there retrying forever instead of saying what happened.
      this.exited = true;
      this.setState("exited");
      this.app.sessionEnded(message.reason);
    }
  }

  /** Exponential backoff, capped. The shell is still alive server-side. */
  reconnectSoon() {
    const delay = Math.min(1000 * 2 ** this.retry++, 15000);
    this.term.write(
      `\r\n\x1b[38;2;107;138;111m[disconnected · reattaching in ${Math.round(delay / 1000)}s]\x1b[0m\r\n`,
    );
    setTimeout(() => {
      if (!this.exited && this.app.tabs.includes(this)) this.connect();
    }, delay);
  }

  send(payload) {
    if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(payload);
  }

  /** Re-measure, then tell the pty, but only when the grid actually changed. */
  resize(force = false) {
    if (this.app.active !== this) return; // a hidden pane measures as 0x0

    const before = { cols: this.term.cols, rows: this.term.rows };
    this.fit.fit();
    const { cols, rows } = this.term;

    this.app.renderGrid();

    if (!force && cols === before.cols && rows === before.rows) return;
    if (this.socket?.readyState !== WebSocket.OPEN) return;

    this.socket.send(JSON.stringify({ type: "resize", cols, rows }));
  }

  /** Returns false to swallow the key; true to let xterm handle it. */
  onKey(event) {
    if (event.type !== "keydown") return true;
    if (!event.ctrlKey || !event.shiftKey || event.altKey) return true;

    // Ctrl+Shift+C: copy. Plain Ctrl+C must stay free for SIGINT, which is the
    // whole reason terminals moved copy onto Shift.
    if (event.code === "KeyC") {
      const selection = this.term.getSelection();
      if (!selection) return true; // nothing selected: let devtools have it
      navigator.clipboard?.writeText(selection).catch(() => {});
      return false;
    }

    // Ctrl+Shift+V: paste. Right-click paste and Cmd+V already work; xterm
    // listens for the DOM `paste` event itself.
    if (event.code === "KeyV") {
      navigator.clipboard
        ?.readText()
        .then((text) => text && this.term.paste(text))
        .catch(() => {});
      return false;
    }

    if (event.code === "KeyT") {
      this.app.open();
      return false;
    }
    if (event.code === "KeyW") {
      this.app.close(this);
      return false;
    }

    return true;
  }

  dispose() {
    this.exited = true; // suppress the reconnect that onclose would schedule
    this.socket?.close();
    this.term.dispose();
    this.pane.remove();
    this.button.remove();
  }
}

function bytes(n) {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KiB`;
}

class App {
  constructor() {
    this.tabs = [];
    this.active = null;

    this.tabsEl = document.getElementById("tabs");
    this.panes = document.getElementById("panes");
    this.connectingEl = document.getElementById("connecting");
    this.newTabButton = document.getElementById("new-tab");

    this.stateEl = document.getElementById("state");
    this.stateText = document.getElementById("state-text");
    this.sessionEl = document.getElementById("session");
    this.shellEl = document.getElementById("shell");
    this.gridEl = document.getElementById("grid");

    this.newTabButton.addEventListener("click", () => this.open());
    window.addEventListener("resize", () => this.active?.resize(true));

    this.renderChrome();
    this.restore();
  }

  /** The address bar and the transport line, filled from what is actually true. */
  renderChrome() {
    const secure = location.protocol === "https:";

    document.getElementById("scheme").textContent = secure ? "https://" : "http://";
    document.getElementById("host").textContent = location.host;
    document.querySelector(".lock").style.color = secure
      ? "var(--green-soft)"
      : "var(--faint)";

    document.getElementById("channel").textContent = secure ? "wss · pty" : "ws · pty";

    // The design read "TLS 1.3 · AES-256-GCM". JavaScript cannot see the
    // negotiated version or cipher suite, so printing them would be decoration
    // dressed up as a security claim. Say only what is checkable.
    document.getElementById("transport").textContent = secure
      ? "TLS"
      : "no TLS (loopback)";
  }

  showConnecting(visible) {
    this.connectingEl.hidden = !visible;
  }

  /** Ask the server what terminals exist and reattach to them. */
  async restore() {
    let existing = [];
    try {
      const response = await fetch("/api/terminals", { credentials: "same-origin" });
      if (response.status === 401) {
        location.href = "/login"; // the session expired while we were away
        return;
      }
      if (response.ok) existing = await response.json();
    } catch (err) {
      console.warn("could not list terminals", err);
    }

    if (existing.length === 0) {
      this.open();
      return;
    }

    for (const info of existing) this.add(new Tab(this, info.id));
    this.focus(this.tabs[0]);
  }

  open() {
    const tab = new Tab(this, null);
    this.add(tab);
    this.focus(tab);
    return tab;
  }

  add(tab) {
    this.tabs.push(tab);
    this.renderAll();
  }

  focus(tab) {
    if (!tab) return;
    this.active = tab;

    for (const other of this.tabs) {
      other.pane.classList.toggle("active", other === tab);
    }

    this.showConnecting(tab.state === "connecting");
    this.renderAll();

    // The pane was display:none until a moment ago, so it measured as 0x0.
    // Re-fit now that it has a real size, or the shell keeps the old geometry.
    requestAnimationFrame(() => {
      tab.fit.fit();
      tab.resize(true);
      tab.term.focus();
    });
  }

  /** Close for real: kills the shell server-side, not just this socket. */
  async close(tab) {
    if (tab.id) {
      try {
        await fetch(`/api/terminals/${encodeURIComponent(tab.id)}`, {
          method: "DELETE",
          credentials: "same-origin",
        });
      } catch (err) {
        console.warn("could not close the terminal server-side", err);
      }
    }

    const index = this.tabs.indexOf(tab);
    this.tabs.splice(index, 1);
    tab.dispose();

    if (this.tabs.length === 0) {
      this.open();
    } else if (this.active === tab) {
      this.focus(this.tabs[Math.min(index, this.tabs.length - 1)]);
    } else {
      this.renderAll();
    }
  }

  renderAll() {
    for (const tab of this.tabs) tab.render();
    this.renderStatus();
    this.renderGrid();
  }

  renderStatus() {
    const tab = this.active;
    if (!tab) return;

    const label = {
      connecting: "connecting",
      open: "connected",
      closed: "reattaching",
      exited: "ended",
    };

    this.stateEl.dataset.state = tab.state;
    this.stateText.textContent = label[tab.state] ?? tab.state;
    this.sessionEl.textContent = tab.id ? `session ${short(tab.id)}` : "";
    this.shellEl.textContent = tab.shell;
  }

  renderGrid() {
    const tab = this.active;
    if (!tab) return;
    this.gridEl.textContent = `${tab.term.cols} × ${tab.term.rows}`;
  }

  toast(text) {
    // The session field is the only spare room in the status bar, and a toast
    // that replaces it briefly is less intrusive than a floating box over the
    // terminal the user is reading.
    const previous = this.sessionEl.textContent;
    this.sessionEl.textContent = text;
    clearTimeout(this._toast);
    this._toast = setTimeout(() => {
      this.sessionEl.textContent = previous;
      this.renderStatus();
    }, 2600);
  }

  /**
   * The server revoked our session. Every tab is now dead, so tear them all
   * down and go to the login page.
   *
   * Guarded, because the tabs report this independently: with four terminals
   * open, four sockets each say the session is gone, and without the flag the
   * page would try to navigate four times.
   */
  sessionEnded(reason) {
    if (this._ending) return;
    this._ending = true;

    for (const tab of this.tabs) tab.exited = true;

    // Long enough to read, short enough not to feel stuck. The line lands in
    // the terminal the user is actually looking at.
    this.toast(reason || "session ended");
    if (this.active) {
      this.active.term.write(
        `\r\n\x1b[38;2;234;105;98m[session ended · returning to sign in]\x1b[0m\r\n`,
      );
    }

    setTimeout(() => location.assign("/login"), 1200);
  }
}

new App();
