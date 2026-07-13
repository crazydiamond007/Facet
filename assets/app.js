// facet: browser side of the terminal bridge.
//
// Protocol (mirror of src/web/ws.rs):
//   binary out  → keystrokes for the shell's stdin
//   binary in   → raw shell output, written straight to xterm
//   text out/in → JSON control ({type:"resize"} / {type:"attached"|"exit"|"error"})
//
// Terminal bytes never become JS strings on the way in. xterm.js has a
// stateful UTF-8 decoder, so handing it a Uint8Array lets a multi-byte
// character split across two WebSocket frames still render correctly.
// Decoding each frame ourselves would corrupt exactly that case.
//
// Terminals live on the *server* and outlive their socket, so a tab is really
// a view onto a server-side terminal. That is what lets a reload, or a dropped
// connection, reattach to a still-running shell instead of starting a new one.

"use strict";

const THEME = {
  background: "#0d1117",
  foreground: "#c9d1d9",
  cursor: "#58a6ff",
  cursorAccent: "#0d1117",
  selectionBackground: "#264f78",
  black: "#484f58",
  red: "#ff7b72",
  green: "#3fb950",
  yellow: "#d29922",
  blue: "#58a6ff",
  magenta: "#bc8cff",
  cyan: "#39c5cf",
  white: "#b1bac4",
  brightBlack: "#6e7681",
  brightRed: "#ffa198",
  brightGreen: "#56d364",
  brightYellow: "#e3b341",
  brightBlue: "#79c0ff",
  brightMagenta: "#d2a8ff",
  brightCyan: "#56d4dd",
  brightWhite: "#f0f6fc",
};

const encoder = new TextEncoder();

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/** One tab: an xterm instance plus a socket onto one server-side terminal. */
class Tab {
  /** @param {string|null} id  server terminal to reattach to, or null for new */
  constructor(app, id) {
    this.app = app;
    this.id = id; // filled in by the server's `attached` message
    this.state = "connecting";
    this.socket = null;
    this.exited = false;
    this.retry = 0;

    this.pane = document.createElement("div");
    this.pane.className = "pane";
    app.panes.appendChild(this.pane);

    this.button = document.createElement("button");
    this.button.className = "tab";
    this.button.addEventListener("click", () => app.focus(this));
    this.render();
    app.tabsEl.insertBefore(this.button, app.newTabButton);

    this.term = new Terminal({
      allowProposedApi: true,
      cursorBlink: true,
      fontFamily:
        '"Cascadia Code", "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace',
      fontSize: 13,
      scrollback: 10000,
      theme: THEME,
      macOptionIsMeta: true,
    });

    this.fit = new FitAddon.FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open(this.pane);

    // WebGL is a large perf win on heavy output (a big build log, `yes`). It
    // fails on some GPUs and drivers, so fall back rather than break.
    try {
      this.term.loadAddon(new WebglAddon.WebglAddon());
    } catch (err) {
      console.warn("webgl renderer unavailable, using the DOM renderer", err);
    }

    this.term.attachCustomKeyEventHandler((e) => this.onKey(e));
    this.term.onData((data) => this.send(encoder.encode(data)));
    this.term.onBinary((data) => {
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff;
      this.send(bytes);
    });

    this.onResize = debounce(() => this.resize(), 60);
    new ResizeObserver(this.onResize).observe(this.pane);

    this.fit.fit();
    this.connect();
  }

  get label() {
    const n = this.app.tabs.indexOf(this) + 1;
    return `shell ${n}`;
  }

  render() {
    this.button.dataset.state = this.state;
    this.button.classList.toggle("active", this.app.active === this);
    this.button.innerHTML = "";

    const dot = document.createElement("span");
    dot.className = "dot";
    this.button.appendChild(dot);

    const name = document.createElement("span");
    name.textContent = this.label;
    this.button.appendChild(name);

    const close = document.createElement("span");
    close.className = "close";
    close.textContent = "×";
    close.title = "Close terminal (kills the shell)";
    close.addEventListener("click", (e) => {
      e.stopPropagation(); // do not also select the tab we are closing
      this.app.close(this);
    });
    this.button.appendChild(close);
  }

  setState(state) {
    this.state = state;
    this.render();
    this.app.renderStatus();
  }

  connect() {
    this.setState("connecting");

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
      if (this.app.active === this) this.term.focus();
      this.resize(true);
    };

    socket.onmessage = (ev) => {
      if (typeof ev.data === "string") this.onControl(ev.data);
      else this.term.write(new Uint8Array(ev.data));
    };

    socket.onclose = () => {
      if (this.exited) return; // shell is gone; nothing to reconnect to
      this.setState("closed");
      this.reconnectSoon();
    };
  }

  onControl(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === "attached") {
      // The server tells us which terminal we got. On a fresh tab this is our
      // first sight of the id; on a reattach it confirms the one we asked for.
      const isReattach = this.id === msg.terminal && msg.replayed > 0;
      this.id = msg.terminal;

      // A replay repaints the whole screen, so clear first to avoid drawing
      // the restored scrollback on top of whatever was already there.
      if (msg.replayed > 0) this.term.reset();
      if (isReattach) this.app.toast(`reattached, replayed ${fmtBytes(msg.replayed)}`);

      this.app.persist();
    } else if (msg.type === "exit") {
      // The shell itself exited. Do not reconnect: there is nothing to go back
      // to, and reconnecting would silently spawn a *new* shell.
      this.exited = true;
      this.setState("exited");
      this.term.write(`\r\n\x1b[38;5;245m[shell exited]\x1b[0m\r\n`);
      this.app.persist();
    } else if (msg.type === "error") {
      this.exited = true;
      this.setState("exited");
      this.term.write(`\r\n\x1b[38;5;203m[${msg.message}]\x1b[0m\r\n`);
    }
  }

  /** Exponential backoff, capped. The shell is still alive server-side. */
  reconnectSoon() {
    const delay = Math.min(1000 * 2 ** this.retry++, 15000);
    this.term.write(
      `\r\n\x1b[38;5;245m[disconnected, reattaching in ${Math.round(delay / 1000)}s]\x1b[0m\r\n`,
    );
    setTimeout(() => {
      if (!this.exited && this.app.tabs.includes(this)) this.connect();
    }, delay);
  }

  send(bytes) {
    if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(bytes);
  }

  /** Re-measure, then tell the pty, but only when the grid actually changed. */
  resize(force = false) {
    if (this.app.active !== this) return; // a hidden pane measures as 0x0

    const before = { cols: this.term.cols, rows: this.term.rows };
    this.fit.fit();
    const { cols, rows } = this.term;

    if (!force && cols === before.cols && rows === before.rows) return;
    if (this.socket?.readyState !== WebSocket.OPEN) return;

    this.socket.send(JSON.stringify({ type: "resize", cols, rows }));
  }

  /** Returns false to swallow the key; true to let xterm handle it. */
  onKey(e) {
    if (e.type !== "keydown") return true;
    if (!e.ctrlKey || !e.shiftKey || e.altKey) return true;

    // Ctrl+Shift+C: copy. Plain Ctrl+C must stay free for SIGINT, which is the
    // whole reason terminals moved copy onto Shift.
    if (e.code === "KeyC") {
      const selection = this.term.getSelection();
      if (!selection) return true; // nothing selected: let devtools have it
      navigator.clipboard?.writeText(selection).catch(() => {});
      return false;
    }

    // Ctrl+Shift+V: paste. Right-click paste and Cmd+V already work: xterm
    // listens for the DOM `paste` event itself.
    if (e.code === "KeyV") {
      navigator.clipboard
        ?.readText()
        .then((text) => text && this.term.paste(text))
        .catch(() => {});
      return false;
    }

    // Ctrl+Shift+T / W: new and close tab, as in a browser or a terminal app.
    if (e.code === "KeyT") {
      this.app.open();
      return false;
    }
    if (e.code === "KeyW") {
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

class App {
  constructor() {
    this.tabs = [];
    this.active = null;

    this.tabsEl = document.getElementById("tabs");
    this.panes = document.getElementById("panes");
    this.statusEl = document.getElementById("status");
    this.toastEl = document.getElementById("toast");
    this.newTabButton = document.getElementById("new-tab");

    this.newTabButton.addEventListener("click", () => this.open());
    window.addEventListener("resize", () => this.active?.resize(true));

    this.restore();
  }

  /** Ask the server what terminals exist and reattach to them. */
  async restore() {
    let existing = [];
    try {
      const response = await fetch("/api/terminals", { credentials: "same-origin" });
      if (response.status === 401) {
        location.href = "/login"; // session expired while we were away
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
  }

  renderStatus() {
    const tab = this.active;
    if (!tab) return;
    this.statusEl.dataset.state = tab.state;
    this.statusEl.textContent =
      { connecting: "connecting", open: "connected", closed: "reattaching", exited: "exited" }[
        tab.state
      ] ?? tab.state;
  }

  persist() {
    this.renderAll();
  }

  toast(text) {
    this.toastEl.textContent = text;
    this.toastEl.hidden = false;
    clearTimeout(this._toast);
    this._toast = setTimeout(() => (this.toastEl.hidden = true), 2600);
  }
}

function fmtBytes(n) {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KiB`;
}

new App();
