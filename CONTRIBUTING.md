# Contributing to facet

Thanks for looking. This is a small, opinionated project: a single-user web terminal that
takes authentication seriously. Contributions are genuinely welcome.

## Getting set up

```bash
git clone https://github.com/crazydiamond007/Facet
cd facet
cargo build
cargo test
```

You need **Rust 1.85+** (edition 2024) and a C toolchain (`build-essential` on Debian/Ubuntu,
for `ring`'s assembly). There is no Node step; `xterm.js` is vendored in `assets/vendor/`.

To run it against a throwaway config rather than your real one:

```bash
mkdir -p /tmp/facet && cd /tmp/facet
cargo run --manifest-path ~/path/to/facet/Cargo.toml -- setup
cargo run --manifest-path ~/path/to/facet/Cargo.toml -- run
```

## Before you open a PR

```bash
cargo fmt
cargo clippy --all-targets
cargo test
```

All three should be clean. Then, if your change touches anything a user can see, **run the
thing and check it actually works**. The tests are good, but they are not a browser.

## House style

A few conventions this codebase holds to. None are unusual, but they are load-bearing:

**No `unwrap()` or `expect()` in a request or WebSocket path.** A panic in a handler is a
crash in a program that is holding someone's shell open. Use the typed errors in
`src/error.rs`. Tests may `expect()` freely; a failing test *should* be loud.

**Errors never describe the machine to a caller.** Internal detail goes to the log; the
response body gets a generic message. `Error::into_response` enforces this, so please don't
route around it.

**Comment the *why*, not the *what*.** The code says what it does. A comment should say what
would go wrong if you did it the obvious way instead. For example, from `src/pty.rs`:

```rust
// Critical: release the slave now. Holding it would keep a writer open on
// the pty forever, so the reader below would never observe EOF.
drop(pair.slave);
```

That comment exists because deleting that one line produces a bug that takes an afternoon to
find. A comment saying `// drop the slave` would be worthless.

**Security-relevant decisions get a comment explaining the attack.** If you add a check, say
what it stops. If you *relax* one, say why it is safe.

## Tests

Integration tests boot a real server on a real ephemeral port, log in over HTTP with a real
TOTP code, open a real WebSocket, and drive a real shell. `tests/common/mod.rs` is the
harness.

One idiom worth knowing before you write a terminal test: a PTY **echoes your keystrokes
back**, so if you send `echo hello` and then assert the output contains `hello`, your test
passes even when the shell never ran. Write commands whose output differs textually from
their input:

```rust
send_line(&mut socket, "echo A$((6*7))Z").await;
read_until(&mut socket, "A42Z").await;   // A42Z can only come from execution
```

Please add a test for anything security-relevant. Every hardening measure in this project has
one, and each test names the attack it prevents: `a_totp_code_cannot_be_replayed`,
`a_failed_password_does_not_burn_the_totp_code`, `ws_is_rejected_from_a_foreign_origin`.

## Scope

Things I am happy to take:

- Bug fixes, especially in the PTY and teardown paths.
- Platform fixes (Windows, macOS, BSD).
- Anything on the roadmap in the [README](README.md#roadmap).
- Security hardening, with a test that demonstrates the attack.
- Documentation that saves the next person an afternoon.

Things that are probably out of scope, though I am open to being persuaded in an issue first:

- **Multi-user support.** Single-user is a design constraint, not an oversight. It is what
  keeps the auth model small enough to reason about.
- **A sandbox or a restricted command set.** `facet` gives you a shell; if you want less than
  a shell, you want a different program.
- **Frontend frameworks.** The UI is deliberately plain JS with no build step, so that
  `cargo build` is the whole story.

## Security bugs

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing, you agree that your work is dual-licensed under MIT and Apache-2.0, matching
the project.
