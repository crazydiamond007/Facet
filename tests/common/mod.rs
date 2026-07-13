//! Test helpers: boot a real server on an ephemeral port, and log in to it.
//!
//! Each integration test is its own binary, so helpers used by only some of
//! them look dead to the others.
#![allow(dead_code)]

use std::net::SocketAddr;

use base64::Engine as _;
use facet::config::{Auth, Config, Shell};
use facet::state::AppState;

pub const PASSWORD: &str = "correct horse battery staple";

/// A server under test, plus the secrets needed to authenticate against it.
pub struct Server {
    pub addr: SocketAddr,
    pub totp_secret: String,
    /// The server's own state, so a test can assert on what the *server*
    /// believes (which terminals exist, which sessions are live) rather than
    /// inferring it from what the HTTP surface is willing to admit.
    pub state: AppState,
}

impl Server {
    pub fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The TOTP code an authenticator app would be showing right now.
    pub fn totp_code(&self) -> String {
        let totp = facet::auth::totp::build(&self.totp_secret, "owner").expect("build totp");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        totp.generate(now)
    }
}

/// A config with known-good credentials and TLS off (loopback only, which
/// `Config::validate` permits).
pub fn test_config(shell: Shell) -> (Config, String) {
    let totp_secret = facet::auth::totp::generate_secret();

    let config = Config {
        shell,
        tls: facet::config::Tls {
            enabled: false,
            ..Default::default()
        },
        auth: Some(Auth {
            password_hash: facet::auth::password::hash(PASSWORD).expect("hash password"),
            totp_secret: totp_secret.clone(),
            jwt_secret: base64::engine::general_purpose::STANDARD.encode([42u8; 32]),
            session_ttl_minutes: 60,
            max_failed_attempts: 3,
            lockout_minutes: 15,
        }),
        ..Config::default()
    };

    (config, totp_secret)
}

/// Boot the server on a random free port.
pub async fn serve(config: Config, totp_secret: String) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let state = AppState::new(config).expect("build state");
    let app = facet::web::router(state.clone())
        .expect("build router")
        .into_make_service_with_connect_info::<SocketAddr>();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Server {
        addr,
        totp_secret,
        state,
    }
}

/// Boot with default credentials and an interactive shell. The common case.
pub async fn serve_default() -> Server {
    let (config, secret) = test_config(interactive_shell());
    serve(config, secret).await
}

/// A cookie-keeping HTTP client, i.e. a stand-in for the browser.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client")
}

/// Fetch the login page and pull the CSRF token out of the form. The cookie
/// half of the double-submit lands in the client's cookie jar.
pub async fn csrf_token(client: &reqwest::Client, server: &Server) -> String {
    let html = client
        .get(format!("http://{}/login", server.addr))
        .send()
        .await
        .expect("GET /login")
        .text()
        .await
        .expect("body");

    let marker = r#"name="csrf" value=""#;
    let start = html.find(marker).expect("csrf field in login form") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");

    rest[..end].to_string()
}

/// POST the login form. Returns the raw response so tests can assert on status.
pub async fn login_with(
    client: &reqwest::Client,
    server: &Server,
    password: &str,
    code: &str,
) -> reqwest::Response {
    let csrf = csrf_token(client, server).await;

    client
        .post(format!("http://{}/login", server.addr))
        .form(&[("password", password), ("code", code), ("csrf", &csrf)])
        .send()
        .await
        .expect("POST /login")
}

/// Log in successfully, leaving a session cookie in the client's jar.
pub async fn login(client: &reqwest::Client, server: &Server) -> reqwest::Response {
    let response = login_with(client, server, PASSWORD, &server.totp_code()).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::SEE_OTHER,
        "expected login to redirect on success"
    );
    response
}

/// The session cookie value, for handing to a WebSocket client.
///
/// Logs in exactly once. Logging in twice would reuse the same TOTP code inside
/// its 30-second step, which the replay check correctly refuses, so this
/// helper has to be as careful with codes as a real user is.
pub async fn session_cookie(client: &reqwest::Client, server: &Server) -> String {
    let response = login(client, server).await;

    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("facet_session="))
        .and_then(|v| v.split(';').next())
        .map(str::to_string)
        .expect("session cookie in the response")
}

/// ConPTY's cursor-position query, and the answer it is waiting for.
///
/// `portable-pty` creates the pseudoconsole with `PSUEDOCONSOLE_INHERIT_CURSOR`,
/// so the very first thing ConPTY does is emit DSR (`ESC[6n`), meaning "terminal,
/// where is your cursor?". It then **will not proceed until something answers**.
/// The shell never runs, not one byte of output is produced, and every test sits
/// there until it times out.
///
/// A real terminal answers by reflex: xterm.js replies with `ESC[<row>;<col>R`
/// without being asked to, which is why the browser works. A test harness is not
/// a terminal, so it has to answer by hand.
///
/// The reply must come from exactly one place. ConPTY consumes the first answer
/// as the cursor report; a second one would be passed through to the shell and
/// typed at the prompt as garbage. In production that one place is the browser.
/// In tests it is us.
///
/// On Unix this never fires: there is no ConPTY and no DSR, so the check below
/// simply never matches.
pub const DSR: &[u8] = b"\x1b[6n";
pub const DSR_REPLY: &[u8] = b"\x1b[1;1R";

/// True if ConPTY is waiting on a cursor report.
pub fn wants_cursor_report(chunk: &[u8]) -> bool {
    chunk.windows(DSR.len()).any(|window| window == DSR)
}

/// A character that appears in the shell's prompt, and therefore means "the
/// shell has started and is listening".
///
/// Typing before the prompt arrives can lose the keystrokes. `/bin/sh` is ready
/// more or less instantly, but `cmd.exe` under ConPTY takes a moment to start
/// reading, and a test that types into the void just sits there until it times
/// out. Wait for the prompt, exactly as a person would.
#[cfg(windows)]
pub const PROMPT: &str = ">";
#[cfg(not(windows))]
pub const PROMPT: &str = "$";

/// Lines to type so the shell prints `<marker>42`.
///
/// The point is that the *output* differs textually from the keystrokes. A pty
/// echoes what you type, so asserting on the text you sent proves nothing:
/// `A42` can only appear once the shell has actually executed the line.
///
/// `cmd.exe` has no `$(( ))`, so on Windows the same trick takes two lines.
pub fn arithmetic_probe(marker: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec!["set /a v=6*7".to_string(), format!("echo {marker}%v%")]
    }
    #[cfg(not(windows))]
    {
        vec![format!("echo {marker}$((6*7))")]
    }
}

/// What [`arithmetic_probe`] makes the shell print.
pub fn probe_output(marker: &str) -> String {
    format!("{marker}42")
}

/// A shell that runs `script` and exits, portable across Windows and Unix.
pub fn oneshot_shell(script: &str) -> Shell {
    #[cfg(windows)]
    let (program, args) = ("cmd.exe", vec!["/C".to_string(), script.to_string()]);
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", vec!["-c".to_string(), script.to_string()]);

    Shell {
        program: program.into(),
        args,
        cwd: None,
        env: Vec::new(),
    }
}

/// An interactive shell with a predictable, quiet prompt.
pub fn interactive_shell() -> Shell {
    #[cfg(windows)]
    let (program, args) = ("cmd.exe", Vec::new());
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", Vec::new());

    Shell {
        program: program.into(),
        args,
        cwd: None,
        env: vec![("PS1".to_string(), "$ ".to_string())],
    }
}
