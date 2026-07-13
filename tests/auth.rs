//! The security boundary, tested from the outside: over HTTP, as a browser.

mod common;

use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header;

/// Build a WebSocket upgrade with whatever cookie and origin the test wants.
fn upgrade(server: &common::Server, cookie: Option<&str>, origin: Option<&str>) -> Request {
    let mut request = format!("ws://{}/ws?cols=80&rows=24", server.addr)
        .into_client_request()
        .expect("build request");

    let headers = request.headers_mut();
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().expect("cookie header"));
    }
    if let Some(origin) = origin {
        headers.insert(header::ORIGIN, origin.parse().expect("origin header"));
    }

    request
}

/// The HTTP status a rejected upgrade came back with.
fn rejected_with(err: tokio_tungstenite::tungstenite::Error) -> StatusCode {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            StatusCode::from_u16(response.status().as_u16()).expect("status")
        }
        other => panic!("expected an HTTP rejection, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The WebSocket is the shell. It must be unreachable without a session.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_is_rejected_without_a_token() {
    let server = common::serve_default().await;

    let err = tokio_tungstenite::connect_async(upgrade(&server, None, Some(&server.origin())))
        .await
        .expect_err("upgrade must be refused without a session cookie");

    assert_eq!(rejected_with(err), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_is_rejected_with_a_forged_token() {
    let server = common::serve_default().await;

    // A syntactically valid JWT, signed with a key we made up.
    let forged = "facet_session=eyJhbGciOiJIUzI1NiJ9.\
                  eyJzdWIiOiJvd25lciIsImlhdCI6MCwiZXhwIjo5OTk5OTk5OTk5LCJqdGkiOiJ4In0.\
                  bm90LXRoZS1yZWFsLXNpZ25hdHVyZQ";

    let err =
        tokio_tungstenite::connect_async(upgrade(&server, Some(forged), Some(&server.origin())))
            .await
            .expect_err("a token we did not sign must be refused");

    assert_eq!(rejected_with(err), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_is_accepted_with_a_valid_token() {
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let (mut socket, response) =
        tokio_tungstenite::connect_async(upgrade(&server, Some(&cookie), Some(&server.origin())))
            .await
            .expect("a valid session must be allowed through");

    assert_eq!(response.status().as_u16(), 101);

    // And it is a real shell on the other end, not just an accepted socket.

    // Wait for the prompt before typing. See `common::PROMPT`: cmd.exe is not
    // reading input the instant ConPTY hands it to us, and keystrokes sent
    // before it is ready are simply lost.
    let ready = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut seen = String::new();
        while let Some(Ok(msg)) = socket.next().await {
            if let tokio_tungstenite::tungstenite::Message::Binary(bytes) = msg {
                seen.push_str(&String::from_utf8_lossy(&bytes));
                if seen.contains(common::PROMPT) {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the shell's prompt");
    assert!(ready, "the shell never printed a prompt");

    for line in common::arithmetic_probe("A") {
        socket
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                format!("{line}\r\n").into_bytes().into(),
            ))
            .await
            .expect("send");
    }

    let expected = common::probe_output("A");
    let found = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut seen = String::new();
        while let Some(Ok(msg)) = socket.next().await {
            if let tokio_tungstenite::tungstenite::Message::Binary(bytes) = msg {
                seen.push_str(&String::from_utf8_lossy(&bytes));
                if seen.contains(&expected) {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("timed out waiting for shell output");

    assert!(
        found,
        "authenticated socket did not produce a working shell"
    );
}

#[tokio::test]
async fn ws_is_rejected_from_a_foreign_origin() {
    // Cross-site WebSocket hijacking: a page on evil.example tries to open a
    // socket to us and ride the victim's cookie.
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let err = tokio_tungstenite::connect_async(upgrade(
        &server,
        Some(&cookie),
        Some("http://evil.example"),
    ))
    .await
    .expect_err("a foreign origin must be refused even with a good cookie");

    assert_eq!(rejected_with(err), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ws_is_rejected_without_an_origin() {
    let server = common::serve_default().await;
    let client = common::client();
    let cookie = common::session_cookie(&client, &server).await;

    let err = tokio_tungstenite::connect_async(upgrade(&server, Some(&cookie), None))
        .await
        .expect_err("a missing Origin must be refused");

    assert_eq!(rejected_with(err), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_credentials_issue_a_hardened_session_cookie() {
    let server = common::serve_default().await;
    let client = common::client();

    let response = common::login(&client, &server).await;

    let cookie = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("facet_session="))
        .expect("session cookie");

    assert!(
        cookie.contains("HttpOnly"),
        "cookie must not be readable by JS: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "cookie must not ride cross-site requests: {cookie}"
    );
    assert!(cookie.contains("Path=/"), "{cookie}");
    // Secure is set only under TLS; this test server is plaintext loopback, so
    // asserting on it here would assert the opposite of what production does.
}

#[tokio::test]
async fn the_wrong_password_is_refused() {
    let server = common::serve_default().await;
    let client = common::client();

    let response =
        common::login_with(&client, &server, "not the password", &server.totp_code()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_wrong_totp_code_is_refused() {
    let server = common::serve_default().await;
    let client = common::client();

    let response = common::login_with(&client, &server, common::PASSWORD, "000000").await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn failures_do_not_reveal_which_factor_was_wrong() {
    // If a bad password and a bad code looked different, an attacker would know
    // when they had guessed the password.
    let server = common::serve_default().await;

    let bad_password = {
        let client = common::client();
        common::login_with(&client, &server, "wrong", &server.totp_code()).await
    };
    let bad_code = {
        let client = common::client();
        common::login_with(&client, &server, common::PASSWORD, "000000").await
    };

    assert_eq!(bad_password.status(), bad_code.status());

    let a = bad_password.text().await.expect("body");
    let b = bad_code.text().await.expect("body");

    // The pages differ only in their CSRF token, so compare the error banner.
    let banner = |html: &str| {
        html.find("class=\"error\"")
            .map(|i| html[i..i + 120].to_string())
            .unwrap_or_default()
    };
    assert_eq!(
        banner(&a),
        banner(&b),
        "the two failures render differently"
    );
}

#[tokio::test]
async fn a_totp_code_cannot_be_replayed() {
    let server = common::serve_default().await;
    let code = server.totp_code();

    let first = common::login_with(&common::client(), &server, common::PASSWORD, &code).await;
    assert_eq!(
        first.status(),
        StatusCode::SEE_OTHER,
        "first login should work"
    );

    // Same code, seconds later: an attacker who observed it must not get in.
    let second = common::login_with(&common::client(), &server, common::PASSWORD, &code).await;
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "code was replayable"
    );
}

#[tokio::test]
async fn login_without_a_csrf_token_is_refused() {
    let server = common::serve_default().await;
    let client = common::client();

    // Straight to the POST, as a cross-origin form would: no GET, so no token.
    let response = client
        .post(format!("http://{}/login", server.addr))
        .form(&[
            ("password", common::PASSWORD),
            ("code", &server.totp_code()),
            ("csrf", "forged"),
        ])
        .send()
        .await
        .expect("POST /login");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn lockout_is_enforced_after_repeated_failures() {
    let server = common::serve_default().await; // max_failed_attempts = 3
    let client = common::client();

    for attempt in 1..=3 {
        let response = common::login_with(&client, &server, "wrong", "000000").await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} should be a plain rejection"
        );
    }

    // The fourth attempt is refused before the credentials are even checked,
    // and crucially, so are the *correct* ones.
    let response =
        common::login_with(&client, &server, common::PASSWORD, &server.totp_code()).await;

    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "lockout must refuse even correct credentials"
    );
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_terminal_page_redirects_to_login_when_signed_out() {
    let server = common::serve_default().await;
    let client = common::client();

    let response = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

#[tokio::test]
async fn the_terminal_page_is_served_once_signed_in() {
    let server = common::serve_default().await;
    let client = common::client();
    common::login(&client, &server).await;

    let response = client
        .get(format!("http://{}/", server.addr))
        .send()
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");
    assert!(body.contains("xterm.js"), "expected the terminal page");
}
