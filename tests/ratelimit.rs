//! Per-IP throttling on the login endpoint.
//!
//! The lockout (tests/auth.rs) stops someone guessing the password. This stops
//! someone making us burn argon2 CPU while they do it.

mod common;

use reqwest::StatusCode;

/// A server whose limiter allows `burst` attempts and then refuses.
///
/// The refill is set absurdly slow so the tests are not racing a clock: once
/// the burst is spent, it stays spent for the length of the test.
async fn serve_limited(burst: u32, trust_forwarded_for: bool) -> common::Server {
    let (mut config, secret) = common::test_config(common::interactive_shell());
    config.rate_limit.enabled = true;
    config.rate_limit.burst = burst;
    config.rate_limit.per_seconds = 3600;
    config.server.trust_forwarded_for = trust_forwarded_for;

    // Keep the account lockout out of the way: this file is about the limiter,
    // and a lockout would answer 429 too and muddy every assertion.
    if let Some(auth) = config.auth.as_mut() {
        auth.max_failed_attempts = u32::MAX;
    }

    common::serve(config, secret).await
}

/// POST the login form directly, with optional spoofed forwarding headers.
async fn attempt(
    client: &reqwest::Client,
    server: &common::Server,
    forwarded_for: Option<&str>,
) -> StatusCode {
    let mut request = client.post(format!("http://{}/login", server.addr)).form(&[
        ("password", "wrong"),
        ("code", "000000"),
        ("csrf", "irrelevant"),
    ]);

    if let Some(ip) = forwarded_for {
        request = request.header("x-forwarded-for", ip);
    }

    request.send().await.expect("POST /login").status()
}

#[tokio::test]
async fn the_burst_is_allowed_and_then_the_flood_is_refused() {
    let server = serve_limited(5, false).await;
    let client = common::client();

    // The burst is what a human fumbling a TOTP code gets to use.
    for attempt_number in 1..=5 {
        let status = attempt(&client, &server, None).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "attempt {attempt_number} was throttled while still inside the burst"
        );
    }

    // Beyond it, we stop paying for argon2 on their behalf.
    let status = attempt(&client, &server, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the limiter let the flood through"
    );
}

#[tokio::test]
async fn a_throttled_response_says_when_to_come_back() {
    let server = serve_limited(1, false).await;
    let client = common::client();

    attempt(&client, &server, None).await;

    let response = client
        .post(format!("http://{}/login", server.addr))
        .form(&[("password", "x"), ("code", "1"), ("csrf", "x")])
        .send()
        .await
        .expect("POST /login");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .contains_key(reqwest::header::RETRY_AFTER),
        "a 429 without Retry-After tells the client nothing useful"
    );
}

#[tokio::test]
async fn x_forwarded_for_is_ignored_unless_it_is_trusted() {
    // The default. An attacker who can reach facet directly can put anything in
    // X-Forwarded-For; if we keyed on it they would get a fresh bucket per
    // request and walk straight through the limiter. Here every request must
    // land in the same bucket regardless of what they claim.
    let server = serve_limited(3, false).await;
    let client = common::client();

    for _ in 0..3 {
        attempt(&client, &server, Some("203.0.113.1")).await;
    }

    let status = attempt(&client, &server, Some("198.51.100.99")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "spoofing X-Forwarded-For got a fresh rate-limit bucket; the limiter is bypassable"
    );
}

#[tokio::test]
async fn x_forwarded_for_is_honoured_when_it_is_trusted() {
    // Behind a proxy that sets the header, two different clients must get two
    // different buckets, or one busy user throttles everybody else.
    let server = serve_limited(3, true).await;
    let client = common::client();

    for _ in 0..3 {
        attempt(&client, &server, Some("203.0.113.1")).await;
    }

    // That IP is now spent.
    assert_eq!(
        attempt(&client, &server, Some("203.0.113.1")).await,
        StatusCode::TOO_MANY_REQUESTS
    );

    // A different client behind the same proxy is unaffected.
    assert_ne!(
        attempt(&client, &server, Some("198.51.100.99")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a second client was throttled for the first one's traffic"
    );
}

#[tokio::test]
async fn the_terminal_is_not_throttled() {
    // The limiter guards the login endpoint only. Applying it to everything
    // would throttle the terminal's own traffic, which is the one thing this
    // program exists to carry.
    let server = serve_limited(1, false).await;
    let client = common::client();

    // Spend the login budget.
    attempt(&client, &server, None).await;
    attempt(&client, &server, None).await;

    // Static assets and the health check must still answer.
    for path in ["/healthz", "/assets/app.js"] {
        let status = client
            .get(format!("http://{}{path}", server.addr))
            .send()
            .await
            .expect("GET")
            .status();

        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "{path} was throttled by the login limiter"
        );
    }
}

#[tokio::test]
async fn a_real_login_still_works_within_the_burst() {
    // The limiter must not lock the owner out of their own machine.
    let server = serve_limited(10, false).await;
    let client = common::client();

    let response =
        common::login_with(&client, &server, common::PASSWORD, &server.totp_code()).await;

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a legitimate login was refused"
    );
}
