//! Per-IP rate limiting on the login endpoint, and the question of what "the
//! client's IP" even means.
//!
//! ## Why, given there is already a lockout
//!
//! The lockout in [`crate::auth`] is the brute-force defence: five wrong
//! answers and nobody gets in for fifteen minutes, however fast they ask.
//!
//! This is a different problem. Verifying a password is *deliberately*
//! expensive: argon2 is tuned to burn tens of milliseconds of CPU so that an
//! offline attack on a stolen hash is slow. That cost is a gift to anyone
//! flooding the login endpoint, who can pin a core with a few hundred requests
//! a second and starve the terminal sessions the machine exists to serve. The
//! limiter refuses the flood *before* it reaches argon2.
//!
//! ## Which IP
//!
//! Neither answer is safe by default, which is why it is a config decision:
//!
//! * **The TCP peer.** Correct when facet is reachable directly. But behind a
//!   Cloudflare or Tailscale tunnel every request arrives from 127.0.0.1, so
//!   all callers share one bucket: an attacker's flood then throttles the owner
//!   too, which is the failure mode we were trying to avoid.
//! * **`X-Forwarded-For`.** Correct behind a proxy that sets it. But the header
//!   is just a string that anyone can send. With no proxy in front, an attacker
//!   changes it on every request, gets a fresh bucket each time, and walks
//!   straight through the limiter.
//!
//! So `server.trust_forwarded_for` defaults to **false** (use the peer), and
//! turning it on is a statement that a proxy you control is in front and
//! overwrites the header.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode, header};
use axum::middleware::Next;
use tower_governor::GovernorLayer;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};

use crate::audit::{self, Event};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::state::AppState;

/// How often to discard rate-limit buckets nobody has used lately. Without this
/// the limiter's map grows once per distinct IP and never shrinks.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Marker on a response the limiter rejected.
///
/// The lockout *also* answers 429, so a middleware cannot tell the two apart by
/// status alone, and would log every lockout a second time as a rate limit.
#[derive(Clone, Copy)]
struct RateLimited;

/// The caller's IP, according to the configured trust policy.
///
/// Used by the limiter, and by the audit log: behind a tunnel with
/// `trust_forwarded_for` off, every login is recorded as coming from 127.0.0.1,
/// which makes an audit log that exists to answer "who logged in, from where"
/// unable to answer it.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_forwarded_for: bool) -> IpAddr {
    if !trust_forwarded_for {
        return peer.ip();
    }

    // The left-most entry is the original client; the rest are the proxies it
    // passed through.
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok());

    let real_ip = || {
        headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
    };

    forwarded.or_else(real_ip).unwrap_or_else(|| peer.ip())
}

/// Wrap `router` in the login limiter. Returns it untouched when disabled.
pub fn apply(router: Router<AppState>, state: &AppState) -> Result<Router<AppState>> {
    let config: &Config = &state.config;

    if !config.rate_limit.enabled {
        tracing::warn!("rate limiting is disabled; the login endpoint is unthrottled");
        return Ok(router);
    }

    let per_seconds = config.rate_limit.per_seconds;
    let burst = config.rate_limit.burst;

    tracing::info!(
        per_seconds,
        burst,
        trust_forwarded_for = config.server.trust_forwarded_for,
        "login rate limiting"
    );

    // The two key extractors are different types, so they cannot be selected at
    // runtime into one variable. `Router::layer` erases the layer's type, so
    // branching on the whole layered router is what makes this work.
    if config.server.trust_forwarded_for {
        throttle(router, state, SmartIpKeyExtractor, per_seconds, burst)
    } else {
        throttle(router, state, PeerIpKeyExtractor, per_seconds, burst)
    }
}

fn throttle<K>(
    router: Router<AppState>,
    state: &AppState,
    key: K,
    per_seconds: u64,
    burst: u32,
) -> Result<Router<AppState>>
where
    K: KeyExtractor + Send + Sync + 'static,
    K::Key: Send + Sync + 'static,
{
    let config = GovernorConfigBuilder::default()
        .per_second(per_seconds)
        .burst_size(burst)
        .key_extractor(key)
        .finish()
        .ok_or_else(|| {
            Error::Config(format!(
                "could not build a rate limiter from per_seconds = {per_seconds}, burst = {burst}"
            ))
        })?;

    // Buckets for IPs that have gone away are kept forever otherwise, which for
    // a public-facing login page is an unbounded map keyed by attacker choice.
    let limiter = config.limiter().clone();
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                ticker.tick().await;
                limiter.retain_recent();
            }
        });
    }

    // Order matters. `layer` applies outermost-last, so the audit middleware
    // added second wraps the limiter added first, and therefore gets to see the
    // 429 the limiter produced *and* still has the request's IP to log with it.
    Ok(router
        .layer(GovernorLayer::new(config).error_handler(rejected))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit_rejections,
        )))
}

/// Turn a limiter rejection into a response. Marked, so the audit middleware
/// can tell it apart from the lockout's 429.
fn rejected(error: GovernorError) -> Response<Body> {
    match error {
        GovernorError::TooManyRequests { wait_time, .. } => {
            let mut response = plain(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait_time}s.\n"),
            );
            if let Ok(value) = HeaderValue::try_from(wait_time.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response.extensions_mut().insert(RateLimited);
            response
        }

        // The key extractor could not find an IP. Refusing is the only safe
        // answer: serving the request would mean serving it unthrottled.
        GovernorError::UnableToExtractKey => {
            tracing::error!("rate limiter could not determine the client IP; refusing the request");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
        }

        GovernorError::Other { code, .. } => plain(code, "request refused\n"),
    }
}

/// Build a small text response without `unwrap`, which has no business on a
/// request path.
fn plain(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Record throttled attempts in the audit log, with the IP that made them.
///
/// This sits *outside* the limiter so it can see the rejection. It keys off the
/// `RateLimited` marker rather than the 429 status, because the account lockout
/// answers 429 too and already logs itself.
async fn audit_rejections(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response<Body> {
    // The request is consumed by `next`, so capture what we need first. The
    // peer comes out of the extensions rather than an extractor: `ConnectInfo`
    // is only present when the service was built with it, and a middleware that
    // refuses to compile without it would be an odd way to find that out.
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| *peer)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    let response = next.run(request).await;

    if response.extensions().get::<RateLimited>().is_some() {
        audit::log(Event::LoginFailed {
            // Log the same IP the limiter keyed on, so the audit trail and the
            // throttle agree about who the caller was.
            ip: client_ip(&headers, peer, state.config.server.trust_forwarded_for),
            reason: "rate_limited",
        });
    }

    response
}
