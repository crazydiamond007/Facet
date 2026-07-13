//! Authentication: argon2 password + TOTP second factor → a signed session
//! cookie. Everything a request path needs is behind [`Authenticator`].

pub mod password;
pub mod sessions;
pub mod token;
pub mod totp;

use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use parking_lot::Mutex;
use totp_rs::TOTP;

use crate::config::Auth as AuthConfig;
use crate::error::Result;
use crate::state::AppState;

/// What the login endpoint learned. The caller collapses every failure into one
/// message for the user; the variants exist so the audit log can be precise.
#[derive(Debug)]
pub enum Outcome {
    Ok {
        token: String,
        jti: String,
    },
    BadPassword,
    BadTotp,
    /// Correct code, already spent.
    ReplayedTotp,
    LockedOut {
        retry_after: Duration,
    },
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }

    /// One line for the audit log.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::BadPassword => "bad_password",
            Self::BadTotp => "bad_totp",
            Self::ReplayedTotp => "replayed_totp",
            Self::LockedOut { .. } => "locked_out",
        }
    }
}

/// Consecutive-failure lockout.
///
/// Deliberately **global**, not per-IP: this is a single-user app, and an
/// attacker who can rotate IPs would walk straight through a per-IP counter.
/// The cost is that an attacker who can reach the login page can lock the owner
/// out for `lockout_minutes`: a nuisance, not a compromise, and the reason the
/// README tells you to put this behind a tunnel rather than on a public port.
struct Lockout {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
    max_failures: u32,
    duration: Duration,
}

impl Lockout {
    /// `None` if we may proceed; `Some(remaining)` if we are locked.
    fn check(&mut self) -> Option<Duration> {
        let until = self.locked_until?;
        let remaining = until.checked_duration_since(Instant::now());

        match remaining {
            Some(left) => Some(left),
            None => {
                // Expired: clear it and let this attempt through.
                self.locked_until = None;
                self.consecutive_failures = 0;
                None
            }
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.max_failures {
            self.locked_until = Some(Instant::now() + self.duration);
            tracing::warn!(
                failures = self.consecutive_failures,
                seconds = self.duration.as_secs(),
                "login locked out"
            );
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
    }
}

pub struct Authenticator {
    password_hash: String,
    totp: TOTP,
    signer: token::Signer,
    lockout: Mutex<Lockout>,
    /// Highest TOTP time-step accepted so far; blocks replay. See `totp`.
    last_totp_step: Mutex<u64>,
    /// The sessions we have issued and not yet revoked. A valid signature is
    /// necessary but not sufficient: see [`sessions`].
    sessions: sessions::Sessions,
    /// Whether cookies get the `Secure` attribute and the `__Host-` prefix.
    /// False only for plaintext loopback development.
    secure_cookies: bool,
}

impl Authenticator {
    pub fn new(config: &AuthConfig, secure_cookies: bool) -> Result<Self> {
        Ok(Self {
            password_hash: config.password_hash.clone(),
            totp: totp::build(&config.totp_secret, "owner")?,
            signer: token::Signer::new(&config.jwt_secret, config.session_ttl_minutes)?,
            lockout: Mutex::new(Lockout {
                consecutive_failures: 0,
                locked_until: None,
                max_failures: config.max_failed_attempts.max(1),
                duration: Duration::from_secs(config.lockout_minutes.saturating_mul(60)),
            }),
            last_totp_step: Mutex::new(0),
            sessions: sessions::Sessions::default(),
            secure_cookies,
        })
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.secure_cookies {
            token::COOKIE
        } else {
            token::COOKIE_INSECURE
        }
    }

    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.signer.ttl_seconds())
    }

    /// The full login check.
    ///
    /// **Blocking**: argon2 is deliberately expensive, so callers must run this
    /// on a blocking thread or it will stall the async runtime.
    ///
    /// Password and TOTP are *both* evaluated even when the password is already
    /// known to be wrong. Short-circuiting would make a wrong password
    /// measurably faster than a wrong code, handing an attacker an oracle for
    /// which factor they had already guessed.
    pub fn authenticate(&self, password: &str, code: &str) -> Outcome {
        if let Some(retry_after) = self.lockout.lock().check() {
            return Outcome::LockedOut { retry_after };
        }

        let password_ok = password::verify(password, &self.password_hash);

        let last_step = *self.last_totp_step.lock();
        let (totp_result, matched_step) = match totp::check(&self.totp, code, last_step) {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, "totp check failed");
                (totp::Totp::Wrong, last_step)
            }
        };

        let outcome = match (password_ok, totp_result) {
            (false, _) => Outcome::BadPassword,
            (true, totp::Totp::Wrong) => Outcome::BadTotp,
            (true, totp::Totp::Replayed) => Outcome::ReplayedTotp,
            (true, totp::Totp::Ok) => match self.signer.issue() {
                Ok((token, claims)) => {
                    // Burn the code only on a fully successful login, so a
                    // wrong password cannot be used to consume the owner's
                    // codes and lock them out of their own authenticator.
                    *self.last_totp_step.lock() = matched_step;

                    // The token is worthless until it is here: `session` will
                    // not honour a jti the registry has never heard of.
                    self.sessions
                        .register(claims.jti.clone(), claims.exp, claims.iat);

                    Outcome::Ok {
                        token,
                        jti: claims.jti,
                    }
                }
                Err(err) => {
                    tracing::error!(%err, "could not issue session token");
                    Outcome::BadPassword
                }
            },
        };

        let mut lockout = self.lockout.lock();
        if outcome.succeeded() {
            lockout.record_success();
        } else {
            lockout.record_failure();
        }

        outcome
    }

    /// Pull a session out of the cookie jar, if there is a valid one.
    ///
    /// Two checks, and the second one is the one that took work. The signature
    /// proves the token is ours and unexpired. The registry proves it has not
    /// been *signed out*, which the token itself cannot tell us: a JWT that has
    /// been revoked looks exactly like one that has not.
    ///
    /// Every authenticated route funnels through here (the `Authenticated`
    /// extractor, the index redirect, `/api`, the WebSocket upgrade), which is
    /// why revocation only had to be implemented once.
    pub fn session(&self, jar: &CookieJar) -> Option<token::Claims> {
        let raw = jar.get(self.cookie_name())?.value();
        let claims = self.signer.verify(raw)?;

        self.is_live(&claims.jti).then_some(claims)
    }

    /// Whether a session id is still one we honour.
    ///
    /// Separate from [`Self::session`] because the WebSocket has no cookie jar
    /// to re-read: once the socket is upgraded the browser never sends another
    /// header, so the bridge holds the `jti` and asks us about it on a timer.
    pub fn is_live(&self, jti: &str) -> bool {
        // A clock we cannot read is a clock we cannot check an expiry against,
        // so refuse rather than guess.
        let Ok(now) = token::unix_now() else {
            tracing::error!("could not read the system clock; refusing the session");
            return false;
        };

        self.sessions.is_live(jti, now)
    }

    /// Sign a session out. Returns false if it was already gone, so the caller
    /// does not write an audit record for a logout that logged nothing out.
    pub fn revoke(&self, jti: &str) -> bool {
        self.sessions.revoke(jti)
    }
}

/// Extractor for routes that require a session. Rejects with a bare 401: no
/// body, no hint about which part of the check failed.
pub struct Authenticated(pub token::Claims);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        state
            .auth
            .session(&jar)
            .map(Authenticated)
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> (AuthConfig, String) {
        use base64::Engine as _;
        let secret = totp::generate_secret();
        (
            AuthConfig {
                password_hash: password::hash("hunter2").expect("hash"),
                totp_secret: secret.clone(),
                jwt_secret: base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                session_ttl_minutes: 60,
                max_failed_attempts: 3,
                lockout_minutes: 15,
            },
            secret,
        )
    }

    fn current_code(secret: &str) -> String {
        let totp = totp::build(secret, "owner").expect("totp");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        totp.generate(now)
    }

    #[test]
    fn accepts_the_right_password_and_code() {
        let (config, secret) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");

        let outcome = auth.authenticate("hunter2", &current_code(&secret));
        assert!(outcome.succeeded(), "{outcome:?}");
    }

    #[test]
    fn rejects_a_valid_code_with_the_wrong_password() {
        let (config, secret) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");

        let outcome = auth.authenticate("wrong", &current_code(&secret));
        assert!(matches!(outcome, Outcome::BadPassword));
    }

    #[test]
    fn rejects_the_right_password_with_a_wrong_code() {
        let (config, _) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");

        let outcome = auth.authenticate("hunter2", "000000");
        assert!(matches!(outcome, Outcome::BadTotp | Outcome::BadPassword));
    }

    #[test]
    fn a_failed_password_does_not_burn_the_totp_code() {
        // Otherwise an attacker could spend the owner's codes by spamming the
        // login with a bad password, locking them out of their own account.
        let (config, secret) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");
        let code = current_code(&secret);

        assert!(matches!(
            auth.authenticate("wrong", &code),
            Outcome::BadPassword
        ));

        // The same code must still work with the right password.
        assert!(auth.authenticate("hunter2", &code).succeeded());
    }

    #[test]
    fn locks_out_after_the_configured_number_of_failures() {
        let (config, secret) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");

        for _ in 0..config.max_failed_attempts {
            assert!(!auth.authenticate("wrong", "000000").succeeded());
        }

        // Now even correct credentials are refused, which is the point.
        let outcome = auth.authenticate("hunter2", &current_code(&secret));
        assert!(
            matches!(outcome, Outcome::LockedOut { .. }),
            "expected lockout, got {outcome:?}"
        );
    }

    #[test]
    fn a_successful_login_clears_the_failure_counter() {
        let (config, secret) = config();
        let auth = Authenticator::new(&config, true).expect("authenticator");

        // One short of a lockout...
        for _ in 0..config.max_failed_attempts - 1 {
            assert!(!auth.authenticate("wrong", "000000").succeeded());
        }
        assert!(
            auth.authenticate("hunter2", &current_code(&secret))
                .succeeded()
        );

        // ...and the counter is back to zero, so this does not lock us out.
        assert!(!auth.authenticate("wrong", "000000").succeeded());
        let outcome = auth.authenticate("wrong", "000000");
        assert!(!matches!(outcome, Outcome::LockedOut { .. }));
    }
}
