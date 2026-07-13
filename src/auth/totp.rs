//! TOTP (RFC 6238) second factor.
//!
//! SHA1 / 6 digits / 30s, which is not a preference so much as what Google
//! Authenticator, Aegis, 1Password and friends actually implement.
//!
//! ## Replay
//!
//! A skew of ±1 step means three codes are valid at any instant, so a code
//! observed by an attacker stays usable for up to 90 seconds. We therefore
//! remember the time-step of the last accepted code and refuse to accept that
//! step or any earlier one again: a code is good exactly once.

use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{Error, Result};

const STEP: u64 = 30;
const DIGITS: usize = 6;
const SKEW: u8 = 1;
const ISSUER: &str = "facet";

/// Build a TOTP from the base32 secret in the config.
pub fn build(secret_base32: &str, account: &str) -> Result<TOTP> {
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| Error::Config(format!("auth.totp_secret is not valid base32: {e:?}")))?;

    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .map_err(|e| Error::Config(format!("could not build TOTP: {e}")))
}

/// Generate a fresh random secret, base32-encoded, for `facet setup`.
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// The outcome of checking a code. The caller turns all failures into one
/// generic message; the distinction exists only for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Totp {
    Ok,
    Wrong,
    /// Correct code, but already used. Someone is replaying.
    Replayed,
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Config("system clock is before the unix epoch".into()))
}

/// Check `code`, rejecting any step at or before `last_accepted_step`.
///
/// On success, returns the step that matched so the caller can persist it.
pub fn check(totp: &TOTP, code: &str, last_accepted_step: u64) -> Result<(Totp, u64)> {
    let current = now()? / STEP;

    // Walk the skew window newest-first so a replay of an older code cannot
    // shadow a legitimate current one.
    let oldest = current.saturating_sub(SKEW as u64);
    let newest = current.saturating_add(SKEW as u64);

    for step in (oldest..=newest).rev() {
        let expected = totp.generate(step * STEP);

        if !constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            continue;
        }

        return if step <= last_accepted_step {
            Ok((Totp::Replayed, last_accepted_step))
        } else {
            Ok((Totp::Ok, step))
        };
    }

    Ok((Totp::Wrong, last_accepted_step))
}

/// Length is not secret (codes are always 6 digits); the contents are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totp() -> TOTP {
        build(&generate_secret(), "test@facet").expect("build totp")
    }

    #[test]
    fn accepts_the_current_code() {
        let totp = totp();
        let step = now().expect("clock") / STEP;
        let code = totp.generate(step * STEP);

        let (result, accepted) = check(&totp, &code, 0).expect("check");
        assert_eq!(result, Totp::Ok);
        assert_eq!(accepted, step);
    }

    #[test]
    fn rejects_a_wrong_code() {
        let totp = totp();
        let (result, _) = check(&totp, "000000", 0).expect("check");
        // Vanishingly unlikely to collide, but be honest about it.
        let step = now().expect("clock") / STEP;
        if totp.generate(step * STEP) != "000000" {
            assert_eq!(result, Totp::Wrong);
        }
    }

    #[test]
    fn a_code_cannot_be_used_twice() {
        let totp = totp();
        let step = now().expect("clock") / STEP;
        let code = totp.generate(step * STEP);

        let (first, accepted) = check(&totp, &code, 0).expect("check");
        assert_eq!(first, Totp::Ok);

        // Same code, now that we have recorded its step: must be refused.
        let (second, _) = check(&totp, &code, accepted).expect("check");
        assert_eq!(second, Totp::Replayed);
    }

    #[test]
    fn a_stale_code_from_inside_the_skew_window_is_refused_after_a_newer_one() {
        let totp = totp();
        let current = now().expect("clock") / STEP;
        let previous_code = totp.generate((current - 1) * STEP);

        // Pretend we already accepted the current step.
        let (result, _) = check(&totp, &previous_code, current).expect("check");
        assert_eq!(result, Totp::Replayed);
    }

    #[test]
    fn empty_and_malformed_codes_are_rejected() {
        let totp = totp();
        for code in ["", "12345", "1234567", "abcdef", "     "] {
            let (result, _) = check(&totp, code, 0).expect("check");
            assert_eq!(result, Totp::Wrong, "accepted {code:?}");
        }
    }
}
