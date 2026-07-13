//! Argon2id password hashing.

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};

use crate::error::{Error, Result};

/// Hash a password into a PHC string, which carries its own random salt and
/// cost parameters. `Argon2::default()` is Argon2id at the parameters OWASP
/// currently recommends (m=19 MiB, t=2, p=1).
pub fn hash(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Config(format!("could not hash password: {e}")))
}

/// Verify a password against a PHC string.
///
/// Deliberately returns `bool`, not `Result`: a malformed hash in the config
/// and a wrong password must be indistinguishable to the caller, so there is no
/// error path that could be timed or logged differently.
///
/// This is intentionally slow (tens of milliseconds). Callers **must** run it
/// on a blocking thread. See `web::login`.
#[must_use]
pub fn verify(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        tracing::error!("auth.password_hash is not a valid PHC string; no password can match");
        return false;
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let phc = hash("correct horse battery staple").expect("hash");
        assert!(verify("correct horse battery staple", &phc));
        assert!(!verify("Correct horse battery staple", &phc));
        assert!(!verify("", &phc));
    }

    #[test]
    fn salts_are_unique() {
        // Same password, different hash: the salt is doing its job.
        let a = hash("hunter2").expect("hash");
        let b = hash("hunter2").expect("hash");
        assert_ne!(a, b);
        assert!(verify("hunter2", &a) && verify("hunter2", &b));
    }

    #[test]
    fn garbage_hash_never_verifies() {
        assert!(!verify("anything", "not-a-phc-string"));
        assert!(!verify("anything", ""));
    }
}
