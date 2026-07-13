//! Session tokens: HS256 JWTs carried in an httpOnly cookie.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Cookie name. `__Host-` is not a decoration: browsers enforce that such a
/// cookie is Secure, has `Path=/`, and carries **no** `Domain` attribute, which
/// makes it impossible for a sibling subdomain to plant one on us.
pub const COOKIE: &str = "__Host-facet_session";

/// Fallback name for plaintext loopback development, where `__Host-` cannot be
/// set (it requires Secure, which requires HTTPS).
pub const COOKIE_INSECURE: &str = "facet_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject. Single-user app, so this is always the owner.
    pub sub: String,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds). Enforced by `jsonwebtoken`.
    pub exp: u64,
    /// Session id, so the audit log can correlate a login with the terminal
    /// sessions opened under it.
    pub jti: String,
}

pub struct Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    ttl_seconds: u64,
}

impl Signer {
    /// `secret` is the base64 blob from the config.
    pub fn new(secret_base64: &str, ttl_minutes: u64) -> Result<Self> {
        use base64::Engine as _;

        let key = base64::engine::general_purpose::STANDARD
            .decode(secret_base64.trim())
            .map_err(|e| Error::Config(format!("auth.jwt_secret is not valid base64: {e}")))?;

        // 256 bits, matching HS256's output. A shorter key would weaken the MAC
        // without any warning from the library, so we refuse it outright.
        if key.len() < 32 {
            return Err(Error::Config(format!(
                "auth.jwt_secret is {} bytes; needs at least 32. Re-run `facet setup`.",
                key.len()
            )));
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["exp", "sub"]);
        validation.leeway = 5;

        Ok(Self {
            encoding: EncodingKey::from_secret(&key),
            decoding: DecodingKey::from_secret(&key),
            validation,
            ttl_seconds: ttl_minutes.saturating_mul(60),
        })
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    pub fn issue(&self) -> Result<(String, Claims)> {
        let now = unix_now()?;
        let claims = Claims {
            sub: "owner".into(),
            iat: now,
            exp: now.saturating_add(self.ttl_seconds),
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|e| Error::Config(format!("could not sign session token: {e}")))?;

        Ok((token, claims))
    }

    /// Verify signature and expiry. Any failure is just "not authenticated";
    /// we never tell the caller which part failed.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        decode::<Claims>(token, &self.decoding, &self.validation)
            .ok()
            .map(|data| data.claims)
    }
}

fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Config("system clock is before the unix epoch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(ttl_minutes: u64) -> Signer {
        use base64::Engine as _;
        let secret = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        Signer::new(&secret, ttl_minutes).expect("signer")
    }

    #[test]
    fn issues_a_token_it_accepts() {
        let signer = signer(60);
        let (token, issued) = signer.issue().expect("issue");
        let claims = signer.verify(&token).expect("verify");
        assert_eq!(claims.sub, "owner");
        assert_eq!(claims.jti, issued.jti);
    }

    #[test]
    fn rejects_a_token_signed_with_another_key() {
        use base64::Engine as _;
        let other = Signer::new(
            &base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            60,
        )
        .expect("signer");

        let (token, _) = other.issue().expect("issue");
        assert!(signer(60).verify(&token).is_none());
    }

    #[test]
    fn rejects_an_expired_token() {
        let signer = signer(60);

        // Sign a token that expired in 1970, well outside the 5s leeway, so
        // the test proves expiry is enforced without having to sleep.
        let expired = Claims {
            sub: "owner".into(),
            iat: 0,
            exp: 1,
            jti: "old".into(),
        };
        let token =
            encode(&Header::new(Algorithm::HS256), &expired, &signer.encoding).expect("encode");

        assert!(signer.verify(&token).is_none());
    }

    #[test]
    fn rejects_garbage_and_the_none_algorithm() {
        let signer = signer(60);
        assert!(signer.verify("").is_none());
        assert!(signer.verify("not.a.jwt").is_none());
        // alg=none with the right-looking claims must not be honoured.
        let alg_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
                        eyJzdWIiOiJvd25lciIsImlhdCI6MCwiZXhwIjo5OTk5OTk5OTk5LCJqdGkiOiJ4In0.";
        assert!(signer.verify(alg_none).is_none());
    }

    #[test]
    fn refuses_a_short_secret() {
        use base64::Engine as _;
        let weak = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(Signer::new(&weak, 60).is_err());
    }
}
