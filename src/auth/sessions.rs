//! The live-session registry: the thing that makes signing out mean something.
//!
//! A JWT is self-contained by design. Anyone holding one can prove it is
//! authentic and unexpired without asking us, which is exactly what makes it
//! cheap, and exactly what makes it impossible to take back. Clearing the cookie
//! at logout only removes the browser's *copy*: the token itself keeps working
//! until it expires, so anything that captured it (a shoulder-surfed dev tools
//! pane, a shared machine, a proxy log) keeps working too.
//!
//! So a signature is no longer sufficient here. A token is accepted only while
//! its `jti` is in this registry. Logging in adds it, logging out removes it,
//! and expiry sweeps it.
//!
//! **This is an allowlist, not a denylist, and the difference is the whole
//! point.** A denylist of revoked ids would have to survive a restart to mean
//! anything: the registry lives in memory, so a restart would empty it, and
//! every token you had revoked would spring back to life. An allowlist fails the
//! other way. A restart empties it too, but an empty allowlist accepts *nothing*,
//! so the worst a restart can do is make you sign in again. When the failure
//! modes are "silently un-revokes a stolen session" and "asks you for your
//! password", the choice makes itself.

use std::collections::HashMap;

use parking_lot::Mutex;

/// Live sessions, keyed by the JWT's `jti`, valued by its expiry (unix seconds).
///
/// Storing the expiry lets one lookup answer both questions a caller has: is
/// this session still known, and is it still in date. The socket ticker in
/// `web::ws` depends on that, because a token can lapse mid-session while the
/// browser never sends another cookie for us to re-verify.
#[derive(Default)]
pub struct Sessions {
    live: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    /// Record a session issued by [`super::token::Signer::issue`].
    ///
    /// Sweeps on the way in. A single-user app holds a handful of sessions at
    /// most, so this is cheaper than running a timer to do it, and it means the
    /// map cannot grow without bound no matter how many times you sign in.
    pub fn register(&self, jti: String, exp: u64, now: u64) {
        let mut live = self.live.lock();
        live.retain(|_, expiry| *expiry > now);
        live.insert(jti, exp);
    }

    /// Forget a session. Returns whether it was there, so the caller can avoid
    /// writing an audit record for a logout that logged nothing out.
    pub fn revoke(&self, jti: &str) -> bool {
        self.live.lock().remove(jti).is_some()
    }

    /// Is this session still usable right now?
    pub fn is_live(&self, jti: &str, now: u64) -> bool {
        self.live
            .lock()
            .get(jti)
            .is_some_and(|expiry| *expiry > now)
    }

    /// How many sessions are currently signed in.
    pub fn count(&self) -> usize {
        self.live.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    #[test]
    fn a_registered_session_is_live() {
        let sessions = Sessions::default();
        sessions.register("a".into(), NOW + 60, NOW);
        assert!(sessions.is_live("a", NOW));
    }

    #[test]
    fn an_unknown_session_is_not_live() {
        // The case that matters: a token with a perfectly good signature that
        // this process never issued. Before the registry, that was accepted.
        let sessions = Sessions::default();
        assert!(!sessions.is_live("forged-but-well-signed", NOW));
    }

    #[test]
    fn revoking_takes_a_session_out_immediately() {
        let sessions = Sessions::default();
        sessions.register("a".into(), NOW + 3_600, NOW);

        assert!(sessions.revoke("a"));
        assert!(
            !sessions.is_live("a", NOW),
            "a revoked session was still accepted; logout does not revoke"
        );
    }

    #[test]
    fn revoking_twice_reports_the_second_one_did_nothing() {
        let sessions = Sessions::default();
        sessions.register("a".into(), NOW + 60, NOW);

        assert!(sessions.revoke("a"));
        assert!(!sessions.revoke("a"));
    }

    #[test]
    fn an_expired_session_is_not_live_even_though_it_is_still_registered() {
        // The sweep runs on registration, so an expired entry can still be
        // sitting in the map. It must not be honoured just for being there.
        let sessions = Sessions::default();
        sessions.register("a".into(), NOW + 10, NOW);

        assert!(!sessions.is_live("a", NOW + 11));
    }

    #[test]
    fn registering_sweeps_the_expired_entries() {
        let sessions = Sessions::default();
        sessions.register("old".into(), NOW + 10, NOW);
        sessions.register("older".into(), NOW + 20, NOW);
        assert_eq!(sessions.count(), 2);

        // Long enough later that both are dead. Registering must not leave them
        // to accumulate for the lifetime of the process.
        sessions.register("new".into(), NOW + 1_000, NOW + 500);
        assert_eq!(sessions.count(), 1);
        assert!(sessions.is_live("new", NOW + 500));
    }

    #[test]
    fn sessions_are_independent() {
        // Signing out of one browser must not sign you out of the other.
        let sessions = Sessions::default();
        sessions.register("laptop".into(), NOW + 60, NOW);
        sessions.register("phone".into(), NOW + 60, NOW);

        sessions.revoke("laptop");

        assert!(!sessions.is_live("laptop", NOW));
        assert!(sessions.is_live("phone", NOW));
    }
}
