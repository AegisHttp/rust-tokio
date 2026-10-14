//! One-time login challenges with a TTL and an optional client binding
//! (e.g. the hash of a pre-login cookie), redeemable exactly once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use rand::Rng;
use tokio::time::Instant;

struct Entry {
    expires_at: Instant,
    binding: Option<String>,
}

/// Issues and redeems one-time login challenges.
///
/// Uses the tokio clock, so tests may pause and advance time.
pub struct ChallengeStore {
    ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Issues a fresh challenge, optionally bound to a client value (such as
    /// the hash of a pre-login cookie). Expired entries are pruned here so
    /// unredeemed challenges do not accumulate.
    pub fn issue(&self, binding: Option<&str>) -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("challenge lock");
        entries.retain(|_, e| e.expires_at > now);
        entries.insert(
            challenge.clone(),
            Entry {
                expires_at: now + self.ttl,
                binding: binding.map(str::to_string),
            },
        );
        challenge
    }

    /// Redeems a challenge: succeeds at most once, only inside the TTL, and
    /// only with the binding it was issued with. A failed attempt with the
    /// wrong binding does not consume the challenge.
    pub fn redeem(&self, challenge: &str, binding: Option<&str>) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("challenge lock");
        let Some(entry) = entries.get(challenge) else {
            return false;
        };
        if entry.expires_at < now {
            entries.remove(challenge);
            return false;
        }
        if entry.binding.as_deref() != binding {
            return false;
        }
        entries.remove(challenge);
        true
    }

    /// Number of live (issued, unredeemed) challenges.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("challenge lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn store() -> ChallengeStore {
        ChallengeStore::new(Duration::from_secs(60))
    }

    #[tokio::test(start_paused = true)]
    async fn a_challenge_redeems_exactly_once() {
        let s = store();
        let c = s.issue(None);
        assert!(s.redeem(&c, None), "first redeem succeeds");
        assert!(!s.redeem(&c, None), "second redeem fails (one-time)");
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_challenges_fail() {
        let s = store();
        assert!(!s.redeem("never-issued", None));
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_challenge_fails() {
        let s = store();
        let c = s.issue(None);
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(!s.redeem(&c, None), "expired after the ttl");
    }

    #[tokio::test(start_paused = true)]
    async fn a_challenge_just_inside_the_ttl_succeeds() {
        let s = store();
        let c = s.issue(None);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(s.redeem(&c, None));
    }

    #[tokio::test(start_paused = true)]
    async fn binding_must_match_when_issued_with_one() {
        let s = store();
        let c = s.issue(Some("cookie-hash-1"));
        assert!(!s.redeem(&c, Some("cookie-hash-2")), "wrong binding");
        assert!(!s.redeem(&c, None), "missing binding");
        // wrong attempts must not consume the challenge
        assert!(s.redeem(&c, Some("cookie-hash-1")), "right binding");
    }

    #[tokio::test(start_paused = true)]
    async fn challenges_are_unique_and_long() {
        let s = store();
        let a = s.issue(None);
        let b = s.issue(None);
        assert_ne!(a, b);
        assert!(a.len() >= 32, "at least 192 bits of entropy encoded");
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_pruned_on_issue() {
        let s = store();
        let _ = s.issue(None);
        tokio::time::advance(Duration::from_secs(120)).await;
        let _ = s.issue(None);
        assert_eq!(s.len(), 1, "expired entries do not accumulate");
    }
}
