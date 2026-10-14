//! Login orchestration: one-time challenge redemption, key lookup,
//! clearsign verification, identity and revocation checks, and the
//! application's authorization hook (where fingerprints get pinned).

use std::sync::Arc;

use pgp::composed::{Deserializable, SignedPublicKey};
use serde::Deserialize;

use crate::challenge::ChallengeStore;
use crate::lookup::{HttpFetch, KeyLookup, LookupError};
use crate::verify::{self, VerifyError};

/// The body the extension posts to the login endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub challenge: String,
    /// Armored clearsigned message over exactly the challenge.
    pub signature: String,
    /// Client-supplied armored public key; ignored unless
    /// [`LoginConfig::allow_client_key`] is set.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// A successfully verified login, before the application issues a session.
#[derive(Debug, Clone)]
pub struct VerifiedLogin {
    pub email: String,
    /// Primary key fingerprint, uppercase hex. Pin it on first login.
    pub fingerprint: String,
    /// The verified public key; register it as the E2E response recipient.
    pub public_key: SignedPublicKey,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("invalid or expired challenge")]
    InvalidChallenge,
    #[error(transparent)]
    Lookup(#[from] LookupError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("the key has been revoked")]
    Revoked,
    #[error("login rejected: {0}")]
    Rejected(String),
}

/// Application decision point: which verified identities may log in. Pin the
/// fingerprint on first login and compare it afterwards; return `Err` with a
/// reason to reject.
#[async_trait::async_trait]
pub trait LoginHook: Send + Sync {
    async fn authorize(&self, email: &str, fingerprint: &str) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// Accept the client-supplied `public_key` when lookup finds nothing.
    /// Off by default: a client-chosen key defeats the keyserver check.
    pub allow_client_key: bool,
    /// Reject keys that carry a revocation signature.
    pub check_revocation: bool,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            allow_client_key: false,
            check_revocation: true,
        }
    }
}

/// Verifies login requests end to end.
pub struct LoginService<H> {
    challenges: Arc<ChallengeStore>,
    lookup: KeyLookup<H>,
    hook: Arc<dyn LoginHook>,
    config: LoginConfig,
}

impl<H: HttpFetch> LoginService<H> {
    pub fn new(
        challenges: Arc<ChallengeStore>,
        lookup: KeyLookup<H>,
        hook: Arc<dyn LoginHook>,
        config: LoginConfig,
    ) -> Self {
        Self {
            challenges,
            lookup,
            hook,
            config,
        }
    }

    pub fn challenges(&self) -> &ChallengeStore {
        &self.challenges
    }

    pub fn lookup(&self) -> &KeyLookup<H> {
        &self.lookup
    }

    /// Verifies one login request. `binding` must match what the challenge
    /// was issued with (e.g. a pre-login cookie hash), if anything.
    pub async fn login(
        &self,
        request: &LoginRequest,
        binding: Option<&str>,
    ) -> Result<VerifiedLogin, LoginError> {
        if !self.challenges.redeem(&request.challenge, binding) {
            return Err(LoginError::InvalidChallenge);
        }
        let key = self.resolve_key(request).await?;
        let fingerprint = verify::verify_clearsign(&request.signature, &request.challenge, &key)?;
        if self.config.check_revocation && verify::is_revoked(&key) {
            return Err(LoginError::Revoked);
        }
        self.hook
            .authorize(&request.email, &fingerprint)
            .await
            .map_err(LoginError::Rejected)?;
        Ok(VerifiedLogin {
            email: request.email.clone(),
            fingerprint,
            public_key: key,
        })
    }

    /// Fetches the key from WKD / keyservers; falls back to the
    /// client-supplied key only when allowed. Either way the key must carry
    /// an identity for the claimed e-mail.
    async fn resolve_key(&self, request: &LoginRequest) -> Result<SignedPublicKey, LoginError> {
        match self.lookup.fetch_key(&request.email).await {
            Ok(key) => Ok(key),
            Err(LookupError::NotFound) if self.config.allow_client_key => {
                let armored = request.public_key.as_deref().ok_or(LookupError::NotFound)?;
                let (key, _) =
                    SignedPublicKey::from_string(armored).map_err(|_| LookupError::NotFound)?;
                let email_lower = request.email.to_ascii_lowercase();
                if !verify::identity_emails(&key)
                    .iter()
                    .any(|e| e.to_ascii_lowercase() == email_lower)
                {
                    return Err(LoginError::Lookup(LookupError::IdentityMismatch));
                }
                Ok(key)
            }
            Err(e) => Err(LoginError::Lookup(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeStore;
    use crate::lookup::test_http::FakeHttp;
    use crate::lookup::{KeyLookup, LookupConfig, LookupError};
    use crate::verify::test_keys::{clearsign, generate};
    use pgp::ser::Serialize;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const EMAIL: &str = "joe.doe@example.org";
    const ADVANCED_URL: &str = "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe";

    struct RecordingHook {
        calls: AtomicU32,
        seen: Mutex<Vec<(String, String)>>,
        reject_with: Option<String>,
    }

    impl RecordingHook {
        fn accepting() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
                seen: Mutex::new(Vec::new()),
                reject_with: None,
            })
        }

        fn rejecting(reason: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
                seen: Mutex::new(Vec::new()),
                reject_with: Some(reason.into()),
            })
        }
    }

    #[async_trait::async_trait]
    impl LoginHook for RecordingHook {
        async fn authorize(&self, email: &str, fingerprint: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .expect("lock")
                .push((email.into(), fingerprint.into()));
            match &self.reject_with {
                Some(reason) => Err(reason.clone()),
                None => Ok(()),
            }
        }
    }

    fn key_bytes(public: &pgp::composed::SignedPublicKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        public.to_writer(&mut bytes).expect("serialize");
        bytes
    }

    fn service(
        responses: &[(&str, u16, Vec<u8>)],
        hook: Arc<RecordingHook>,
        config: LoginConfig,
    ) -> LoginService<FakeHttp> {
        LoginService::new(
            Arc::new(ChallengeStore::new(Duration::from_secs(60))),
            KeyLookup::new(FakeHttp::new(responses), LookupConfig::default()),
            hook,
            config,
        )
    }

    fn request(
        service: &LoginService<FakeHttp>,
        secret: &pgp::composed::SignedSecretKey,
    ) -> LoginRequest {
        let challenge = service.challenges().issue(None);
        LoginRequest {
            email: EMAIL.into(),
            challenge: challenge.clone(),
            signature: clearsign(2, &challenge, secret),
            public_key: None,
        }
    }

    #[tokio::test]
    async fn a_valid_login_passes_and_reaches_the_hook() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let hook = RecordingHook::accepting();
        let s = service(
            &[(ADVANCED_URL, 200, key_bytes(&public))],
            Arc::clone(&hook),
            LoginConfig::default(),
        );
        let req = request(&s, &secret);
        let verified = s.login(&req, None).await.expect("login ok");
        assert_eq!(verified.email, EMAIL);
        assert_eq!(
            verified.fingerprint,
            crate::verify::fingerprint_hex(&public)
        );
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            hook.seen.lock().expect("lock")[0],
            (EMAIL.to_string(), verified.fingerprint.clone())
        );
    }

    #[tokio::test]
    async fn an_unissued_challenge_is_rejected_without_any_lookup() {
        let (secret, _) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(&[], RecordingHook::accepting(), LoginConfig::default());
        let req = LoginRequest {
            email: EMAIL.into(),
            challenge: "never-issued".into(),
            signature: clearsign(2, "never-issued", &secret),
            public_key: None,
        };
        let err = s.login(&req, None).await.expect_err("bad challenge");
        assert!(matches!(err, LoginError::InvalidChallenge));
        assert!(s.lookup().http().requested().is_empty(), "no key fetched");
    }

    #[tokio::test]
    async fn a_challenge_cannot_be_replayed() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(
            &[(ADVANCED_URL, 200, key_bytes(&public))],
            RecordingHook::accepting(),
            LoginConfig::default(),
        );
        let req = request(&s, &secret);
        s.login(&req, None).await.expect("first login ok");
        let err = s.login(&req, None).await.expect_err("replay rejected");
        assert!(matches!(err, LoginError::InvalidChallenge));
    }

    #[tokio::test]
    async fn a_signature_over_other_text_is_rejected() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(
            &[(ADVANCED_URL, 200, key_bytes(&public))],
            RecordingHook::accepting(),
            LoginConfig::default(),
        );
        let challenge = s.challenges().issue(None);
        let req = LoginRequest {
            email: EMAIL.into(),
            challenge,
            signature: clearsign(2, "some other text", &secret),
            public_key: None,
        };
        let err = s.login(&req, None).await.expect_err("text mismatch");
        assert!(matches!(err, LoginError::Verify(_)));
    }

    #[tokio::test]
    async fn a_revoked_key_is_rejected() {
        let (secret, mut public) = generate(7, "Joe Doe <joe.doe@example.org>");
        // Sign a real key revocation so it survives the serialize/parse round trip.
        let revocation = {
            use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
            use pgp::types::{KeyDetails as _, Password, Timestamp};
            let mut config = SignatureConfig::v4(
                SignatureType::KeyRevocation,
                secret.primary_key.algorithm(),
                pgp::crypto::hash::HashAlgorithm::Sha256,
            );
            config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                    .expect("subpacket"),
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret.primary_key.fingerprint(),
                ))
                .expect("subpacket"),
            ];
            config
                .sign_key(&secret.primary_key, &Password::empty(), &public.primary_key)
                .expect("revocation signature")
        };
        public.details.revocation_signatures.push(revocation);
        let s = service(
            &[(ADVANCED_URL, 200, key_bytes(&public))],
            RecordingHook::accepting(),
            LoginConfig::default(),
        );
        let req = request(&s, &secret);
        let err = s.login(&req, None).await.expect_err("revoked key");
        assert!(matches!(err, LoginError::Revoked));
    }

    #[tokio::test]
    async fn the_hook_can_reject_a_login() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(
            &[(ADVANCED_URL, 200, key_bytes(&public))],
            RecordingHook::rejecting("not an admin"),
            LoginConfig::default(),
        );
        let req = request(&s, &secret);
        let err = s.login(&req, None).await.expect_err("hook rejected");
        assert!(matches!(err, LoginError::Rejected(ref r) if r == "not an admin"));
    }

    #[tokio::test]
    async fn client_supplied_keys_are_ignored_by_default() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(&[], RecordingHook::accepting(), LoginConfig::default());
        let challenge = s.challenges().issue(None);
        let req = LoginRequest {
            email: EMAIL.into(),
            challenge: challenge.clone(),
            signature: clearsign(2, &challenge, &secret),
            public_key: Some(public.to_armored_string(Default::default()).expect("armor")),
        };
        let err = s.login(&req, None).await.expect_err("lookup must fail");
        assert!(matches!(err, LoginError::Lookup(LookupError::NotFound)));
    }

    #[tokio::test]
    async fn client_supplied_keys_work_when_explicitly_allowed() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let s = service(
            &[],
            RecordingHook::accepting(),
            LoginConfig {
                allow_client_key: true,
                ..LoginConfig::default()
            },
        );
        let challenge = s.challenges().issue(None);
        let req = LoginRequest {
            email: EMAIL.into(),
            challenge: challenge.clone(),
            signature: clearsign(2, &challenge, &secret),
            public_key: Some(public.to_armored_string(Default::default()).expect("armor")),
        };
        let verified = s.login(&req, None).await.expect("client key accepted");
        assert_eq!(
            verified.fingerprint,
            crate::verify::fingerprint_hex(&public)
        );
    }

    #[tokio::test]
    async fn a_client_key_without_the_email_identity_is_rejected() {
        let (secret, _) = generate(7, "Joe Doe <joe.doe@example.org>");
        let (_, other) = generate(8, "Mallory <mallory@example.org>");
        let s = service(
            &[],
            RecordingHook::accepting(),
            LoginConfig {
                allow_client_key: true,
                ..LoginConfig::default()
            },
        );
        let challenge = s.challenges().issue(None);
        let req = LoginRequest {
            email: EMAIL.into(),
            challenge: challenge.clone(),
            signature: clearsign(2, &challenge, &secret),
            public_key: Some(other.to_armored_string(Default::default()).expect("armor")),
        };
        let err = s.login(&req, None).await.expect_err("identity mismatch");
        assert!(matches!(
            err,
            LoginError::Lookup(LookupError::IdentityMismatch)
        ));
    }
}
