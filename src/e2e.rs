//! End-to-end payload encryption: the server keypair, decryption of
//! `x-gpg-encrypted` request bodies (with replay protection and the
//! `x-gpg-tunnel` envelope) and encryption of responses to verified
//! recipients.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use serde::Deserialize;

/// Replay window for `_gpg_timestamp`, matching the reference middleware.
const REPLAY_WINDOW_MS: u64 = 60_000;

#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    #[error("key generation failed: {0}")]
    Keygen(String),
    #[error("could not decrypt the request body: {0}")]
    Decrypt(String),
    #[error("replay protection: {0}")]
    Replay(String),
}

/// The server's OpenPGP keypair: signing primary plus one encryption subkey.
pub struct ServerKey {
    secret: SignedSecretKey,
    public_armored: String,
    email: String,
}

impl ServerKey {
    /// Generates a fresh server key for `email`.
    pub fn generate<R>(mut rng: R, email: &str) -> Result<Self, E2eError>
    where
        R: rand08::Rng + rand08::CryptoRng,
    {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(format!("Aegis Server <{email}>"))
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .map_err(|e| E2eError::Keygen(e.to_string()))?,
            )
            .build()
            .map_err(|e| E2eError::Keygen(e.to_string()))?;
        let secret = params
            .generate(&mut rng)
            .map_err(|e| E2eError::Keygen(e.to_string()))?;
        Self::from_secret(secret, email.to_string())
    }

    /// Restores a server key from its armored secret key.
    pub fn from_armored(armored_secret: &str) -> Result<Self, E2eError> {
        let (secret, _) = SignedSecretKey::from_string(armored_secret)
            .map_err(|e| E2eError::Keygen(e.to_string()))?;
        let email = crate::verify::identity_emails(&SignedPublicKey::from(secret.clone()))
            .into_iter()
            .next()
            .unwrap_or_default();
        Self::from_secret(secret, email)
    }

    fn from_secret(secret: SignedSecretKey, email: String) -> Result<Self, E2eError> {
        let public_armored = SignedPublicKey::from(secret.clone())
            .to_armored_string(Default::default())
            .map_err(|e| E2eError::Keygen(e.to_string()))?;
        Ok(Self {
            secret,
            public_armored,
            email,
        })
    }

    /// The armored public key, served at `/api/server-pubkey`.
    pub fn public_armored(&self) -> &str {
        &self.public_armored
    }

    /// The armored secret key, for persisting across restarts. Store it like
    /// any other secret.
    pub fn secret_armored(&self) -> Result<String, E2eError> {
        self.secret
            .to_armored_string(Default::default())
            .map_err(|e| E2eError::Keygen(e.to_string()))
    }

    /// The identity advertised in `x-gpg-server-id`.
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// The `x-gpg-tunnel` envelope: a whole HTTP request wrapped in the
/// encrypted body.
#[derive(Debug, Clone, Deserialize)]
pub struct TunnelEnvelope {
    #[serde(rename = "tunnel_method")]
    pub method: String,
    #[serde(rename = "tunnel_url")]
    pub url: String,
    #[serde(rename = "tunnel_headers", default)]
    pub headers: HashMap<String, String>,
    #[serde(rename = "tunnel_body", default)]
    pub body: Option<serde_json::Value>,
}

/// Parses a decrypted tunnel envelope.
pub fn parse_tunnel(plain: &[u8]) -> Result<TunnelEnvelope, E2eError> {
    serde_json::from_slice(plain).map_err(|e| E2eError::Decrypt(format!("tunnel envelope: {e}")))
}

/// End-to-end payload encryption state: the server key, the verified
/// recipient keys (registered after successful logins) and the replay caches.
pub struct E2e {
    server: ServerKey,
    recipients: RwLock<HashMap<String, SignedPublicKey>>,
    seen_nonces: Mutex<HashMap<String, u64>>,
    nonce_ttl: Duration,
}

impl E2e {
    pub fn new(server: ServerKey, nonce_ttl: Duration) -> Self {
        Self {
            server,
            recipients: RwLock::new(HashMap::new()),
            seen_nonces: Mutex::new(HashMap::new()),
            nonce_ttl,
        }
    }

    pub fn server(&self) -> &ServerKey {
        &self.server
    }

    /// Registers a verified login's key so responses can be encrypted to it.
    /// Never register unverified, client-supplied keys.
    pub fn register_recipient(&self, email: &str, key: SignedPublicKey) {
        self.recipients
            .write()
            .expect("recipients lock")
            .insert(email.to_ascii_lowercase(), key);
    }

    /// Decrypts an `x-gpg-encrypted` request body with the server key and
    /// enforces the `_gpg_timestamp` / `_gpg_nonce` replay protection when
    /// present (the markers are stripped from the returned JSON).
    pub fn decrypt_request(&self, body: &[u8], now_ms: u64) -> Result<Vec<u8>, E2eError> {
        let text = String::from_utf8_lossy(body);
        let (message, _) =
            Message::from_string(&text).map_err(|e| E2eError::Decrypt(e.to_string()))?;
        let mut decrypted = message
            .decrypt(&Password::empty(), &self.server.secret)
            .map_err(|e| E2eError::Decrypt(e.to_string()))?;
        let plain = decrypted
            .as_data_vec()
            .map_err(|e| E2eError::Decrypt(e.to_string()))?;

        let Ok(mut parsed) = serde_json::from_slice::<serde_json::Value>(&plain) else {
            return Ok(plain);
        };
        let Some(object) = parsed.as_object_mut() else {
            return Ok(plain);
        };
        let Some(timestamp) = object.get("_gpg_timestamp").and_then(|v| v.as_f64()) else {
            return Ok(plain);
        };
        let Some(nonce) = object
            .get("_gpg_nonce")
            .and_then(|v| v.as_str())
            .map(String::from)
        else {
            return Ok(plain);
        };
        let age = (now_ms as f64) - timestamp;
        if age.abs() > REPLAY_WINDOW_MS as f64 {
            return Err(E2eError::Replay(
                "payload expired or timestamp invalid".into(),
            ));
        }
        {
            let ttl_ms = self.nonce_ttl.as_millis() as u64;
            let mut seen = self.seen_nonces.lock().expect("nonce lock");
            seen.retain(|_, stored| now_ms.saturating_sub(*stored) <= ttl_ms);
            if seen.insert(nonce, now_ms).is_some() {
                return Err(E2eError::Replay("duplicate payload".into()));
            }
        }
        object.remove("_gpg_timestamp");
        object.remove("_gpg_nonce");
        serde_json::to_vec(&parsed).map_err(|e| E2eError::Decrypt(e.to_string()))
    }

    /// Encrypts a response body to a registered recipient; `None` when the
    /// recipient is unknown (the caller should then send plaintext and must
    /// not set `x-gpg-encrypted`).
    pub fn encrypt_response(&self, email: &str, body: &[u8]) -> Option<String> {
        let recipients = self.recipients.read().expect("recipients lock");
        let key = recipients.get(&email.to_ascii_lowercase())?;
        let mut rng = rand08::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", body.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        let result = if let Some(subkey) = key.public_subkeys.first() {
            builder.encrypt_to_key(&mut rng, subkey)
        } else {
            builder.encrypt_to_key(&mut rng, key)
        };
        if result.is_err() {
            return None;
        }
        builder.to_armored_string(&mut rng, Default::default()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::test_keys::generate;
    use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey};
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::types::Password;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SERVER_EMAIL: &str = "server@example.org";

    fn server() -> ServerKey {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        ServerKey::generate(&mut rng, SERVER_EMAIL).expect("server key")
    }

    /// Encrypts `plain` to `key` the way the extension does.
    fn client_encrypt(plain: &[u8], armored_key: &str) -> Vec<u8> {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (key, _) = SignedPublicKey::from_string(armored_key).expect("parse server key");
        let enc_key = key
            .public_subkeys
            .first()
            .expect("server key has an encryption subkey");
        let mut builder = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.encrypt_to_key(&mut rng, enc_key).expect("encrypt");
        builder
            .to_armored_string(&mut rng, Default::default())
            .expect("armor")
            .into_bytes()
    }

    fn e2e() -> E2e {
        E2e::new(server(), std::time::Duration::from_secs(60))
    }

    #[test]
    fn the_generated_server_key_has_a_signing_primary_and_encryption_subkey() {
        let s = server();
        let (public, _) = SignedPublicKey::from_string(s.public_armored()).expect("parses");
        assert_eq!(crate::verify::identity_emails(&public), vec![SERVER_EMAIL]);
        assert_eq!(public.public_subkeys.len(), 1, "one encryption subkey");
    }

    #[test]
    fn the_server_key_round_trips_through_armor() {
        let s = server();
        let restored =
            ServerKey::from_armored(&s.secret_armored().expect("serialize")).expect("parses back");
        assert_eq!(restored.public_armored(), s.public_armored());
    }

    #[tokio::test]
    async fn an_encrypted_request_body_is_decrypted() {
        let e = e2e();
        let body = client_encrypt(br#"{"hello":"world"}"#, e.server().public_armored());
        let plain = e.decrypt_request(&body, now_ms()).expect("decrypts");
        assert_eq!(plain, br#"{"hello":"world"}"#);
    }

    #[tokio::test]
    async fn garbage_with_the_encrypted_header_is_an_error() {
        let e = e2e();
        let err = e
            .decrypt_request(b"definitely not pgp", now_ms())
            .expect_err("must not pass through");
        assert!(matches!(err, E2eError::Decrypt(_)));
    }

    #[tokio::test]
    async fn stale_timestamps_are_rejected() {
        let e = e2e();
        let now = now_ms();
        let payload = format!(
            r#"{{"a":1,"_gpg_timestamp":{},"_gpg_nonce":"n-1"}}"#,
            now - 61_000
        );
        let body = client_encrypt(payload.as_bytes(), e.server().public_armored());
        let err = e.decrypt_request(&body, now).expect_err("stale");
        assert!(matches!(err, E2eError::Replay(_)));
    }

    #[tokio::test]
    async fn duplicate_nonces_are_rejected_and_fields_are_stripped() {
        let e = e2e();
        let now = now_ms();
        let payload = format!(r#"{{"a":1,"_gpg_timestamp":{now},"_gpg_nonce":"n-dup"}}"#);
        let body = client_encrypt(payload.as_bytes(), e.server().public_armored());
        let plain = e.decrypt_request(&body, now).expect("first time passes");
        let value: serde_json::Value = serde_json::from_slice(&plain).expect("json");
        assert_eq!(value["a"], 1);
        assert!(value.get("_gpg_timestamp").is_none(), "marker stripped");
        assert!(value.get("_gpg_nonce").is_none(), "marker stripped");

        let body2 = client_encrypt(payload.as_bytes(), e.server().public_armored());
        let err = e.decrypt_request(&body2, now).expect_err("replay");
        assert!(matches!(err, E2eError::Replay(_)));
    }

    #[tokio::test]
    async fn tunnel_envelopes_are_parsed() {
        let envelope = r#"{
            "tunnel_method": "DELETE",
            "tunnel_url": "/api/sites/5",
            "tunnel_headers": {"x-custom": "1"},
            "tunnel_body": {"reason": "spam"}
        }"#;
        let tunnel = parse_tunnel(envelope.as_bytes()).expect("envelope parses");
        assert_eq!(tunnel.method, "DELETE");
        assert_eq!(tunnel.url, "/api/sites/5");
        assert_eq!(
            tunnel.headers.get("x-custom").map(String::as_str),
            Some("1")
        );
        assert_eq!(tunnel.body.expect("body")["reason"], "spam");
    }

    #[tokio::test]
    async fn responses_are_encrypted_only_to_registered_recipients() {
        let e = e2e();
        let (user_secret, user_public) = generate(5, "Joe Doe <joe.doe@example.org>");
        assert!(
            e.encrypt_response("joe.doe@example.org", b"secret data")
                .is_none(),
            "unknown recipient gets nothing"
        );
        e.register_recipient("joe.doe@example.org", user_public);
        let armored = e
            .encrypt_response("joe.doe@example.org", b"secret data")
            .expect("encrypted");
        let (msg, _) = Message::from_string(&armored).expect("parse message");
        let mut decrypted = msg
            .decrypt(&Password::empty(), &user_secret)
            .expect("user can decrypt");
        assert_eq!(decrypted.as_data_vec().expect("data"), b"secret data");
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_millis() as u64
    }
}
