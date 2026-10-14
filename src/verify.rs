//! Clearsigned-challenge verification with rPGP.

use pgp::composed::{CleartextSignedMessage, SignedPublicKey};
use pgp::types::KeyDetails;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("could not parse the clearsigned message: {0}")]
    Parse(String),
    #[error("the signed text does not equal the expected challenge")]
    TextMismatch,
    #[error("signature verification failed: {0}")]
    BadSignature(String),
}

/// Verifies an armored clearsigned message: it must parse, its signed text
/// must equal `expected_text` exactly, and its signature must verify against
/// `key` (primary or a signing subkey). Returns the key's primary
/// fingerprint as uppercase hex.
pub fn verify_clearsign(
    armored: &str,
    expected_text: &str,
    key: &SignedPublicKey,
) -> Result<String, VerifyError> {
    let (message, _headers) = CleartextSignedMessage::from_string(armored)
        .map_err(|e| VerifyError::Parse(e.to_string()))?;
    let signed = message.signed_text();
    if signed.trim_end() != expected_text {
        return Err(VerifyError::TextMismatch);
    }
    message
        .verify(key)
        .map(|_| fingerprint_hex(key))
        .or_else(|primary_err| {
            for subkey in &key.public_subkeys {
                if message.verify(subkey).is_ok() {
                    return Ok(fingerprint_hex(key));
                }
            }
            Err(VerifyError::BadSignature(primary_err.to_string()))
        })
}

/// The key's primary fingerprint as uppercase hex.
pub fn fingerprint_hex(key: &SignedPublicKey) -> String {
    let fp = key.primary_key.fingerprint();
    fp.as_bytes().iter().map(|b| format!("{b:02X}")).collect()
}

/// The e-mail addresses of the key's user ids.
pub fn identity_emails(key: &SignedPublicKey) -> Vec<String> {
    key.details
        .users
        .iter()
        .filter_map(|user| {
            let id = String::from_utf8_lossy(user.id.id());
            let email = id.rsplit_once('<')?.1.strip_suffix('>')?.trim().to_string();
            (!email.is_empty()).then_some(email)
        })
        .collect()
}

/// Whether the key carries a revocation signature.
pub fn is_revoked(key: &SignedPublicKey) -> bool {
    !key.details.revocation_signatures.is_empty()
}

#[cfg(test)]
pub(crate) mod test_keys {
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey};
    use pgp::types::Password;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Deterministic test key with the given user id, e.g.
    /// `"Admin <admin@example.org>"`.
    pub fn generate(seed: u64, user_id: &str) -> (SignedSecretKey, SignedPublicKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(user_id.to_string())
            .build()
            .expect("valid key params");
        let secret = params.generate(&mut rng).expect("key generation");
        let public = SignedPublicKey::from(secret.clone());
        (secret, public)
    }

    /// Clearsigns `text` with the key.
    pub fn clearsign(seed: u64, text: &str, secret: &SignedSecretKey) -> String {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let msg = pgp::composed::CleartextSignedMessage::sign(
            &mut rng,
            text,
            &secret.primary_key,
            &Password::empty(),
        )
        .expect("clearsign");
        msg.to_armored_string(Default::default()).expect("armor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::test_keys::{clearsign, generate};

    const CHALLENGE: &str = "dGVzdC1jaGFsbGVuZ2UtcGhyYXNl";

    #[test]
    fn a_valid_clearsign_over_the_exact_text_verifies() {
        let (secret, public) = generate(1, "Admin <admin@example.org>");
        let armored = clearsign(2, CHALLENGE, &secret);
        let fingerprint =
            verify_clearsign(&armored, CHALLENGE, &public).expect("signature verifies");
        assert_eq!(fingerprint, crate::verify::fingerprint_hex(&public));
        assert_eq!(fingerprint.len(), 40, "v4 fingerprint as hex");
        assert_eq!(fingerprint, fingerprint.to_uppercase());
    }

    #[test]
    fn signed_text_must_equal_the_challenge() {
        let (secret, public) = generate(1, "Admin <admin@example.org>");
        let armored = clearsign(2, "something-else-entirely", &secret);
        let err = verify_clearsign(&armored, CHALLENGE, &public).expect_err("text mismatch");
        assert!(matches!(err, VerifyError::TextMismatch));
    }

    #[test]
    fn a_signature_from_another_key_fails() {
        let (secret, _) = generate(1, "Admin <admin@example.org>");
        let (_, other_public) = generate(99, "Other <other@example.org>");
        let armored = clearsign(2, CHALLENGE, &secret);
        let err = verify_clearsign(&armored, CHALLENGE, &other_public).expect_err("wrong key");
        assert!(matches!(err, VerifyError::BadSignature(_)));
    }

    #[test]
    fn garbage_input_is_a_parse_error() {
        let (_, public) = generate(1, "Admin <admin@example.org>");
        let err = verify_clearsign("not armored at all", CHALLENGE, &public)
            .expect_err("unparseable input");
        assert!(matches!(err, VerifyError::Parse(_)));
    }

    #[test]
    fn email_identities_are_extracted() {
        let (_, public) = generate(1, "Admin User <admin@example.org>");
        assert_eq!(identity_emails(&public), vec!["admin@example.org"]);
    }
}
