//! Public key lookup: WKD (advanced, then direct) with HTTPS keyserver
//! fallback. The HTTP transport is a trait so tests stay offline.

use pgp::composed::{Deserializable, SignedPublicKey};
use sha1::{Digest, Sha1};

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("invalid email address")]
    InvalidEmail,
    #[error("keyserver must use https: {0}")]
    InsecureKeyserver(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("response exceeds the size limit")]
    TooLarge,
    #[error("no public key found for the address")]
    NotFound,
    #[error("the key does not carry an identity for the address")]
    IdentityMismatch,
}

/// HTTPS GET boundary; implement it with your HTTP client of choice.
/// Implementations should enforce a request timeout.
#[async_trait::async_trait]
pub trait HttpFetch: Send + Sync {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), LookupError>;
}

#[derive(Debug, Clone)]
pub struct LookupConfig {
    /// Keyserver base URLs tried after WKD, in order. HTTPS only.
    pub keyservers: Vec<String>,
    /// Response size cap in bytes.
    pub max_response_bytes: usize,
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self {
            keyservers: vec![
                "https://keys.openpgp.org".into(),
                "https://keyserver.ubuntu.com".into(),
            ],
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// Fetches public keys for an e-mail address: WKD advanced method, WKD
/// direct method, then each configured keyserver.
pub struct KeyLookup<H> {
    http: H,
    config: LookupConfig,
}

impl<H: HttpFetch> KeyLookup<H> {
    /// Panics if the configuration names a non-HTTPS keyserver; use
    /// [`KeyLookup::checked`] to handle that as an error.
    pub fn new(http: H, config: LookupConfig) -> Self {
        match Self::checked(http, config) {
            Ok(lookup) => lookup,
            Err(e) => panic!("invalid lookup config: {e}"),
        }
    }

    pub fn checked(http: H, config: LookupConfig) -> Result<Self, LookupError> {
        if let Some(bad) = config
            .keyservers
            .iter()
            .find(|k| !k.starts_with("https://"))
        {
            return Err(LookupError::InsecureKeyserver(bad.clone()));
        }
        Ok(Self { http, config })
    }

    pub fn http(&self) -> &H {
        &self.http
    }

    /// Fetches the public key for `email`, trying WKD (advanced, direct) and
    /// then the configured keyservers. The returned key always carries an
    /// identity for `email`.
    pub async fn fetch_key(&self, email: &str) -> Result<SignedPublicKey, LookupError> {
        let (local, domain) = email.split_once('@').ok_or(LookupError::InvalidEmail)?;
        if local.is_empty() || domain.is_empty() || email.contains(|c: char| c.is_whitespace()) {
            return Err(LookupError::InvalidEmail);
        }
        let local_lower = local.to_ascii_lowercase();
        let domain = domain.to_ascii_lowercase();
        let hash = zbase32(&Sha1::digest(local_lower.as_bytes()));
        let encoded_local = urlencode(local);

        let advanced = format!(
            "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={encoded_local}"
        );
        let direct = format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={encoded_local}");

        for url in [advanced, direct] {
            if let Some(key) = self.try_fetch(&url, email, false).await? {
                return Ok(key);
            }
        }
        for base in &self.config.keyservers {
            let url = format!(
                "{}/pks/lookup?op=get&options=mr&search={}",
                base.trim_end_matches('/'),
                urlencode(email)
            );
            if let Some(key) = self.try_fetch(&url, email, true).await? {
                return Ok(key);
            }
        }
        Err(LookupError::NotFound)
    }

    /// One fetch attempt. Transport errors and non-200 responses mean "try
    /// the next source" (`None`); a parsed key without the identity is a
    /// hard error, since a matching source returned the wrong key.
    async fn try_fetch(
        &self,
        url: &str,
        email: &str,
        armored: bool,
    ) -> Result<Option<SignedPublicKey>, LookupError> {
        let (status, body) = match self.http.get(url).await {
            Ok(response) => response,
            Err(LookupError::TooLarge) => return Err(LookupError::TooLarge),
            Err(_) => return Ok(None),
        };
        if status != 200 {
            return Ok(None);
        }
        if body.len() > self.config.max_response_bytes {
            return Err(LookupError::TooLarge);
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        let keys: Vec<SignedPublicKey> = if armored {
            let Ok((iter, _)) = SignedPublicKey::from_string_many(&text) else {
                return Ok(None);
            };
            iter.filter_map(Result::ok).collect()
        } else {
            let Ok(iter) = SignedPublicKey::from_bytes_many(&body[..]) else {
                return Ok(None);
            };
            iter.filter_map(Result::ok).collect()
        };
        if keys.is_empty() {
            return Ok(None);
        }
        let email_lower = email.to_ascii_lowercase();
        keys.into_iter()
            .find(|k| {
                crate::verify::identity_emails(k)
                    .iter()
                    .any(|e| e.to_ascii_lowercase() == email_lower)
            })
            .map(Some)
            .ok_or(LookupError::IdentityMismatch)
    }
}

/// z-base-32 (RFC: the WKD draft's encoding of the SHA-1 local-part hash).
pub fn zbase32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::test_keys::generate;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeHttp {
        responses: HashMap<String, (u16, Vec<u8>)>,
        requests: Mutex<Vec<String>>,
    }

    impl FakeHttp {
        fn new(responses: &[(&str, u16, Vec<u8>)]) -> Self {
            Self {
                responses: responses
                    .iter()
                    .map(|(u, s, b)| (u.to_string(), (*s, b.clone())))
                    .collect(),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requested(&self) -> Vec<String> {
            self.requests.lock().expect("lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl HttpFetch for FakeHttp {
        async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), LookupError> {
            self.requests.lock().expect("lock").push(url.to_string());
            match self.responses.get(url) {
                Some((status, body)) => Ok((*status, body.clone())),
                None => Err(LookupError::Transport("connection refused".into())),
            }
        }
    }

    const EMAIL: &str = "joe.doe@example.org";
    // Known vector from the WKD draft: zbase32(sha1("joe.doe")).
    const WKD_HASH: &str = "iy9q119eutrkn8s1mk4r39qejnbu3n5q";

    fn advanced_url() -> String {
        format!(
            "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/{WKD_HASH}?l=joe.doe"
        )
    }

    fn direct_url() -> String {
        format!("https://example.org/.well-known/openpgpkey/hu/{WKD_HASH}?l=joe.doe")
    }

    fn keyserver_url(base: &str) -> String {
        format!("{base}/pks/lookup?op=get&options=mr&search=joe.doe%40example.org")
    }

    fn key_bytes() -> Vec<u8> {
        use pgp::ser::Serialize;
        let (_, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let mut bytes = Vec::new();
        public.to_writer(&mut bytes).expect("serialize");
        bytes
    }

    fn key_armored() -> Vec<u8> {
        let (_, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        public
            .to_armored_string(Default::default())
            .expect("armor")
            .into_bytes()
    }

    fn lookup(http: FakeHttp) -> KeyLookup<FakeHttp> {
        KeyLookup::new(http, LookupConfig::default())
    }

    #[test]
    fn zbase32_matches_the_wkd_draft_vector() {
        use sha1::{Digest, Sha1};
        let digest = Sha1::digest(b"joe.doe");
        assert_eq!(zbase32(&digest), WKD_HASH);
    }

    #[tokio::test]
    async fn advanced_wkd_is_tried_first_and_wins() {
        let http = FakeHttp::new(&[(advanced_url().as_str(), 200, key_bytes())]);
        let l = lookup(http);
        let key = l.fetch_key(EMAIL).await.expect("key found");
        assert_eq!(crate::verify::identity_emails(&key), vec![EMAIL]);
        assert_eq!(l.http().requested(), vec![advanced_url()]);
    }

    #[tokio::test]
    async fn direct_wkd_is_the_second_attempt() {
        let http = FakeHttp::new(&[(direct_url().as_str(), 200, key_bytes())]);
        let l = lookup(http);
        l.fetch_key(EMAIL).await.expect("key found");
        assert_eq!(l.http().requested(), vec![advanced_url(), direct_url()]);
    }

    #[tokio::test]
    async fn keyservers_are_the_fallback_in_order() {
        let second = keyserver_url("https://keyserver.ubuntu.com");
        let http = FakeHttp::new(&[(second.as_str(), 200, key_armored())]);
        let l = lookup(http);
        l.fetch_key(EMAIL).await.expect("key found");
        assert_eq!(
            l.http().requested(),
            vec![
                advanced_url(),
                direct_url(),
                keyserver_url("https://keys.openpgp.org"),
                second
            ]
        );
    }

    #[tokio::test]
    async fn not_found_anywhere_is_an_error() {
        let l = lookup(FakeHttp::new(&[]));
        let err = l.fetch_key(EMAIL).await.expect_err("nothing found");
        assert!(matches!(err, LookupError::NotFound));
    }

    #[tokio::test]
    async fn a_key_without_the_email_identity_is_rejected() {
        let (_, other) = generate(8, "Mallory <mallory@example.org>");
        let other_bytes = {
            use pgp::ser::Serialize;
            let mut bytes = Vec::new();
            other.to_writer(&mut bytes).expect("serialize");
            bytes
        };
        let http = FakeHttp::new(&[(advanced_url().as_str(), 200, other_bytes)]);
        let err = lookup(http)
            .fetch_key(EMAIL)
            .await
            .expect_err("wrong identity");
        assert!(matches!(err, LookupError::IdentityMismatch));
    }

    #[tokio::test]
    async fn oversized_responses_are_rejected() {
        let http = FakeHttp::new(&[(advanced_url().as_str(), 200, vec![0u8; 1024 * 1024 + 1])]);
        let err = lookup(http).fetch_key(EMAIL).await.expect_err("too large");
        assert!(matches!(err, LookupError::TooLarge));
    }

    #[test]
    fn plain_http_keyservers_are_rejected_at_construction() {
        let config = LookupConfig {
            keyservers: vec!["http://keyserver.ubuntu.com".into()],
            ..LookupConfig::default()
        };
        assert!(matches!(
            KeyLookup::checked(FakeHttp::new(&[]), config),
            Err(LookupError::InsecureKeyserver(_))
        ));
    }

    #[tokio::test]
    async fn invalid_email_is_rejected() {
        let l = lookup(FakeHttp::new(&[]));
        let err = l.fetch_key("not-an-email").await.expect_err("no at sign");
        assert!(matches!(err, LookupError::InvalidEmail));
        assert!(l.http().requested().is_empty(), "nothing fetched");
    }
}
