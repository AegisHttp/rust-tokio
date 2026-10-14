//! axum adapter: the challenge / login / server-pubkey routes and the E2E
//! encryption middleware.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::body::Body;
use ::axum::extract::State;
use ::axum::response::{IntoResponse, Response};
use ::axum::routing::{get, post};
use ::axum::{Json, Router};
use http::{header, HeaderName, HeaderValue, Request, StatusCode};
use tower::{Layer, Service};

use crate::e2e::{parse_tunnel, E2e, E2eError};
use crate::login::{LoginError, LoginRequest, LoginService, VerifiedLogin};
use crate::lookup::HttpFetch;

/// Maximum body size the E2E middleware will buffer.
const MAX_E2E_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Issues the application session (e.g. a `Set-Cookie` header) after a
/// verified login. Session storage and validation stay in the application.
#[async_trait::async_trait]
pub trait SessionIssuer: Send + Sync {
    async fn issue(&self, login: &VerifiedLogin) -> Vec<(HeaderName, HeaderValue)>;
}

struct Inner<H> {
    login: LoginService<H>,
    e2e: Option<Arc<E2e>>,
    session: Arc<dyn SessionIssuer>,
}

/// Shared state behind the aegis routes and the E2E layer.
pub struct AegisState<H> {
    inner: Arc<Inner<H>>,
}

impl<H> Clone for AegisState<H> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<H: HttpFetch> AegisState<H> {
    pub fn new(
        login: LoginService<H>,
        e2e: Option<Arc<E2e>>,
        session: Arc<dyn SessionIssuer>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                login,
                e2e,
                session,
            }),
        }
    }

    pub fn e2e(&self) -> Option<&Arc<E2e>> {
        self.inner.e2e.as_ref()
    }

    fn support_headers(&self, response: &mut Response) {
        let headers = response.headers_mut();
        headers.insert("x-gpg-support", HeaderValue::from_static("true"));
        if let Some(e2e) = &self.inner.e2e {
            if let Ok(value) = HeaderValue::from_str(e2e.server().email()) {
                headers.insert("x-gpg-server-id", value);
            }
        }
    }
}

/// The protocol routes: `GET /api/challenge`, `POST /api/login` and
/// `GET /api/server-pubkey`.
pub fn aegis_router<H: HttpFetch + 'static>(state: AegisState<H>) -> Router {
    Router::new()
        .route("/api/challenge", get(challenge::<H>))
        .route("/api/login", post(login::<H>))
        .route("/api/server-pubkey", get(server_pubkey::<H>))
        .with_state(state)
}

async fn challenge<H: HttpFetch>(State(state): State<AegisState<H>>) -> Response {
    let challenge = state.inner.login.challenges().issue(None);
    let mut response = Json(serde_json::json!({ "challenge": challenge })).into_response();
    state.support_headers(&mut response);
    response
}

async fn login<H: HttpFetch>(
    State(state): State<AegisState<H>>,
    Json(request): Json<LoginRequest>,
) -> Response {
    match state.inner.login.login(&request, None).await {
        Ok(verified) => {
            if let Some(e2e) = &state.inner.e2e {
                e2e.register_recipient(&verified.email, verified.public_key.clone());
            }
            let session_headers = state.inner.session.issue(&verified).await;
            let mut response = Json(serde_json::json!({
                "status": "success",
                "message": "Successfully authenticated via GPG Aegis Http!",
                "email": verified.email,
            }))
            .into_response();
            for (name, value) in session_headers {
                response.headers_mut().append(name, value);
            }
            state.support_headers(&mut response);
            response
        }
        Err(err) => {
            let status = match &err {
                LoginError::InvalidChallenge | LoginError::Lookup(_) => StatusCode::BAD_REQUEST,
                LoginError::Verify(_) | LoginError::Revoked | LoginError::Rejected(_) => {
                    StatusCode::UNAUTHORIZED
                }
            };
            let mut response = (
                status,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
                .into_response();
            state.support_headers(&mut response);
            response
        }
    }
}

async fn server_pubkey<H: HttpFetch>(State(state): State<AegisState<H>>) -> Response {
    match &state.inner.e2e {
        Some(e2e) => {
            let mut response = (
                [(header::CONTENT_TYPE, "text/plain")],
                e2e.server().public_armored().to_string(),
            )
                .into_response();
            state.support_headers(&mut response);
            response
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Builds the E2E encryption layer. Wrap the **whole** router with it
/// (`e2e_layer(state).layer(router)`), not via `Router::layer`, so that
/// tunnelled requests re-enter routing after being rewritten.
pub fn e2e_layer<H>(state: AegisState<H>) -> E2eLayer {
    E2eLayer {
        e2e: state.inner.e2e.clone(),
    }
}

#[derive(Clone)]
pub struct E2eLayer {
    e2e: Option<Arc<E2e>>,
}

impl<S> Layer<S> for E2eLayer {
    type Service = E2eService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        E2eService {
            inner,
            e2e: self.e2e.clone(),
        }
    }
}

/// Decrypts `x-gpg-encrypted` request bodies (including the `x-gpg-tunnel`
/// envelope) before the inner service and encrypts responses to the
/// verified `x-gpg-id` recipient after it.
#[derive(Clone)]
pub struct E2eService<S> {
    inner: S,
    e2e: Option<Arc<E2e>>,
}

impl<S> Service<Request<Body>> for E2eService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let e2e = self.e2e.clone();
        Box::pin(async move {
            let Some(e2e) = e2e else {
                return inner.call(request).await;
            };

            let (mut parts, body) = request.into_parts();
            let body = if parts.headers.contains_key("x-gpg-encrypted") {
                let Ok(bytes) = ::axum::body::to_bytes(body, MAX_E2E_BODY_BYTES).await else {
                    return Ok(error_response(StatusCode::BAD_REQUEST, "unreadable body"));
                };
                match e2e.decrypt_request(&bytes, unix_now_ms()) {
                    Ok(plain) => {
                        if header_is_true(&parts.headers, "x-gpg-tunnel") {
                            match parse_tunnel(&plain) {
                                Ok(tunnel) => {
                                    let Ok(method) = tunnel.method.parse() else {
                                        return Ok(error_response(
                                            StatusCode::BAD_REQUEST,
                                            "invalid tunnel method",
                                        ));
                                    };
                                    let Ok(uri) = tunnel.url.parse() else {
                                        return Ok(error_response(
                                            StatusCode::BAD_REQUEST,
                                            "invalid tunnel url",
                                        ));
                                    };
                                    parts.method = method;
                                    parts.uri = uri;
                                    for (name, value) in &tunnel.headers {
                                        if let (Ok(name), Ok(value)) = (
                                            HeaderName::from_bytes(name.as_bytes()),
                                            HeaderValue::from_str(value),
                                        ) {
                                            parts.headers.insert(name, value);
                                        }
                                    }
                                    match &tunnel.body {
                                        Some(body) => Body::from(body.to_string()),
                                        None => Body::empty(),
                                    }
                                }
                                Err(_) => {
                                    return Ok(error_response(
                                        StatusCode::BAD_REQUEST,
                                        "invalid tunnel envelope",
                                    ));
                                }
                            }
                        } else {
                            Body::from(plain)
                        }
                    }
                    Err(E2eError::Replay(reason)) => {
                        return Ok(error_response(StatusCode::FORBIDDEN, &reason));
                    }
                    Err(err) => {
                        return Ok(error_response(StatusCode::BAD_REQUEST, &err.to_string()));
                    }
                }
            } else {
                body
            };
            parts.headers.remove(header::CONTENT_LENGTH);
            let recipient = parts
                .headers
                .get("x-gpg-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let request = Request::from_parts(parts, body);

            let response = inner.call(request).await?;

            let Some(recipient) = recipient else {
                return Ok(response);
            };
            let (mut parts, body) = response.into_parts();
            let Ok(bytes) = ::axum::body::to_bytes(body, MAX_E2E_BODY_BYTES).await else {
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unreadable response body",
                ));
            };
            match e2e.encrypt_response(&recipient, &bytes) {
                Some(armored) => {
                    parts.headers.remove(header::CONTENT_LENGTH);
                    if let Ok(value) = HeaderValue::from_str(&recipient) {
                        parts.headers.insert("x-gpg-encrypted", value);
                    }
                    parts
                        .headers
                        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                    Ok(Response::from_parts(parts, Body::from(armored)))
                }
                // Unknown recipient: never pretend to encrypt.
                None => Ok(Response::from_parts(parts, Body::from(bytes))),
            }
        })
    }
}

fn header_is_true(headers: &http::HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeStore;
    use crate::e2e::{E2e, ServerKey};
    use crate::login::{LoginConfig, LoginHook, LoginService, VerifiedLogin};
    use crate::lookup::test_http::FakeHttp;
    use crate::lookup::{KeyLookup, LookupConfig};
    use crate::verify::test_keys::{clearsign, generate};
    use ::axum::body::Body;
    use ::axum::Router;
    use http::{header, Request, StatusCode};
    use http_body_util::BodyExt;
    use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey};
    use pgp::ser::Serialize as _;
    use pgp::types::Password;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const EMAIL: &str = "joe.doe@example.org";
    const ADVANCED_URL: &str = "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe";

    struct AllowAll;

    #[async_trait::async_trait]
    impl LoginHook for AllowAll {
        async fn authorize(&self, _email: &str, _fingerprint: &str) -> Result<(), String> {
            Ok(())
        }
    }

    struct CookieIssuer;

    #[async_trait::async_trait]
    impl SessionIssuer for CookieIssuer {
        async fn issue(
            &self,
            login: &VerifiedLogin,
        ) -> Vec<(header::HeaderName, header::HeaderValue)> {
            vec![(
                header::SET_COOKIE,
                header::HeaderValue::from_str(&format!("session=issued-for-{}", login.email))
                    .expect("header value"),
            )]
        }
    }

    fn key_bytes(public: &SignedPublicKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        public.to_writer(&mut bytes).expect("serialize");
        bytes
    }

    fn state(responses: &[(&str, u16, Vec<u8>)]) -> AegisState<FakeHttp> {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        AegisState::new(
            LoginService::new(
                Arc::new(ChallengeStore::new(Duration::from_secs(60))),
                KeyLookup::new(FakeHttp::new(responses), LookupConfig::default()),
                Arc::new(AllowAll),
                LoginConfig::default(),
            ),
            Some(Arc::new(E2e::new(
                ServerKey::generate(&mut rng, "server@example.org").expect("server key"),
                Duration::from_secs(60),
            ))),
            Arc::new(CookieIssuer),
        )
    }

    /// The E2E layer wraps the whole router so tunnel rewrites re-enter
    /// routing.
    fn app(state: AegisState<FakeHttp>) -> E2eService<Router> {
        use tower::Layer as _;
        let router = aegis_router(state.clone()).merge(
            Router::new()
                .route(
                    "/api/echo",
                    ::axum::routing::post(|body: String| async move { format!("echo:{body}") }),
                )
                .route(
                    "/api/tunneled",
                    ::axum::routing::delete(|| async { "tunnel-reached" }),
                ),
        );
        e2e_layer(state).layer(router)
    }

    async fn get_challenge(app: &E2eService<Router>) -> (String, http::HeaderMap) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        (
            value["challenge"].as_str().expect("challenge").to_string(),
            headers,
        )
    }

    #[tokio::test]
    async fn the_challenge_route_returns_a_challenge_and_support_headers() {
        let app = app(state(&[]));
        let (challenge, headers) = get_challenge(&app).await;
        assert!(challenge.len() >= 32);
        assert_eq!(
            headers.get("x-gpg-support").map(|v| v.to_str().ok()),
            Some(Some("true"))
        );
        assert_eq!(
            headers.get("x-gpg-server-id").and_then(|v| v.to_str().ok()),
            Some("server@example.org")
        );
    }

    #[tokio::test]
    async fn a_valid_login_issues_the_session_headers() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let app = app(state(&[(ADVANCED_URL, 200, key_bytes(&public))]));
        let (challenge, _) = get_challenge(&app).await;
        let body = serde_json::json!({
            "email": EMAIL,
            "challenge": challenge,
            "signature": clearsign(2, &challenge, &secret),
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok()),
            Some("session=issued-for-joe.doe@example.org")
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["email"], EMAIL);
        assert_eq!(value["status"], "success");
    }

    #[tokio::test]
    async fn a_bad_signature_is_a_401_with_no_session() {
        let (_, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let (other_secret, _) = generate(9, "Joe Doe <joe.doe@example.org>");
        let app = app(state(&[(ADVANCED_URL, 200, key_bytes(&public))]));
        let (challenge, _) = get_challenge(&app).await;
        let body = serde_json::json!({
            "email": EMAIL,
            "challenge": challenge,
            "signature": clearsign(2, &challenge, &other_secret),
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn the_server_pubkey_route_serves_the_armored_key() {
        let app = app(state(&[]));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/server-pubkey")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[tokio::test]
    async fn encrypted_requests_are_decrypted_and_responses_encrypted_for_the_recipient() {
        let (secret, public) = generate(7, "Joe Doe <joe.doe@example.org>");
        let st = state(&[(ADVANCED_URL, 200, key_bytes(&public))]);
        let app = app(st.clone());

        // Log in first so the recipient key is registered.
        let (challenge, _) = get_challenge(&app).await;
        let login_body = serde_json::json!({
            "email": EMAIL,
            "challenge": challenge,
            "signature": clearsign(2, &challenge, &secret),
        });
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(login_body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("login response");
        assert_eq!(login.status(), StatusCode::OK);

        // Encrypt a body to the server key, as the extension would.
        let server_armored = st
            .e2e()
            .expect("e2e on")
            .server()
            .public_armored()
            .to_string();
        let (server_key, _) = SignedPublicKey::from_string(&server_armored).expect("server key");
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let mut builder = MessageBuilder::from_bytes("", &b"top secret"[..])
            .seipd_v1(&mut rng, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, server_key.public_subkeys.first().expect("subkey"))
            .expect("encrypt");
        let encrypted = builder
            .to_armored_string(&mut rng, Default::default())
            .expect("armor");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/echo")
                    .header("x-gpg-encrypted", "true")
                    .header("x-gpg-id", EMAIL)
                    .body(Body::from(encrypted))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-gpg-encrypted")
                .and_then(|v| v.to_str().ok()),
            Some(EMAIL)
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let armored_text = String::from_utf8_lossy(&body).into_owned();
        let (msg, _) = Message::from_string(&armored_text).expect("pgp message");
        let mut decrypted = msg.decrypt(&Password::empty(), &secret).expect("decrypts");
        assert_eq!(decrypted.as_data_vec().expect("data"), b"echo:top secret");
    }

    #[tokio::test]
    async fn tunneled_requests_are_rewritten() {
        let st = state(&[]);
        let app = app(st.clone());
        let envelope = serde_json::json!({
            "tunnel_method": "DELETE",
            "tunnel_url": "/api/tunneled",
            "tunnel_headers": {"x-extra": "yes"},
        });
        let server_armored = st
            .e2e()
            .expect("e2e on")
            .server()
            .public_armored()
            .to_string();
        let (server_key, _) = SignedPublicKey::from_string(&server_armored).expect("server key");
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let mut builder = MessageBuilder::from_bytes("", envelope.to_string().into_bytes())
            .seipd_v1(&mut rng, pgp::crypto::sym::SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, server_key.public_subkeys.first().expect("subkey"))
            .expect("encrypt");
        let encrypted = builder
            .to_armored_string(&mut rng, Default::default())
            .expect("armor");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/anything")
                    .header("x-gpg-encrypted", "true")
                    .header("x-gpg-tunnel", "true")
                    .body(Body::from(encrypted))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..], b"tunnel-reached");
    }
}
