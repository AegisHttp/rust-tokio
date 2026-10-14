# aegis-http-tokio

Server-side middleware for the [Aegis Http](https://github.com/AegisHttp) Zero Trust
protocol, for Rust / tokio services: OpenPGP challenge login and end-to-end
encrypted payloads, as a framework-independent tower layer with an axum adapter.

Counterpart of [`gofiber-aegis`](https://github.com/AegisHttp/gofiber-aegis) (Go)
and the client-side [`aegis-ts-sdk`](https://github.com/AegisHttp/aegis-ts-sdk).
OpenPGP operations use [rPGP](https://github.com/rpgp/rpgp) (pure Rust).

## Protocol

1. `GET /api/challenge` → `{"challenge": "<one-time random phrase>"}` with
   `x-gpg-support: true`.
2. The browser extension clearsigns the challenge with the key in the OS
   keyring and the page posts `{email, challenge, signature, public_key?}` to
   `POST /api/login`.
3. The server verifies: the clearsigned text equals the challenge (one-time,
   TTL), the signature checks out against a key fetched from WKD (primary) or
   a keyserver over HTTPS, the key identity matches the e-mail, the key is not
   revoked. Your application hook decides who may log in (and can pin the key
   fingerprint on first login).
4. Optionally, request bodies arriving with `x-gpg-encrypted` are decrypted
   with the server key, and JSON responses are encrypted to the verified
   sender (`x-gpg-id`), including the `x-gpg-tunnel` full-envelope mode.

Hardening defaults: one-time challenges with a TTL, HTTPS-only key lookup,
client-supplied public keys rejected unless explicitly enabled, `x-gpg-id`
never trusted without verification.

## Usage (axum)

```rust,ignore
use aegis_http_tokio::{AegisConfig, AegisState};

let aegis = AegisState::new(AegisConfig {
    server_email: "server@example.org".into(),
    ..AegisConfig::default()
});
let app = axum::Router::new()
    .merge(aegis_http_tokio::axum_router(aegis.clone())) // /api/challenge, /api/login, /api/server-pubkey
    .route("/api/protected", axum::routing::get(handler))
    .layer(aegis.e2e_layer()); // optional end-to-end encryption
```

Your login hook receives the verified e-mail and key fingerprint and returns
whether the login is accepted; session management stays in your application.

## Status

Under active development; API not yet stable. License: MIT OR Apache-2.0.
