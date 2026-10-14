//! Server-side implementation of the Aegis Http Zero Trust protocol for
//! tokio services: OpenPGP challenge login (clearsigned challenges verified
//! against keys fetched from WKD / keyservers) and end-to-end encrypted
//! request / response payloads, exposed as a tower layer with an axum
//! adapter.
//!
//! Protocol reference: the AegisHttp browser extension and the
//! `gofiber-aegis` middleware; the hardening model follows one-time TTL
//! challenges, fingerprint pinning, HTTPS-only key lookup and
//! client-supplied keys off by default.

#[cfg(feature = "axum")]
pub mod axum;
pub mod challenge;
pub mod e2e;
pub mod login;
pub mod lookup;
pub mod verify;
