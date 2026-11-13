//! The blocking HTTPS client handed to openidconnect.
//!
//! [`build_client`] wraps a `ureq` 3 `Agent` in a closure. Any
//! `Fn(HttpRequest) -> Result<HttpResponse, E>` with `E: std::error::Error`
//! implements openidconnect's (oauth2 5's) `SyncHttpClient` through a blanket
//! impl, and so do `Box<dyn Fn ...>` and `&dyn Fn ...`.
//!
//! Requirements for the agent (implementation notes from the scaffold):
//! - rustls with the ring provider passed explicitly via
//!   `TlsConfig::builder().unversioned_rustls_crypto_provider(..)` (the crate
//!   is built with `ureq/rustls-no-provider`, so nothing is picked by default);
//!   roots only from `cfg.ca_file` (`RootCerts::new_with_certs`, PEM parsed
//!   with `ureq::tls::parse_pem` or `rustls_pki_types::pem::PemObject`);
//! - `max_redirects(0)` (a 3xx is returned as-is and fails in oauth2);
//! - `https_only(true)`, and reject non-`https` request URIs before sending;
//! - `proxy(None)`: ureq's default config reads `HTTPS_PROXY`/`ALL_PROXY` from
//!   the environment, which the module must not do;
//! - `timeout_connect(cfg.connect_timeout)` and a per-request overall bound
//!   from `cfg.timeout`. Note: ureq's `DefaultResolver` spawns a thread when a
//!   resolve timeout applies (`timeout_resolve` or `timeout_global`); to stay
//!   thread-free use per-phase timeouts that leave resolve unbounded, or a
//!   custom resolver;
//! - `http_status_as_error(false)` so oauth2 sees error bodies;
//! - response bodies capped at [`MAX_BODY`] bytes.

use openidconnect::{HttpRequest, HttpResponse};

use crate::args::Config;
use crate::error::Error;

/// Largest response body accepted, in bytes.
pub const MAX_BODY: u64 = 64 * 1024;

/// Transport-level failure of one HTTP request. Its `Display` never includes
/// request or response bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// Connect, DNS, I/O, timeout or protocol failure.
    Network(String),
    /// TLS failure, including an untrusted or unreadable CA.
    Tls(String),
    /// The request URI is not `https`.
    Insecure(String),
    /// The response body exceeded [`MAX_BODY`].
    TooLarge,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl std::error::Error for HttpError {}

impl From<HttpError> for Error {
    /// `Tls` → [`Error::Tls`]; `Network`, `Insecure`, `TooLarge` → [`Error::Network`].
    fn from(_e: HttpError) -> Self {
        todo!()
    }
}

/// The client as a trait object; this is what [`crate::oidc`] takes.
pub type DynHttpClient = dyn Fn(HttpRequest) -> Result<HttpResponse, HttpError>;

/// An owned client, as returned by [`build_client`].
pub type HttpClientFn = Box<DynHttpClient>;

/// Builds the HTTPS client for `cfg` (CA bundle, timeouts).
///
/// # Errors
/// [`Error::Tls`] if `cfg.ca_file` cannot be read or holds no certificate.
pub fn build_client(_cfg: &Config) -> Result<HttpClientFn, Error> {
    todo!()
}

#[cfg(test)]
#[path = "tests/http_tests.rs"]
mod tests;
