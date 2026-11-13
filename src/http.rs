//! The blocking HTTPS client handed to openidconnect.
//!
//! [`build_client`] wraps a `ureq` 3 `Agent` in a closure. Any
//! `Fn(HttpRequest) -> Result<HttpResponse, E>` with `E: std::error::Error`
//! implements openidconnect's (oauth2 5's) `SyncHttpClient` through a blanket
//! impl, and so do `Box<dyn Fn ...>` and `&dyn Fn ...`.
//!
//! The agent:
//! - uses rustls with the ring provider and trusts only the certificates in
//!   `cfg.ca_file` (no platform or bundled roots);
//! - follows no redirects (a 3xx is returned as-is and fails in oauth2);
//! - refuses any request URI that is not `https`, before connecting;
//! - uses no proxy (ureq's default config looks at `HTTPS_PROXY`/`ALL_PROXY`;
//!   that value is discarded);
//! - bounds connecting (TCP and TLS handshake) by `cfg.connect_timeout` and
//!   each later phase (send headers, send body, receive headers, receive
//!   body) by `cfg.timeout`. DNS resolution is left unbounded, because ureq
//!   spawns a thread for a resolve timeout (or a global/per-call one) and the
//!   module must not start threads inside the PAM caller;
//! - returns error statuses as responses, so oauth2 sees error bodies;
//! - caps response bodies at [`MAX_BODY`] bytes.

use std::path::Path;
use std::sync::Arc;

use ::http::uri::Scheme;
use openidconnect::{HttpRequest, HttpResponse};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Insecure(uri) => write!(f, "refusing a non-https request to {uri}"),
            Self::TooLarge => write!(f, "response body larger than {MAX_BODY} bytes"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<HttpError> for Error {
    /// `Tls` → [`Error::Tls`]; `Network`, `Insecure`, `TooLarge` → [`Error::Network`].
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::Tls(msg) => Error::Tls(msg),
            HttpError::Network(msg) => Error::Network(msg),
            other => Error::Network(other.to_string()),
        }
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
pub fn build_client(cfg: &Config) -> Result<HttpClientFn, Error> {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(load_roots(&cfg.ca_file)?)
        .build();
    let agent: Agent = Agent::config_builder()
        .tls_config(tls)
        .proxy(None)
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(cfg.connect_timeout))
        .timeout_send_request(Some(cfg.timeout))
        .timeout_send_body(Some(cfg.timeout))
        .timeout_recv_response(Some(cfg.timeout))
        .timeout_recv_body(Some(cfg.timeout))
        .build()
        .into();
    Ok(Box::new(move |req| send(&agent, req)))
}

/// Reads the PEM bundle at `path`. Every certificate in it must parse, and
/// there must be at least one.
fn load_roots(path: &Path) -> Result<RootCerts, Error> {
    let pem = std::fs::read(path)
        .map_err(|e| Error::Tls(format!("cannot read CA file {}: {e}", path.display())))?;
    // A PEM syntax error is treated like an empty bundle.
    let ders: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    let (added, ignored) = RootCertStore::empty().add_parsable_certificates(ders.iter().cloned());
    if added == 0 || ignored > 0 {
        return Err(Error::Tls(format!(
            "CA file {}: {added} usable and {ignored} invalid certificates",
            path.display()
        )));
    }
    let certs: Vec<Certificate<'static>> = ders
        .iter()
        .map(|d| Certificate::from_der(d.as_ref()).to_owned())
        .collect();
    Ok(RootCerts::new_with_certs(&certs))
}

/// Sends one request and reads the whole (capped) response body.
fn send(agent: &Agent, req: HttpRequest) -> Result<HttpResponse, HttpError> {
    if req.uri().scheme() != Some(&Scheme::HTTPS) {
        return Err(HttpError::Insecure(req.uri().to_string()));
    }
    let (parts, mut body) = agent.run(req).map_err(classify)?.into_parts();
    let body = body
        .with_config()
        .limit(MAX_BODY)
        .read_to_vec()
        .map_err(classify)?;
    Ok(HttpResponse::from_parts(parts, body))
}

/// Sorts a ureq error into an [`HttpError`]. Handshake failures (such as an
/// untrusted certificate) arrive as an I/O error wrapping a `rustls::Error`.
fn classify(e: ureq::Error) -> HttpError {
    match e {
        ureq::Error::BodyExceedsLimit(_) => HttpError::TooLarge,
        ureq::Error::Io(io) if io.get_ref().is_some_and(|inner| inner.is::<rustls::Error>()) => {
            HttpError::Tls(io.to_string())
        }
        e => HttpError::Network(e.to_string()),
    }
}

#[cfg(test)]
#[path = "tests/http_tests.rs"]
mod tests;
