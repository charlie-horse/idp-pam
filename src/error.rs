//! Error type and its mapping onto PAM return codes.
//!
//! Every failure inside the module becomes an [`Error`]; [`Error::pam_code`]
//! turns it into the [`PamCode`] that `pam_sm_authenticate` returns.

use std::fmt;

use pam_bindings::constants::PamResultCode;

/// The subset of PAM return codes this module can produce.
///
/// Kept separate from [`PamResultCode`] so that the logic (and its tests)
/// works with a small, `Copy`, comparable enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PamCode {
    /// `PAM_SUCCESS`: SSO verified.
    Success,
    /// `PAM_IGNORE`: the user chose the directory password; the next module handles it.
    Ignore,
    /// `PAM_AUTH_ERR`: claim or signature mismatch.
    AuthErr,
    /// `PAM_MAXTRIES`: denied, expired, cancelled, or bad menu input three times.
    MaxTries,
    /// `PAM_AUTHINFO_UNAVAIL`: network, TLS, `IdP` or secret-file problem.
    AuthInfoUnavail,
    /// `PAM_CONV_ERR`: the conversation function failed.
    ConvErr,
    /// `PAM_SERVICE_ERR`: bad module arguments.
    ServiceErr,
    /// `PAM_USER_UNKNOWN`: PAM could not supply a user name.
    UserUnknown,
    /// `PAM_ABORT`: a panic (produced by the hook macro, listed for completeness).
    Abort,
}

impl PamCode {
    /// Converts to the raw `pam-bindings` result code.
    #[must_use]
    pub fn to_pam(self) -> PamResultCode {
        todo!()
    }
}

/// Everything that can go wrong while authenticating.
///
/// The [`fmt::Display`] text is safe to log: it never contains the client
/// secret, the device code, tokens, or the raw `IdP` response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Bad or missing module arguments (unknown key, `http://` URL, bad number, ...).
    Config(String),
    /// The PAM conversation failed.
    Conv,
    /// PAM could not supply the user name.
    UserUnknown,
    /// Connection, DNS, timeout, or HTTP-level failure.
    Network(String),
    /// TLS setup or handshake failure (including an untrusted CA).
    Tls(String),
    /// The identity provider returned something unusable (bad metadata, error response, ...).
    Idp(String),
    /// The user denied the request at the `IdP` (`access_denied`).
    Denied,
    /// The device code expired, or our own `max_wait` deadline passed.
    Expired,
    /// The user cancelled at the "press Enter" prompt.
    Cancelled,
    /// Three invalid answers at the method menu.
    BadMenuInput,
    /// The ID token verified, but a claim check failed (wrong user, missing group, ...).
    Claim(String),
    /// The ID token failed verification (signature, iss, aud, azp, exp, iat, alg).
    Token(String),
    /// The client-secret file is missing, unreadable, or has unsafe ownership or mode.
    Secret(String),
}

impl Error {
    /// The PAM code for this error, per the plan's mapping:
    ///
    /// | Error | Code |
    /// | --- | --- |
    /// | `Config` | `ServiceErr` |
    /// | `Conv` | `ConvErr` |
    /// | `UserUnknown` | `UserUnknown` |
    /// | `Network`, `Tls`, `Idp`, `Secret` | `AuthInfoUnavail` |
    /// | `Denied`, `Expired`, `Cancelled`, `BadMenuInput` | `MaxTries` |
    /// | `Claim`, `Token` | `AuthErr` |
    #[must_use]
    pub fn pam_code(&self) -> PamCode {
        todo!()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
#[path = "tests/error_tests.rs"]
mod tests;
