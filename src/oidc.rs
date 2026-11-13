//! OIDC: discovery (with the device endpoint), the device
//! authorization grant (RFC 8628), ID-token verification and claim checks.
//!
//! Built on `openidconnect` 4.1; see its `okta_device_grant` example for the
//! metadata extension. All network calls go through a [`DynHttpClient`].

use std::time::{Duration, SystemTime};

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGenderClaim,
    CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, DeviceAuthorizationResponse,
    DeviceAuthorizationUrl, EmptyExtraDeviceAuthorizationFields, EmptyExtraTokenFields,
    IdTokenFields, ProviderMetadata, StandardTokenResponse,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::args::Config;
use crate::error::Error;
use crate::http::DynHttpClient;
use crate::time::{Clock, Sleeper};

/// The non-standard discovery field we need (RFC 8628 §4).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceEndpointMetadata {
    /// `device_authorization_endpoint`.
    pub device_authorization_endpoint: DeviceAuthorizationUrl,
}

impl AdditionalProviderMetadata for DeviceEndpointMetadata {}

/// Provider metadata with the device endpoint.
pub type DeviceProviderMetadata = ProviderMetadata<
    DeviceEndpointMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Every ID-token claim that openidconnect does not model itself, so that
/// the configurable `username_claim` and `groups_claim` can be read.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct ExtraClaims {
    /// The remaining claims, by name.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl AdditionalClaims for ExtraClaims {}

/// ID-token fields of the token response.
pub type IdpIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// The token endpoint's response.
pub type Tokens = StandardTokenResponse<IdpIdTokenFields, CoreTokenType>;

/// The raw device authorization response.
pub type DeviceDetails = DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>;

/// Discovered provider: metadata (with JWKS) and the device endpoint to use
/// (from `cfg.device_endpoint` if set, else from discovery). Every endpoint
/// has been checked to be `https` on the issuer's host.
#[derive(Clone, Debug)]
pub struct Provider {
    /// Discovery document plus the fetched JWKS.
    pub metadata: DeviceProviderMetadata,
    /// The device authorization endpoint actually used.
    pub device_endpoint: DeviceAuthorizationUrl,
}

/// What the user is shown (the non-secret part of the device response).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStart {
    /// `verification_uri`.
    pub verification_uri: String,
    /// `verification_uri_complete`, if the `IdP` sent one.
    pub verification_uri_complete: Option<String>,
    /// `user_code`.
    pub user_code: String,
    /// `expires_in`.
    pub expires_in: Duration,
}

/// The secret part of a started device flow, needed to poll.
#[derive(Debug)]
pub struct DeviceSession {
    /// The full device response (holds the device code).
    pub details: DeviceDetails,
    /// Our own deadline: start time + min(`expires_in`, `cfg.max_wait`).
    /// Reaching it is [`Error::Expired`] whatever the library reports.
    pub deadline: SystemTime,
}

/// The verified identity taken from the ID token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// Value of `cfg.username_claim`.
    pub username: String,
    /// Value of `cfg.groups_claim` (missing claim → empty).
    pub groups: Vec<String>,
}

/// The SSO flow's dependencies, borrowed for one authentication.
pub struct Sso<'a> {
    /// Module configuration.
    pub cfg: &'a Config,
    /// HTTPS client.
    pub http: &'a DynHttpClient,
    /// Time source (token expiry, deadlines, `iat`).
    pub clock: &'a dyn Clock,
    /// Sleep between polls.
    pub sleeper: &'a dyn Sleeper,
}

impl Sso<'_> {
    /// Fetches the discovery document and JWKS, and picks the device endpoint.
    ///
    /// # Errors
    /// [`Error::Network`]/[`Error::Tls`] on transport failure; [`Error::Idp`] for
    /// bad metadata, a missing device endpoint, an issuer mismatch, or any
    /// endpoint that is not `https` on the issuer's host.
    pub fn discover(&self) -> Result<Provider, Error> {
        todo!()
    }

    /// Starts the device flow (client authenticated with `secret`, scopes from `cfg`).
    ///
    /// # Errors
    /// Transport errors as in [`Sso::discover`]; [`Error::Idp`] for an error response
    /// or a `verification_uri`/`verification_uri_complete` that is not `https`.
    pub fn start_device(
        &self,
        _provider: &Provider,
        _secret: &SecretString,
    ) -> Result<(DeviceStart, DeviceSession), Error> {
        todo!()
    }

    /// Polls the token endpoint until approval, denial, expiry or `session.deadline`
    /// (one `request()` call; the library handles `authorization_pending` and `slow_down`).
    ///
    /// # Errors
    /// [`Error::Denied`] for `access_denied`; [`Error::Expired`] for `expired_token`
    /// or once the deadline passes; [`Error::Idp`] for other error responses or a
    /// response without an ID token; transport errors as in [`Sso::discover`].
    pub fn wait_for_token(
        &self,
        _provider: &Provider,
        _secret: &SecretString,
        _session: &DeviceSession,
    ) -> Result<Tokens, Error> {
        todo!()
    }

    /// Verifies the ID token in `tokens`: RS256 only, signature against the JWKS,
    /// `iss`, `aud` (must contain `client_id`), `azp` (if present, must equal
    /// `client_id`), `exp`, and `iat` (not in the future), using `clock`. The
    /// nonce is not checked (the device flow has none).
    ///
    /// # Errors
    /// [`Error::Token`] for any verification failure or a missing ID token;
    /// [`Error::Claim`] if the username claim is missing or not a string, or the
    /// groups claim is not a list of strings.
    pub fn verify_id_token(&self, _provider: &Provider, _tokens: &Tokens) -> Result<Claims, Error> {
        todo!()
    }
}

/// Checks the verified claims against PAM and the config: `username` must equal
/// `pam_user`, and if `cfg.require_group` is non-empty, `groups` must contain at
/// least one of them.
///
/// # Errors
/// [`Error::Claim`] naming the failed check (not the token).
pub fn check_claims(_cfg: &Config, _pam_user: &str, _claims: &Claims) -> Result<(), Error> {
    todo!()
}

#[cfg(test)]
#[path = "tests/oidc_tests.rs"]
mod tests;
