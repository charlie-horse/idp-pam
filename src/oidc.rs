//! OIDC: discovery (with the device endpoint), the device
//! authorization grant (RFC 8628), ID-token verification and claim checks.
//!
//! Built on `openidconnect` 4.1; see its `okta_device_grant` example for the
//! metadata extension. All network calls go through a [`DynHttpClient`].
//!
//! Discovery is done by hand (one GET, then [`JsonWebKeySet::fetch`]) rather
//! than with `ProviderMetadata::discover`, so that the endpoints can be
//! checked before the JWKS is fetched and so that `device_endpoint` can stand
//! in for a missing `device_authorization_endpoint`.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use ::http::StatusCode;
use ::http::header::ACCEPT;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreClaimName, CoreClaimType, CoreClientAuthMethod,
    CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
    CoreResponseMode, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreSubjectIdentifierType, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, Client, ClientId, ClientSecret,
    DeviceAuthorizationResponse, DeviceAuthorizationUrl, DeviceCodeErrorResponseType,
    EmptyExtraDeviceAuthorizationFields, EmptyExtraTokenFields, EndpointNotSet, IdTokenFields,
    IdTokenVerifier, JsonWebKeySet, Nonce, ProviderMetadata, RequestTokenError, Scope,
    StandardErrorResponse, StandardTokenResponse, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::args::Config;
use crate::error::Error;
use crate::http::{DynHttpClient, HttpError};
use crate::time::{Clock, Sleeper};

/// How far in the future an ID token's `iat` may lie (clock skew with the `IdP`).
pub const IAT_LEEWAY: Duration = Duration::from_secs(60);

/// Longest poll interval accepted from the `IdP` (the device response's `interval`).
pub const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Shortest wait between polls, whatever `interval` the `IdP` sends.
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// How much each `slow_down` adds to the poll interval (RFC 8628 §3.5).
pub const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// Consecutive transport failures while polling after which the flow ends
/// with that failure ([`Error::Network`]/[`Error::Tls`]).
pub const MAX_TRANSPORT_FAILURES: u32 = 3;

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

/// The openidconnect client, before any endpoint is set.
type IdpClient = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    Tokens,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
>;

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
    /// [`Sso::wait_for_token`] never sleeps past it.
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
        let issuer = &self.cfg.issuer;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.as_str().trim_end_matches('/')
        );
        // Building the request fails only for a URI that `http` cannot hold;
        // that is refused like a non-https one.
        let resp = ::http::Request::get(&url)
            .header(ACCEPT, "application/json")
            .body(Vec::new())
            .ok()
            .map_or(Err(HttpError::Insecure(url)), self.http)?;
        if resp.status() != StatusCode::OK {
            return Err(Error::Idp(format!(
                "discovery returned HTTP {}",
                resp.status()
            )));
        }
        let mut metadata: DeviceProviderMetadata = serde_json::from_slice(resp.body())
            .and_then(|mut doc: serde_json::Map<String, Value>| {
                if let Some(ep) = &self.cfg.device_endpoint {
                    doc.insert(
                        "device_authorization_endpoint".to_owned(),
                        Value::from(ep.as_str()),
                    );
                }
                serde_json::from_value(Value::Object(doc))
            })
            .map_err(|e| Error::Idp(format!("bad discovery document: {e}")))?;
        if metadata.issuer().url() != issuer {
            return Err(Error::Idp(format!(
                "discovery names issuer {}, expected {issuer}",
                metadata.issuer().as_str()
            )));
        }
        let device_endpoint = metadata
            .additional_metadata()
            .device_authorization_endpoint
            .clone();
        let endpoints = [
            ("jwks_uri", Some(metadata.jwks_uri().url())),
            (
                "token_endpoint",
                metadata.token_endpoint().map(TokenUrl::url),
            ),
            ("device_authorization_endpoint", Some(device_endpoint.url())),
        ];
        for (name, url) in endpoints {
            if !url.is_some_and(|u| u.scheme() == "https" && u.origin() == issuer.origin()) {
                return Err(Error::Idp(format!(
                    "{name} is missing or not https on the issuer's host"
                )));
            }
        }
        let jwks = JsonWebKeySet::fetch(metadata.jwks_uri(), &self.http).map_err(|e| match e {
            openidconnect::DiscoveryError::Request(e) => Error::from(e),
            e => Error::Idp(format!("JWKS: {e}")),
        })?;
        metadata = metadata.set_jwks(jwks);
        Ok(Provider {
            metadata,
            device_endpoint,
        })
    }

    /// Starts the device flow (client authenticated with `secret`, scopes from `cfg`).
    ///
    /// # Errors
    /// Transport errors as in [`Sso::discover`]; [`Error::Idp`] for an error response,
    /// a `verification_uri`/`verification_uri_complete` that is not `https`, or an
    /// `interval` that [`poll_interval`] refuses.
    pub fn start_device(
        &self,
        provider: &Provider,
        secret: &SecretString,
    ) -> Result<(DeviceStart, DeviceSession), Error> {
        let details: DeviceDetails = self
            .client(provider, secret)
            .set_device_authorization_url(provider.device_endpoint.clone())
            .exchange_device_code()
            .add_scopes(self.cfg.scopes.iter().cloned().map(Scope::new))
            .request(&self.http)
            .map_err(|e| match e {
                RequestTokenError::Request(e) => Error::from(e),
                // Only the error code: the description may echo request data.
                RequestTokenError::ServerResponse(r) => Error::Idp(format!(
                    "device authorization refused: {}",
                    r.error().as_ref()
                )),
                e => Error::Idp(format!("device authorization: {e}")),
            })?;
        let start = DeviceStart {
            verification_uri: details.verification_uri().as_str().to_owned(),
            verification_uri_complete: details
                .verification_uri_complete()
                .map(|u| u.secret().clone()),
            user_code: details.user_code().secret().clone(),
            expires_in: details.expires_in(),
        };
        if std::iter::once(&start.verification_uri)
            .chain(&start.verification_uri_complete)
            .any(|u| !u.starts_with("https://"))
        {
            return Err(Error::Idp("verification URI is not https".to_owned()));
        }
        poll_interval(&details, self.cfg)?;
        let deadline = self.clock.now() + start.expires_in.min(self.cfg.max_wait);
        Ok((start, DeviceSession { details, deadline }))
    }

    /// Polls the token endpoint until approval, denial, expiry or `session.deadline`.
    ///
    /// The loop is ours, not oauth2's (whose loop sleeps past any deadline,
    /// can overflow on `slow_down`, swallows transport errors and backs off
    /// below the server's interval). Each request goes through [`Sso::poll_once`].
    /// - The wait starts at the device response's `interval` (see
    ///   [`poll_interval`]) and grows by 5 s on each `slow_down` (RFC 8628 §3.5).
    /// - After a transport error the wait doubles from the current interval
    ///   (never below it); [`MAX_TRANSPORT_FAILURES`] in a row end the flow
    ///   with that error.
    /// - No wait runs past the deadline: when the next one would, the flow
    ///   ends at once, with the last transport error if the last poll failed
    ///   and [`Error::Expired`] otherwise.
    ///
    /// # Errors
    /// [`Error::Denied`] for `access_denied`; [`Error::Expired`] for `expired_token`
    /// or at the deadline; [`Error::Network`]/[`Error::Tls`] for transport failures
    /// as above; [`Error::Idp`] for a bad `interval`, other error responses, or a
    /// response without an ID token.
    pub fn wait_for_token(
        &self,
        provider: &Provider,
        secret: &SecretString,
        session: &DeviceSession,
    ) -> Result<Tokens, Error> {
        let mut interval = poll_interval(&session.details, self.cfg)?;
        let mut failures = 0;
        if self.time_left(session).is_zero() {
            return Err(Error::Expired);
        }
        loop {
            let (wait, failure) = match self.poll_once(provider, secret, session)? {
                Poll::Tokens(tokens) => {
                    if tokens.id_token().is_none() {
                        return Err(Error::Idp("token response has no ID token".to_owned()));
                    }
                    return Ok(*tokens);
                }
                Poll::Pending => {
                    failures = 0;
                    (interval, None)
                }
                Poll::SlowDown => {
                    failures = 0;
                    interval += SLOW_DOWN_STEP;
                    (interval, None)
                }
                Poll::Transport(e) => {
                    failures += 1;
                    if failures >= MAX_TRANSPORT_FAILURES {
                        return Err(e.into());
                    }
                    (interval * (1 << failures), Some(e))
                }
            };
            if wait > self.time_left(session) {
                return Err(failure.map_or(Error::Expired, Error::from));
            }
            self.sleeper.sleep(wait);
        }
    }

    /// Time until `session.deadline` (zero once it has passed).
    fn time_left(&self, session: &DeviceSession) -> Duration {
        session
            .deadline
            .duration_since(self.clock.now())
            .unwrap_or_default()
    }

    /// Sends exactly one token request, through oauth2 so that it builds the
    /// request (client authentication) and parses the response.
    ///
    /// oauth2 only offers a polling loop, so it is held to one round: its
    /// sleep function records the interval it asks for instead of sleeping,
    /// and from then on its clock reads past the (zero) timeout, so the loop
    /// ends with a made-up `expired_token` before a second request. The HTTP
    /// client records any transport error, which oauth2 would swallow.
    fn poll_once(
        &self,
        provider: &Provider,
        secret: &SecretString,
        session: &DeviceSession,
    ) -> Result<Poll, Error> {
        let token_url = provider
            .metadata
            .token_endpoint()
            .ok_or_else(|| Error::Idp("no token endpoint".to_owned()))?;
        let failure = RefCell::new(None);
        let http = |req| {
            (self.http)(req).inspect_err(|e: &HttpError| *failure.borrow_mut() = Some(e.clone()))
        };
        let asked = Cell::new(None);
        let done = AtomicBool::new(false);
        let now = self.clock.now();
        let later = now + Duration::from_secs(1);
        let result = self
            .client(provider, secret)
            .set_token_uri(token_url.clone())
            .exchange_device_access_token(&session.details)
            .set_time_fn(|| {
                if done.load(Ordering::Relaxed) {
                    later.into()
                } else {
                    now.into()
                }
            })
            .request(
                &http,
                |d| {
                    asked.set(Some(d));
                    done.store(true, Ordering::Relaxed);
                },
                Some(Duration::ZERO),
            );
        if let Some(asked) = asked.get() {
            // oauth2 wanted another round: pending, slow_down or a transport error.
            return Ok(match failure.into_inner() {
                Some(e) => Poll::Transport(e),
                None if asked > session.details.interval() => Poll::SlowDown,
                None => Poll::Pending,
            });
        }
        result
            .map(|t| Poll::Tokens(Box::new(t)))
            .map_err(|e| match e {
                RequestTokenError::ServerResponse(r) => match r.error() {
                    DeviceCodeErrorResponseType::AccessDenied => Error::Denied,
                    DeviceCodeErrorResponseType::ExpiredToken => Error::Expired,
                    other => Error::Idp(format!("token endpoint: {}", other.as_ref())),
                },
                e => Error::Idp(format!("token endpoint: {e}")),
            })
    }

    /// Verifies the ID token in `tokens`: RS256 only, signature against the JWKS,
    /// `iss`, `aud` (must contain `client_id`), `azp` (if present, must equal
    /// `client_id`), `exp`, and `iat` (at most [`IAT_LEEWAY`] in the future), using `clock`. The
    /// nonce is not checked (the device flow has none).
    ///
    /// # Errors
    /// [`Error::Token`] for any verification failure or a missing ID token;
    /// [`Error::Claim`] if the username claim is missing or not a string, or the
    /// groups claim is not a list of strings.
    pub fn verify_id_token(&self, provider: &Provider, tokens: &Tokens) -> Result<Claims, Error> {
        let cfg = self.cfg;
        let clock = self.clock;
        let id_token = tokens
            .id_token()
            .ok_or(Error::Token("no ID token".to_owned()))?;
        let verifier = IdTokenVerifier::new_public_client(
            ClientId::new(cfg.client_id.clone()),
            provider.metadata.issuer().clone(),
            provider.metadata.jwks().clone(),
        )
        .set_time_fn(move || clock.now().into())
        .set_issue_time_verifier_fn(move |iat| {
            if SystemTime::from(iat) > clock.now() + IAT_LEEWAY {
                Err(format!("issued in the future ({iat})"))
            } else {
                Ok(())
            }
        });
        let claims = id_token
            .claims(&verifier, |_: Option<&Nonce>| Ok(()))
            .map_err(|e| Error::Token(e.to_string()))?;
        if claims
            .authorized_party()
            .is_some_and(|azp| azp.as_str() != cfg.client_id)
        {
            return Err(Error::Token("azp is not our client_id".to_owned()));
        }
        // Standard and additional claims alike, by name.
        let all = serde_json::to_value(claims).unwrap_or_default();
        let username = all
            .get(&cfg.username_claim)
            .and_then(Value::as_str)
            .ok_or(Error::Claim(format!(
                "claim {} is missing or not a string",
                cfg.username_claim
            )))?
            .to_owned();
        let groups = all
            .get(&cfg.groups_claim)
            .map_or(Ok(Vec::new()), |g| serde_json::from_value(g.clone()))
            .map_err(|_| {
                Error::Claim(format!(
                    "claim {} is not a list of strings",
                    cfg.groups_claim
                ))
            })?;
        Ok(Claims { username, groups })
    }

    /// The openidconnect client for `provider`, authenticated with `secret`.
    /// openidconnect's automatic `openid` scope is off: `cfg.scopes` is sent as is.
    fn client(&self, provider: &Provider, secret: &SecretString) -> IdpClient {
        IdpClient::new(
            ClientId::new(self.cfg.client_id.clone()),
            provider.metadata.issuer().clone(),
            provider.metadata.jwks().clone(),
        )
        .set_client_secret(ClientSecret::new(secret.expose_secret().to_owned()))
        .disable_openid_scope()
    }
}

/// What one token request came back with.
enum Poll {
    /// The token response (not yet checked for an ID token).
    Tokens(Box<Tokens>),
    /// `authorization_pending`.
    Pending,
    /// `slow_down`.
    SlowDown,
    /// The request failed below HTTP (connect, TLS, timeout, ...).
    Transport(HttpError),
}

/// The wait between polls: the device response's `interval`, at least
/// [`MIN_INTERVAL`] (so that `0` is no busy loop). The interval must not
/// exceed [`MAX_INTERVAL`] or `cfg.max_wait`: a larger one would block the
/// PAM caller past `max_wait` (and oauth2 overflows adding 5 s to a huge one
/// on `slow_down`).
///
/// # Errors
/// [`Error::Idp`] if the interval is too long.
pub fn poll_interval(details: &DeviceDetails, cfg: &Config) -> Result<Duration, Error> {
    let interval = details.interval();
    if interval > MAX_INTERVAL.min(cfg.max_wait) {
        return Err(Error::Idp(format!(
            "device response asks for a {}-second poll interval",
            interval.as_secs()
        )));
    }
    Ok(interval.max(MIN_INTERVAL))
}

/// Checks the verified claims against PAM and the config: `username` must equal
/// `pam_user` (an empty `pam_user` never matches), and if `cfg.require_group` is non-empty, `groups` must contain at
/// least one of them.
///
/// # Errors
/// [`Error::Claim`] naming the failed check (not the token).
pub fn check_claims(cfg: &Config, pam_user: &str, claims: &Claims) -> Result<(), Error> {
    if pam_user.is_empty() || claims.username != pam_user {
        return Err(Error::Claim(format!(
            "{} does not match the PAM user",
            cfg.username_claim
        )));
    }
    if !cfg.require_group.is_empty() && !claims.groups.iter().any(|g| cfg.require_group.contains(g))
    {
        return Err(Error::Claim("none of the required groups".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/oidc_tests.rs"]
mod tests;
