//! `pam_idp`: a PAM module that offers a numbered menu (directory password
//! vs. SSO) and runs the OAuth 2.0 Device Authorization Grant (RFC 8628)
//! against an OIDC identity provider, verifying the ID token.
//!
//! All logic lives in [`authenticate`], which takes its side effects as
//! traits so that it is fully unit-testable; `ffi.rs` only adapts
//! `pam-bindings` to those traits.

pub mod args;
pub mod error;
pub mod http;
pub mod log;
pub mod menu;
pub mod oidc;
pub mod pam;
pub mod prompt;
pub mod secret;
pub mod time;

#[allow(missing_docs)]
mod ffi;

pub use crate::args::{Config, Method, QrMode, WaitMode};
pub use crate::error::{Error, PamCode};
pub use crate::http::{DynHttpClient, HttpClientFn, HttpError};
pub use crate::pam::{Conv, Logger, PamItems};
pub use crate::secret::SecretSource;
pub use crate::time::{Clock, Sleeper};

/// Builds the HTTPS client for a parsed config; [`http::build_client`] in production.
pub type HttpFactory = dyn Fn(&Config) -> Result<HttpClientFn, Error>;

/// The side effects [`authenticate`] needs besides the PAM conversation and items.
pub struct Deps<'a> {
    /// HTTP client factory (called after the arguments are parsed, so it can use
    /// `ca_file` and the timeouts).
    pub http: &'a HttpFactory,
    /// Sleep between polls.
    pub sleeper: &'a dyn Sleeper,
    /// Wall clock.
    pub clock: &'a dyn Clock,
    /// Client-secret reader.
    pub secrets: &'a dyn SecretSource,
    /// Syslog sink (exactly one line per call, see [`log::auth_line`]).
    pub logger: &'a dyn Logger,
}

/// `pam_sm_authenticate`: parse `args`, show the menu, and either hand off to
/// the password module ([`PamCode::Ignore`]) or run SSO
/// (discover → device start → show code → optional Enter prompt → poll →
/// verify ID token → check claims). Logs one line and returns the PAM code
/// per [`Error::pam_code`].
#[must_use]
pub fn authenticate(
    args: &[&str],
    conv: &dyn Conv,
    items: &dyn PamItems,
    deps: &Deps<'_>,
) -> PamCode {
    let mut user = None;
    let mut method = None;
    let code =
        run(args, conv, items, deps, &mut user, &mut method).unwrap_or_else(|e| e.pam_code());
    deps.logger.log(&log::auth_line(
        user.as_deref(),
        items.rhost().as_deref(),
        method,
        code,
    ));
    code
}

/// The body of [`authenticate`]; records the user and method as soon as they
/// are known, for the log line.
fn run(
    args: &[&str],
    conv: &dyn Conv,
    items: &dyn PamItems,
    deps: &Deps<'_>,
    user: &mut Option<String>,
    method: &mut Option<Method>,
) -> Result<PamCode, Error> {
    let cfg = Config::parse(args)?;
    let user = user.insert(items.user()?);
    if *method.insert(menu::choose(&cfg, conv)?) == Method::Pass {
        return Ok(PamCode::Ignore);
    }
    let http = (deps.http)(&cfg)?;
    let secret = deps.secrets.read(&cfg.secret_file)?;
    let sso = oidc::Sso {
        cfg: &cfg,
        http: &*http,
        clock: deps.clock,
        sleeper: deps.sleeper,
    };
    let provider = sso.discover()?;
    let (start, session) = sso.start_device(&provider, &secret)?;
    for msg in prompt::device_messages(&start, cfg.qr) {
        conv.info(&msg)?;
    }
    if let Some(p) = prompt::wait_prompt(cfg.wait_mode_for(items.service().as_deref()))
        && prompt::is_cancel(&conv.prompt_echo_on(p)?)
    {
        return Err(Error::Cancelled);
    }
    let tokens = sso.wait_for_token(&provider, &secret, &session)?;
    let claims = sso.verify_id_token(&provider, &tokens)?;
    oidc::check_claims(&cfg, user, &claims)?;
    Ok(PamCode::Success)
}

/// `pam_sm_setcred`: nothing to set, always [`PamCode::Success`].
#[must_use]
pub fn setcred() -> PamCode {
    PamCode::Success
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
