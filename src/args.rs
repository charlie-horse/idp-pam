//! Module arguments (`key=value` words from the PAM stack line).
//!
//! Lists are comma-separated; durations are whole seconds. Unknown keys,
//! duplicate keys, bad values, and any non-`https` URL are
//! [`Error::Config`] (→ `PAM_SERVICE_ERR`).
//!
//! | Key | Default | Meaning |
//! | --- | --- | --- |
//! | `methods` | `password,sso` | Menu entries in order (`password`, `sso`); one entry skips the menu |
//! | `default` | first of `methods` | Method chosen by an empty answer |
//! | `labels` | [`DEFAULT_PASS_LABEL`], [`DEFAULT_SSO_LABEL`] | Menu labels, comma-separated, in `methods` order |
//! | `issuer` | required | OIDC issuer URL (`https`) |
//! | `client_id` | required | OAuth client id |
//! | `secret_file` | [`DEFAULT_SECRET_FILE`] | Client-secret file |
//! | `ca_file` | [`DEFAULT_CA_FILE`] | PEM bundle; the only TLS roots trusted |
//! | `device_endpoint` | from discovery | Override for `device_authorization_endpoint` (`https`, issuer host) |
//! | `scopes` | [`DEFAULT_SCOPES`] | Requested scopes |
//! | `username_claim` | `preferred_username` | Claim that must equal `PAM_USER` |
//! | `groups_claim` | `groups` | Claim holding the user's groups |
//! | `require_group` | empty (no check) | At least one of these groups is required |
//! | `connect_timeout` | 10 | TCP/TLS connect timeout, seconds |
//! | `timeout` | 30 | Per-request timeout, seconds |
//! | `max_wait` | 600 | Upper bound on the whole device flow, seconds |
//! | `wait` | `auto` | `auto`, `enter`, `poll` |
//! | `qr` | `on` | `on`, `off`, `invert` |
//! | `debug` | off | Bare flag (or `debug=true`/`false`) |

use std::path::PathBuf;
use std::time::Duration;

use openidconnect::url::Url;

use crate::error::Error;

/// Default client-secret file.
pub const DEFAULT_SECRET_FILE: &str = "/var/lib/secrets/login-sso-client-secret";
/// Default CA bundle.
pub const DEFAULT_CA_FILE: &str = "/etc/ssl/certs/ca-certificates.crt";
/// Default scopes.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile"];
/// Default username claim.
pub const DEFAULT_USERNAME_CLAIM: &str = "preferred_username";
/// Default groups claim.
pub const DEFAULT_GROUPS_CLAIM: &str = "groups";
/// Default menu label for [`Method::Pass`].
pub const DEFAULT_PASS_LABEL: &str = "Password";
/// Default menu label for [`Method::Sso`].
pub const DEFAULT_SSO_LABEL: &str = "Single sign-on (browser or phone)";
/// Default `connect_timeout`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default `timeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default `max_wait`.
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(600);

/// A login method offered by the menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// The directory password, handled by the next module (`pam_sss`); we return `PAM_IGNORE`.
    /// Spelled `password` in arguments.
    Pass,
    /// OAuth 2.0 device flow against the issuer. Spelled `sso` in arguments.
    Sso,
}

/// When polling for the token starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitMode {
    /// [`WaitMode::Enter`] for the `sshd` service, [`WaitMode::Poll`] otherwise.
    Auto,
    /// Prompt "Press Enter once you've approved", then poll (needed for sshd,
    /// which only shows info lines together with the next prompt).
    Enter,
    /// Start polling right after showing the code.
    Poll,
}

/// QR code rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrMode {
    /// Dark modules drawn as filled half-blocks.
    On,
    /// No QR code.
    Off,
    /// Colours inverted, for light-on-dark terminals that need it.
    Invert,
}

/// Menu labels, one per method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Labels {
    /// Label for [`Method::Pass`].
    pub pass: String,
    /// Label for [`Method::Sso`].
    pub sso: String,
}

impl Default for Labels {
    fn default() -> Self {
        Self {
            pass: DEFAULT_PASS_LABEL.to_owned(),
            sso: DEFAULT_SSO_LABEL.to_owned(),
        }
    }
}

/// Parsed module configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Menu entries in display order; non-empty, no duplicates.
    pub methods: Vec<Method>,
    /// Method chosen by an empty menu answer; must be in `methods`.
    pub default_method: Method,
    /// Menu labels.
    pub labels: Labels,
    /// OIDC issuer (`https`).
    pub issuer: Url,
    /// OAuth client id.
    pub client_id: String,
    /// Client-secret file.
    pub secret_file: PathBuf,
    /// PEM CA bundle; the only trusted roots.
    pub ca_file: PathBuf,
    /// Override for the device authorization endpoint.
    pub device_endpoint: Option<Url>,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Claim that must equal `PAM_USER`.
    pub username_claim: String,
    /// Claim holding the user's groups.
    pub groups_claim: String,
    /// Required groups (any one suffices); empty means no group check.
    pub require_group: Vec<String>,
    /// Connect timeout per request.
    pub connect_timeout: Duration,
    /// Overall timeout per request.
    pub timeout: Duration,
    /// Upper bound on the whole device flow.
    pub max_wait: Duration,
    /// When polling starts.
    pub wait: WaitMode,
    /// QR code rendering.
    pub qr: QrMode,
    /// Extra (still secret-free) logging.
    pub debug: bool,
}

impl Config {
    /// A config with every optional field at its default (methods `password,sso`,
    /// default `password`). For tests and for [`Config::parse`] to start from.
    #[must_use]
    pub fn new(issuer: Url, client_id: impl Into<String>) -> Self {
        Self {
            methods: vec![Method::Pass, Method::Sso],
            default_method: Method::Pass,
            labels: Labels::default(),
            issuer,
            client_id: client_id.into(),
            secret_file: PathBuf::from(DEFAULT_SECRET_FILE),
            ca_file: PathBuf::from(DEFAULT_CA_FILE),
            device_endpoint: None,
            scopes: DEFAULT_SCOPES.iter().map(|&s| s.to_owned()).collect(),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            groups_claim: DEFAULT_GROUPS_CLAIM.to_owned(),
            require_group: Vec::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
            max_wait: DEFAULT_MAX_WAIT,
            wait: WaitMode::Auto,
            qr: QrMode::On,
            debug: false,
        }
    }

    /// Parses the module arguments.
    ///
    /// # Errors
    /// [`Error::Config`] for unknown or duplicate keys, missing `issuer`/`client_id`,
    /// bad values, or a non-`https` URL.
    pub fn parse(_args: &[&str]) -> Result<Self, Error> {
        todo!()
    }

    /// The effective wait mode for `service`: [`WaitMode::Auto`] becomes
    /// [`WaitMode::Enter`] for `"sshd"` and [`WaitMode::Poll`] otherwise;
    /// explicit modes are returned unchanged.
    #[must_use]
    pub fn wait_mode_for(&self, _service: Option<&str>) -> WaitMode {
        todo!()
    }

    /// The menu label for `method`.
    #[must_use]
    pub fn label(&self, _method: Method) -> &str {
        todo!()
    }
}

#[cfg(test)]
#[path = "tests/args_tests.rs"]
mod tests;
