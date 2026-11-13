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

use std::collections::BTreeMap;
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

impl Method {
    /// The spelling used in arguments and in the log line.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pass => "password",
            Self::Sso => "sso",
        }
    }
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
    pub fn parse(args: &[&str]) -> Result<Self, Error> {
        let mut map = BTreeMap::new();
        for &arg in args {
            let (key, value) = arg
                .split_once('=')
                .or_else(|| (arg == "debug").then_some((arg, "true")))
                .ok_or_else(|| bad(arg, "expected key=value"))?;
            if map.insert(key, value).is_some() {
                return Err(bad(key, "given twice"));
            }
        }
        let issuer = https_url("issuer", required(&map, "issuer")?)?;
        let client_id = non_empty("client_id", required(&map, "client_id")?)?;
        let mut cfg = Self::new(issuer, client_id);
        for (&key, &value) in &map {
            match key {
                "issuer" | "client_id" | "default" | "labels" => {}
                "methods" => cfg.methods = methods(value)?,
                "secret_file" => cfg.secret_file = non_empty(key, value)?.into(),
                "ca_file" => cfg.ca_file = non_empty(key, value)?.into(),
                "device_endpoint" => {
                    let url = https_url(key, value)?;
                    if url.origin() != cfg.issuer.origin() {
                        return Err(bad(key, "must be on the issuer's host"));
                    }
                    cfg.device_endpoint = Some(url);
                }
                "scopes" => cfg.scopes = list(key, value)?,
                "username_claim" => non_empty(key, value)?.clone_into(&mut cfg.username_claim),
                "groups_claim" => non_empty(key, value)?.clone_into(&mut cfg.groups_claim),
                "require_group" => cfg.require_group = list(key, value)?,
                "connect_timeout" => cfg.connect_timeout = seconds(key, value)?,
                "timeout" => cfg.timeout = seconds(key, value)?,
                "max_wait" => cfg.max_wait = seconds(key, value)?,
                "wait" => {
                    cfg.wait = choice(
                        key,
                        value,
                        &[
                            ("auto", WaitMode::Auto),
                            ("enter", WaitMode::Enter),
                            ("poll", WaitMode::Poll),
                        ],
                    )?;
                }
                "qr" => {
                    cfg.qr = choice(
                        key,
                        value,
                        &[
                            ("on", QrMode::On),
                            ("off", QrMode::Off),
                            ("invert", QrMode::Invert),
                        ],
                    )?;
                }
                "debug" => cfg.debug = choice(key, value, &[("true", true), ("false", false)])?,
                _ => return Err(bad(key, "unknown key")),
            }
        }
        cfg.default_method = map
            .get("default")
            .map_or(Ok(cfg.methods[0]), |v| method("default", v))?;
        if !cfg.methods.contains(&cfg.default_method) {
            return Err(bad("default", "not one of methods"));
        }
        if let Some(value) = map.get("labels") {
            let labels = list("labels", value)?;
            if labels.len() != cfg.methods.len() {
                return Err(bad("labels", "need one label per method"));
            }
            for (&m, label) in cfg.methods.iter().zip(labels) {
                *match m {
                    Method::Pass => &mut cfg.labels.pass,
                    Method::Sso => &mut cfg.labels.sso,
                } = label;
            }
        }
        Ok(cfg)
    }

    /// The effective wait mode for `service`: [`WaitMode::Auto`] becomes
    /// [`WaitMode::Enter`] for `"sshd"` and [`WaitMode::Poll`] otherwise;
    /// explicit modes are returned unchanged.
    #[must_use]
    pub fn wait_mode_for(&self, service: Option<&str>) -> WaitMode {
        match self.wait {
            WaitMode::Auto if service == Some("sshd") => WaitMode::Enter,
            WaitMode::Auto => WaitMode::Poll,
            mode => mode,
        }
    }

    /// The menu label for `method`.
    #[must_use]
    pub fn label(&self, method: Method) -> &str {
        match method {
            Method::Pass => &self.labels.pass,
            Method::Sso => &self.labels.sso,
        }
    }
}

/// An [`Error::Config`] naming `key`.
fn bad(key: &str, why: &str) -> Error {
    Error::Config(format!("{key}: {why}"))
}

/// The value of a required key.
fn required<'a>(map: &BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, Error> {
    map.get(key).copied().ok_or_else(|| bad(key, "missing"))
}

fn non_empty<'a>(key: &str, value: &'a str) -> Result<&'a str, Error> {
    if value.is_empty() {
        Err(bad(key, "empty value"))
    } else {
        Ok(value)
    }
}

/// A comma-separated list of non-empty items.
fn list(key: &str, value: &str) -> Result<Vec<String>, Error> {
    value
        .split(',')
        .map(|item| non_empty(key, item).map(str::to_owned))
        .collect()
}

fn https_url(key: &str, value: &str) -> Result<Url, Error> {
    Url::parse(value)
        .ok()
        .filter(|url| url.scheme() == "https")
        .ok_or_else(|| bad(key, "must be an https URL"))
}

/// A positive whole number of seconds.
fn seconds(key: &str, value: &str) -> Result<Duration, Error> {
    value
        .parse()
        .ok()
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| bad(key, "must be a positive number of seconds"))
}

/// One of the named `options`.
fn choice<T: Copy>(key: &str, value: &str, options: &[(&str, T)]) -> Result<T, Error> {
    options
        .iter()
        .find(|(name, _)| *name == value)
        .map(|&(_, v)| v)
        .ok_or_else(|| bad(key, "unknown value"))
}

fn method(key: &str, value: &str) -> Result<Method, Error> {
    [Method::Pass, Method::Sso]
        .into_iter()
        .find(|m| m.name() == value)
        .ok_or_else(|| bad(key, "unknown method"))
}

/// A non-empty list of distinct methods.
fn methods(value: &str) -> Result<Vec<Method>, Error> {
    let mut out = Vec::new();
    for item in value.split(',') {
        let m = method("methods", item)?;
        if out.contains(&m) {
            return Err(bad("methods", "duplicate method"));
        }
        out.push(m);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/args_tests.rs"]
mod tests;
