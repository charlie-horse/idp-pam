//! The single syslog line written per authentication.
//!
//! It records only the user, rhost, method and outcome, e.g.
//! `pam_idp: user=alice rhost=10.0.0.5 method=sso outcome=success`.
//! Missing values are written as `-`. Control characters, whitespace and `=`
//! in the user and rhost are replaced by `?` so the line cannot be forged or split.

use crate::args::Method;
use crate::error::PamCode;

/// Formats the line for one authentication. `method` is `None` when no method
/// was chosen (bad arguments, menu failure).
#[must_use]
pub fn auth_line(
    user: Option<&str>,
    rhost: Option<&str>,
    method: Option<Method>,
    outcome: PamCode,
) -> String {
    format!(
        "pam_idp: user={} rhost={} method={} outcome={}",
        field(user),
        field(rhost),
        method.map_or("-", Method::name),
        outcome_name(outcome)
    )
}

/// `value` with every character that could split or forge a field replaced, or `-`.
fn field(value: Option<&str>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |v| {
            v.chars()
                .map(|c| {
                    if c.is_control() || c.is_whitespace() || c == '=' {
                        '?'
                    } else {
                        c
                    }
                })
                .collect()
        },
    )
}

/// The Linux-PAM constant name without `PAM_`, in lower case.
fn outcome_name(code: PamCode) -> &'static str {
    match code {
        PamCode::Success => "success",
        PamCode::Ignore => "ignore",
        PamCode::AuthErr => "auth_err",
        PamCode::MaxTries => "maxtries",
        PamCode::AuthInfoUnavail => "authinfo_unavail",
        PamCode::ConvErr => "conv_err",
        PamCode::ServiceErr => "service_err",
        PamCode::UserUnknown => "user_unknown",
        PamCode::Abort => "abort",
    }
}

#[cfg(test)]
#[path = "tests/log_tests.rs"]
mod tests;
