#[allow(unused_imports)]
use super::*;

/// Outcome spelling: the Linux-PAM constant name without `PAM_`, lower case.
const OUTCOMES: [(PamCode, &str); 9] = [
    (PamCode::Success, "success"),
    (PamCode::Ignore, "ignore"),
    (PamCode::AuthErr, "auth_err"),
    (PamCode::MaxTries, "maxtries"),
    (PamCode::AuthInfoUnavail, "authinfo_unavail"),
    (PamCode::ConvErr, "conv_err"),
    (PamCode::ServiceErr, "service_err"),
    (PamCode::UserUnknown, "user_unknown"),
    (PamCode::Abort, "abort"),
];

#[test]
fn documented_example_line() {
    assert_eq!(
        auth_line(
            Some("alice"),
            Some("10.0.0.5"),
            Some(Method::Sso),
            PamCode::Success
        ),
        "pam_idp: user=alice rhost=10.0.0.5 method=sso outcome=success"
    );
}

#[test]
fn password_method_is_spelled_like_the_argument() {
    assert_eq!(
        auth_line(
            Some("bob"),
            Some("host.example"),
            Some(Method::Pass),
            PamCode::Ignore
        ),
        "pam_idp: user=bob rhost=host.example method=password outcome=ignore"
    );
}

#[test]
fn missing_values_are_dashes() {
    assert_eq!(
        auth_line(None, None, None, PamCode::ServiceErr),
        "pam_idp: user=- rhost=- method=- outcome=service_err"
    );
}

#[test]
fn every_outcome_has_its_spelling() {
    for (code, word) in OUTCOMES {
        let line = auth_line(Some("u"), None, Some(Method::Sso), code);
        assert_eq!(
            line,
            format!("pam_idp: user=u rhost=- method=sso outcome={word}"),
            "{code:?}"
        );
    }
}

#[test]
fn spaces_and_control_characters_cannot_forge_fields() {
    let user = "alice outcome=success\nmethod=sso\r\t\u{7f}\u{1b}[2J";
    let rhost = "evil host\0x\nuser=root";
    let line = auth_line(
        Some(user),
        Some(rhost),
        Some(Method::Pass),
        PamCode::AuthErr,
    );
    assert!(
        !line
            .chars()
            .any(|c| c.is_control() || (c.is_whitespace() && c != ' ')),
        "control characters survived: {line:?}"
    );
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 5, "fields were split or forged: {line:?}");
    assert_eq!(fields[0], "pam_idp:");
    assert!(fields[1].starts_with("user=alice"), "{line:?}");
    assert!(fields[2].starts_with("rhost=evil"), "{line:?}");
    assert_eq!(fields[3], "method=password");
    assert_eq!(fields[4], "outcome=auth_err");
    assert_eq!(line.matches("outcome=").count(), 1, "{line:?}");
}

#[test]
fn ordinary_characters_are_kept() {
    let line = auth_line(
        Some("j.doe-2_x@corp"),
        Some("fe80::1%eth0"),
        None,
        PamCode::UserUnknown,
    );
    assert_eq!(
        line,
        "pam_idp: user=j.doe-2_x@corp rhost=fe80::1%eth0 method=- outcome=user_unknown"
    );
}

#[test]
fn non_ascii_printable_characters_are_kept() {
    let line = auth_line(Some("jörg"), None, None, PamCode::Abort);
    assert_eq!(line, "pam_idp: user=jörg rhost=- method=- outcome=abort");
}
