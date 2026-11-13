#[allow(unused_imports)]
use super::*;

use std::collections::HashSet;

/// One value of every `Error` variant, with its expected PAM code.
fn every_error() -> Vec<(Error, PamCode)> {
    vec![
        (
            Error::Config("unknown key `foo`".into()),
            PamCode::ServiceErr,
        ),
        (Error::Conv, PamCode::ConvErr),
        (Error::UserUnknown, PamCode::UserUnknown),
        (
            Error::Network("connection refused".into()),
            PamCode::AuthInfoUnavail,
        ),
        (
            Error::Tls("unknown issuer".into()),
            PamCode::AuthInfoUnavail,
        ),
        (Error::Idp("bad metadata".into()), PamCode::AuthInfoUnavail),
        (Error::Denied, PamCode::MaxTries),
        (Error::Expired, PamCode::MaxTries),
        (Error::Cancelled, PamCode::MaxTries),
        (Error::BadMenuInput, PamCode::MaxTries),
        (Error::Claim("wrong user".into()), PamCode::AuthErr),
        (Error::Token("bad signature".into()), PamCode::AuthErr),
        (
            Error::Secret("/run/secret: mode 0644".into()),
            PamCode::AuthInfoUnavail,
        ),
    ]
}

#[test]
fn pam_code_maps_every_variant() {
    for (err, code) in every_error() {
        assert_eq!(err.pam_code(), code, "pam_code({err:?})");
    }
}

#[test]
fn to_pam_maps_every_code() {
    use pam_bindings::constants::PamResultCode as R;
    let table = [
        (PamCode::Success, R::PAM_SUCCESS),
        (PamCode::Ignore, R::PAM_IGNORE),
        (PamCode::AuthErr, R::PAM_AUTH_ERR),
        (PamCode::MaxTries, R::PAM_MAXTRIES),
        (PamCode::AuthInfoUnavail, R::PAM_AUTHINFO_UNAVAIL),
        (PamCode::ConvErr, R::PAM_CONV_ERR),
        (PamCode::ServiceErr, R::PAM_SERVICE_ERR),
        (PamCode::UserUnknown, R::PAM_USER_UNKNOWN),
        (PamCode::Abort, R::PAM_ABORT),
    ];
    for (code, raw) in table {
        assert_eq!(code.to_pam(), raw, "to_pam({code:?})");
    }
}

#[test]
fn to_pam_raw_values_match_linux_pam() {
    // Linux-PAM's numeric values, as returned to libpam.
    let table = [
        (PamCode::Success, 0),
        (PamCode::ServiceErr, 3),
        (PamCode::AuthErr, 7),
        (PamCode::AuthInfoUnavail, 9),
        (PamCode::UserUnknown, 10),
        (PamCode::MaxTries, 11),
        (PamCode::ConvErr, 19),
        (PamCode::Ignore, 25),
        (PamCode::Abort, 26),
    ];
    for (code, raw) in table {
        assert_eq!(code.to_pam() as i32, raw, "raw value of {code:?}");
    }
}

#[test]
fn display_is_nonempty_and_distinct_for_every_variant() {
    let texts: Vec<String> = every_error().iter().map(|(e, _)| e.to_string()).collect();
    for t in &texts {
        assert!(!t.trim().is_empty(), "empty Display text");
        assert!(!t.contains('\n'), "Display must be one line: {t:?}");
    }
    let unique: HashSet<&String> = texts.iter().collect();
    assert_eq!(
        unique.len(),
        texts.len(),
        "Display texts collide: {texts:?}"
    );
}

#[test]
fn display_includes_the_detail_of_string_variants() {
    let cases = [
        Error::Config("unknown key `foo`".into()),
        Error::Network("connection refused".into()),
        Error::Tls("unknown issuer".into()),
        Error::Idp("bad metadata".into()),
        Error::Claim("wrong user".into()),
        Error::Token("bad signature".into()),
        Error::Secret("/run/secret: mode 0644".into()),
    ];
    for err in cases {
        let detail = match &err {
            Error::Config(s)
            | Error::Network(s)
            | Error::Tls(s)
            | Error::Idp(s)
            | Error::Claim(s)
            | Error::Token(s)
            | Error::Secret(s) => s.clone(),
            _ => unreachable!(),
        };
        let text = err.to_string();
        assert!(text.contains(&detail), "{text:?} lacks {detail:?}");
    }
}

#[test]
fn string_variants_with_different_details_display_differently() {
    assert_ne!(
        Error::Config("a".into()).to_string(),
        Error::Config("b".into()).to_string()
    );
}

#[test]
fn error_is_a_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(Error::Denied);
    assert!(err.source().is_none());
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_derives_clone_and_eq() {
    let e = Error::Idp("x".into());
    assert_eq!(e.clone(), e);
    assert_ne!(e, Error::Idp("y".into()));
}
