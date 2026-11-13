#[allow(unused_imports)]
use super::*;

const ISSUER: &str = "https://idp.example.test/application/o/login/";
const ISSUER_ARG: &str = "issuer=https://idp.example.test/application/o/login/";
const CLIENT_ARG: &str = "client_id=login-sso";

fn issuer() -> Url {
    Url::parse(ISSUER).unwrap()
}

/// Parses the two required arguments plus `extra`.
fn parse_with(extra: &[&str]) -> Result<Config, Error> {
    let mut args = vec![ISSUER_ARG, CLIENT_ARG];
    args.extend_from_slice(extra);
    Config::parse(&args)
}

fn assert_config_err(res: &Result<Config, Error>, what: &str) {
    assert!(
        matches!(res, Err(Error::Config(_))),
        "{what}: expected Error::Config, got {res:?}"
    );
}

// --- Config::new (implemented in the scaffold) -----------------------------

#[test]
fn new_fills_in_the_documented_defaults() {
    let cfg = Config::new(issuer(), "login-sso");
    assert_eq!(cfg.methods, vec![Method::Pass, Method::Sso]);
    assert_eq!(cfg.default_method, Method::Pass);
    assert_eq!(cfg.labels, Labels::default());
    assert_eq!(cfg.labels.pass, DEFAULT_PASS_LABEL);
    assert_eq!(cfg.labels.sso, DEFAULT_SSO_LABEL);
    assert_eq!(cfg.issuer.as_str(), ISSUER);
    assert_eq!(cfg.client_id, "login-sso");
    assert_eq!(cfg.secret_file, PathBuf::from(DEFAULT_SECRET_FILE));
    assert_eq!(cfg.ca_file, PathBuf::from(DEFAULT_CA_FILE));
    assert_eq!(cfg.device_endpoint, None);
    assert_eq!(cfg.scopes, vec!["openid".to_owned(), "profile".to_owned()]);
    assert_eq!(cfg.username_claim, DEFAULT_USERNAME_CLAIM);
    assert_eq!(cfg.groups_claim, DEFAULT_GROUPS_CLAIM);
    assert!(cfg.require_group.is_empty());
    assert_eq!(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);
    assert_eq!(cfg.max_wait, DEFAULT_MAX_WAIT);
    assert_eq!(cfg.wait, WaitMode::Auto);
    assert_eq!(cfg.qr, QrMode::On);
    assert!(!cfg.debug);
}

#[test]
fn default_constants_match_the_plan() {
    assert_eq!(
        DEFAULT_SECRET_FILE,
        "/var/lib/secrets/login-sso-client-secret"
    );
    assert_eq!(DEFAULT_CA_FILE, "/etc/ssl/certs/ca-certificates.crt");
    assert_eq!(DEFAULT_SCOPES, &["openid", "profile"]);
    assert_eq!(DEFAULT_USERNAME_CLAIM, "preferred_username");
    assert_eq!(DEFAULT_GROUPS_CLAIM, "groups");
    assert_eq!(DEFAULT_PASS_LABEL, "Password");
    assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DEFAULT_MAX_WAIT, Duration::from_secs(600));
}

// --- Config::parse: the minimal line ----------------------------------------

#[test]
fn parse_minimal_equals_new() {
    let cfg = parse_with(&[]).unwrap();
    assert_eq!(cfg, Config::new(issuer(), "login-sso"));
}

#[test]
fn parse_is_order_independent() {
    let a = Config::parse(&[CLIENT_ARG, "qr=off", ISSUER_ARG]).unwrap();
    let b = Config::parse(&[ISSUER_ARG, "qr=off", CLIENT_ARG]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.qr, QrMode::Off);
}

#[test]
fn parse_every_key() {
    let cfg = parse_with(&[
        "methods=sso,password",
        "default=password",
        "labels=Browser login,Directory pass",
        "secret_file=/run/keys/sso",
        "ca_file=/etc/idp/ca.pem",
        "device_endpoint=https://idp.example.test/application/o/device/",
        "scopes=openid,profile,email,groups",
        "username_claim=email",
        "groups_claim=roles",
        "require_group=admins,ops",
        "connect_timeout=5",
        "timeout=7",
        "max_wait=120",
        "wait=enter",
        "qr=invert",
        "debug",
    ])
    .unwrap();
    assert_eq!(cfg.methods, vec![Method::Sso, Method::Pass]);
    assert_eq!(cfg.default_method, Method::Pass);
    assert_eq!(cfg.labels.sso, "Browser login");
    assert_eq!(cfg.labels.pass, "Directory pass");
    assert_eq!(cfg.issuer.as_str(), ISSUER);
    assert_eq!(cfg.client_id, "login-sso");
    assert_eq!(cfg.secret_file, PathBuf::from("/run/keys/sso"));
    assert_eq!(cfg.ca_file, PathBuf::from("/etc/idp/ca.pem"));
    assert_eq!(
        cfg.device_endpoint.as_ref().map(Url::as_str),
        Some("https://idp.example.test/application/o/device/")
    );
    assert_eq!(cfg.scopes, ["openid", "profile", "email", "groups"]);
    assert_eq!(cfg.username_claim, "email");
    assert_eq!(cfg.groups_claim, "roles");
    assert_eq!(cfg.require_group, ["admins", "ops"]);
    assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
    assert_eq!(cfg.timeout, Duration::from_secs(7));
    assert_eq!(cfg.max_wait, Duration::from_secs(120));
    assert_eq!(cfg.wait, WaitMode::Enter);
    assert_eq!(cfg.qr, QrMode::Invert);
    assert!(cfg.debug);
}

// --- methods / default / labels ---------------------------------------------

#[test]
fn methods_single_sso() {
    let cfg = parse_with(&["methods=sso"]).unwrap();
    assert_eq!(cfg.methods, vec![Method::Sso]);
    assert_eq!(
        cfg.default_method,
        Method::Sso,
        "default is the first method"
    );
}

#[test]
fn methods_single_password() {
    let cfg = parse_with(&["methods=password"]).unwrap();
    assert_eq!(cfg.methods, vec![Method::Pass]);
    assert_eq!(cfg.default_method, Method::Pass);
}

#[test]
fn default_is_first_of_methods() {
    let cfg = parse_with(&["methods=sso,password"]).unwrap();
    assert_eq!(cfg.default_method, Method::Sso);
    let cfg = parse_with(&["methods=password,sso"]).unwrap();
    assert_eq!(cfg.default_method, Method::Pass);
}

#[test]
fn explicit_default() {
    let cfg = parse_with(&["methods=password,sso", "default=sso"]).unwrap();
    assert_eq!(cfg.methods, vec![Method::Pass, Method::Sso]);
    assert_eq!(cfg.default_method, Method::Sso);
    let cfg = parse_with(&["default=sso"]).unwrap();
    assert_eq!(cfg.default_method, Method::Sso);
}

#[test]
fn default_must_be_one_of_methods() {
    assert_config_err(
        &parse_with(&["methods=sso", "default=password"]),
        "default not in methods",
    );
    assert_config_err(
        &parse_with(&["methods=password", "default=sso"]),
        "default not in methods",
    );
}

#[test]
fn default_must_be_a_known_method() {
    assert_config_err(&parse_with(&["default=ssh-key"]), "unknown default");
    assert_config_err(&parse_with(&["default="]), "empty default");
}

#[test]
fn methods_reject_unknown_empty_and_duplicates() {
    assert_config_err(&parse_with(&["methods=sso,kerberos"]), "unknown method");
    assert_config_err(&parse_with(&["methods="]), "empty methods");
    assert_config_err(&parse_with(&["methods=sso,,password"]), "empty list item");
    assert_config_err(&parse_with(&["methods=sso,sso"]), "duplicate method");
    assert_config_err(&parse_with(&["methods=SSO"]), "methods are lower case");
}

#[test]
fn labels_follow_methods_order() {
    let cfg = parse_with(&["labels=Use my pass,Use SSO"]).unwrap();
    assert_eq!(cfg.labels.pass, "Use my pass");
    assert_eq!(cfg.labels.sso, "Use SSO");
}

#[test]
fn labels_for_a_single_method_keep_the_other_default() {
    let cfg = parse_with(&["methods=sso", "labels=Authentik"]).unwrap();
    assert_eq!(cfg.labels.sso, "Authentik");
    assert_eq!(cfg.labels.pass, DEFAULT_PASS_LABEL);
}

#[test]
fn labels_count_must_match_methods() {
    assert_config_err(&parse_with(&["labels=Only one"]), "too few labels");
    assert_config_err(
        &parse_with(&["methods=sso", "labels=a,b"]),
        "too many labels",
    );
    assert_config_err(&parse_with(&["labels=a,"]), "empty label");
}

#[test]
fn labels_may_come_before_methods() {
    let cfg = parse_with(&["labels=S,P", "methods=sso,password"]).unwrap();
    assert_eq!(cfg.labels.sso, "S");
    assert_eq!(cfg.labels.pass, "P");
}

#[test]
fn label_returns_the_label_of_each_method() {
    let mut cfg = Config::new(issuer(), "c");
    cfg.labels = Labels {
        pass: "P-label".into(),
        sso: "S-label".into(),
    };
    assert_eq!(cfg.label(Method::Pass), "P-label");
    assert_eq!(cfg.label(Method::Sso), "S-label");
}

// --- issuer / client_id / URLs ------------------------------------------------

#[test]
fn missing_issuer() {
    assert_config_err(&Config::parse(&[CLIENT_ARG]), "missing issuer");
}

#[test]
fn missing_client_id() {
    assert_config_err(&Config::parse(&[ISSUER_ARG]), "missing client_id");
}

#[test]
fn no_arguments_at_all() {
    assert_config_err(&Config::parse(&[]), "no arguments");
}

#[test]
fn empty_client_id() {
    assert_config_err(
        &Config::parse(&[ISSUER_ARG, "client_id="]),
        "empty client_id",
    );
}

#[test]
fn issuer_must_be_https() {
    assert_config_err(
        &Config::parse(&[
            "issuer=http://idp.example.test/application/o/login/",
            CLIENT_ARG,
        ]),
        "http issuer",
    );
    assert_config_err(
        &Config::parse(&["issuer=ftp://idp.example.test/", CLIENT_ARG]),
        "ftp issuer",
    );
}

#[test]
fn issuer_must_be_a_url() {
    assert_config_err(
        &Config::parse(&["issuer=not a url", CLIENT_ARG]),
        "garbage issuer",
    );
    assert_config_err(&Config::parse(&["issuer=", CLIENT_ARG]), "empty issuer");
}

#[test]
fn device_endpoint_must_be_https() {
    assert_config_err(
        &parse_with(&["device_endpoint=http://idp.example.test/application/o/device/"]),
        "http device endpoint",
    );
    assert_config_err(
        &parse_with(&["device_endpoint=::nope"]),
        "garbage device endpoint",
    );
}

#[test]
fn device_endpoint_must_be_on_the_issuer_host() {
    assert_config_err(
        &parse_with(&["device_endpoint=https://evil.example.test/application/o/device/"]),
        "device endpoint on another host",
    );
}

// --- keys and values ------------------------------------------------------------

#[test]
fn unknown_key() {
    assert_config_err(&parse_with(&["colour=blue"]), "unknown key");
    assert_config_err(
        &parse_with(&["Issuer=https://x.test/"]),
        "keys are case-sensitive",
    );
}

#[test]
fn bare_word_other_than_debug() {
    assert_config_err(&parse_with(&["verbose"]), "unknown flag");
    assert_config_err(&parse_with(&["timeout"]), "key without value");
}

#[test]
fn duplicate_keys() {
    assert_config_err(&parse_with(&["qr=on", "qr=off"]), "duplicate qr");
    assert_config_err(&parse_with(&[ISSUER_ARG]), "duplicate issuer");
    assert_config_err(&parse_with(&["debug", "debug"]), "duplicate debug");
}

#[test]
fn value_may_contain_equals_signs() {
    let cfg = parse_with(&["require_group=team=a"]).unwrap();
    assert_eq!(cfg.require_group, ["team=a"]);
}

#[test]
fn simple_string_keys() {
    let cfg = parse_with(&[
        "secret_file=/a/b",
        "ca_file=/c/d.pem",
        "username_claim=sub",
        "groups_claim=ak_groups",
    ])
    .unwrap();
    assert_eq!(cfg.secret_file, PathBuf::from("/a/b"));
    assert_eq!(cfg.ca_file, PathBuf::from("/c/d.pem"));
    assert_eq!(cfg.username_claim, "sub");
    assert_eq!(cfg.groups_claim, "ak_groups");
}

#[test]
fn empty_string_values_are_rejected() {
    for arg in [
        "secret_file=",
        "ca_file=",
        "username_claim=",
        "groups_claim=",
        "scopes=",
        "require_group=",
        "labels=",
        "device_endpoint=",
    ] {
        assert_config_err(&parse_with(&[arg]), arg);
    }
}

#[test]
fn scopes_list() {
    let cfg = parse_with(&["scopes=openid"]).unwrap();
    assert_eq!(cfg.scopes, ["openid"]);
    assert_config_err(&parse_with(&["scopes=openid,,email"]), "empty scope");
}

#[test]
fn require_group_list() {
    let cfg = parse_with(&["require_group=admins"]).unwrap();
    assert_eq!(cfg.require_group, ["admins"]);
    assert_config_err(&parse_with(&["require_group=a,"]), "empty group");
}

#[test]
fn durations_in_seconds() {
    let cfg = parse_with(&["connect_timeout=1", "timeout=3600", "max_wait=86400"]).unwrap();
    assert_eq!(cfg.connect_timeout, Duration::from_secs(1));
    assert_eq!(cfg.timeout, Duration::from_secs(3600));
    assert_eq!(cfg.max_wait, Duration::from_secs(86400));
}

#[test]
fn bad_numbers() {
    for key in ["connect_timeout", "timeout", "max_wait"] {
        for value in [
            "",
            "abc",
            "-1",
            "0",
            "1.5",
            "10s",
            " 5",
            "99999999999999999999999",
        ] {
            let arg = format!("{key}={value}");
            assert_config_err(&parse_with(&[&arg]), &arg);
        }
    }
}

#[test]
fn wait_values() {
    for (v, mode) in [
        ("auto", WaitMode::Auto),
        ("enter", WaitMode::Enter),
        ("poll", WaitMode::Poll),
    ] {
        let arg = format!("wait={v}");
        assert_eq!(parse_with(&[&arg]).unwrap().wait, mode, "{arg}");
    }
    assert_config_err(&parse_with(&["wait=forever"]), "bad wait");
    assert_config_err(&parse_with(&["wait="]), "empty wait");
}

#[test]
fn qr_values() {
    for (v, mode) in [
        ("on", QrMode::On),
        ("off", QrMode::Off),
        ("invert", QrMode::Invert),
    ] {
        let arg = format!("qr={v}");
        assert_eq!(parse_with(&[&arg]).unwrap().qr, mode, "{arg}");
    }
    assert_config_err(&parse_with(&["qr=yes"]), "bad qr");
}

#[test]
fn debug_values() {
    assert!(parse_with(&["debug"]).unwrap().debug);
    assert!(parse_with(&["debug=true"]).unwrap().debug);
    assert!(!parse_with(&["debug=false"]).unwrap().debug);
    assert_config_err(&parse_with(&["debug=yes"]), "bad debug");
    assert_config_err(&parse_with(&["debug="]), "empty debug");
}

#[test]
fn config_error_names_the_offending_key() {
    let Err(Error::Config(msg)) = parse_with(&["colour=blue"]) else {
        panic!("expected Error::Config");
    };
    assert!(msg.contains("colour"), "{msg:?}");
    let Err(Error::Config(msg)) = parse_with(&["timeout=abc"]) else {
        panic!("expected Error::Config");
    };
    assert!(msg.contains("timeout"), "{msg:?}");
}

// --- wait_mode_for ------------------------------------------------------------------

#[test]
fn wait_mode_for_auto() {
    let cfg = Config::new(issuer(), "c");
    assert_eq!(cfg.wait_mode_for(Some("sshd")), WaitMode::Enter);
    assert_eq!(cfg.wait_mode_for(Some("login")), WaitMode::Poll);
    assert_eq!(cfg.wait_mode_for(Some("sudo")), WaitMode::Poll);
    assert_eq!(cfg.wait_mode_for(Some("SSHD")), WaitMode::Poll);
    assert_eq!(cfg.wait_mode_for(None), WaitMode::Poll);
}

#[test]
fn wait_mode_for_explicit_modes_are_unchanged() {
    let mut cfg = Config::new(issuer(), "c");
    cfg.wait = WaitMode::Enter;
    assert_eq!(cfg.wait_mode_for(Some("login")), WaitMode::Enter);
    assert_eq!(cfg.wait_mode_for(None), WaitMode::Enter);
    cfg.wait = WaitMode::Poll;
    assert_eq!(cfg.wait_mode_for(Some("sshd")), WaitMode::Poll);
    assert_eq!(cfg.wait_mode_for(None), WaitMode::Poll);
}
