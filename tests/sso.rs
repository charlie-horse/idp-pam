//! End-to-end SSO tests: the public [`pam_idp::authenticate`] against an
//! `httpmock` `IdP` over TLS (discovery, JWKS, device and token endpoints),
//! with the real HTTP client, the real secret-file reader, a scripted PAM
//! conversation and a sleeper that does not sleep.
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use httpmock::prelude::*;
use httpmock::{Mock, MockServer};
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKeyId, PrivateSigningKey};
use serde_json::{Value, json};

use pam_idp::http::build_client;
use pam_idp::prompt::ENTER_PROMPT;
use pam_idp::secret::FileSecretSource;
use pam_idp::time::SystemClock;
use pam_idp::{Conv, Deps, Error, Logger, PamCode, PamItems, Sleeper, authenticate};

const CLIENT_ID: &str = "pam-login";
const CLIENT_SECRET: &str = "e2e-client-s3cret";
const DEVICE_CODE: &str = "dev-e2e-1";
const USER_CODE: &str = "QXRT-PLMN";
const ACCESS_TOKEN: &str = "at-e2e-opaque";
const ISSUER_PATH: &str = "/application/o/login/";
const DEVICE_PATH: &str = "/application/o/device/";
const TOKEN_PATH: &str = "/application/o/token/";
const JWKS_PATH: &str = "/application/o/login/jwks/";

/// Test-only RSA key (2048 bit, PKCS#1). Never used outside these tests.
const KEY_PEM: &str = concat!(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEogIBAAKCAQEApoDhxnYw/HFlUNFJ9ZyREgKZ98MCI4E7+SYNp72Jz6PApkjd\n",
    "E/qnDq1xBzIViI7RNxmop9zV0nGLrlUkYzwnsK6leVruOExNahDHMXdTkvoZfFGr\n",
    "xlLf3u8+nI+XQNC+M7PkcCHbEpH+4FOWS/UWVyVf6O2Fy7i/Z1O0eaSKIPtXcSLN\n",
    "GM2cYR3Btj331z2JVXXz9KH47u5Sg3WDEa0Aj1fWP3sl4ScvdA0zZrsJFfbPc541\n",
    "cqzWtEXidvo2F5438rJPUcOeKecq5gqdkSkA8oxmh4WNLID9hMhlC7MNS45XoILf\n",
    "BPjDaDU67pfOFxw+oMWc20vxyEFBsr0dQHJpWwIDAQABAoH/B0ZX7FPoVMB5rMJu\n",
    "sbTQMAw45tM/kIZzzIHwFsxqHJVp1WhQGo9dxq6w2UDSNMZneibBSqc+/D63ad0M\n",
    "GMUfx2kJcwGPjOYnX0uVQoEQoPyFT/KzVb4QVdMnpsv0oG6RXCK44eF8W4w+VDl4\n",
    "o3ok1RI1RHzQZTK2uGS2+TFTqEMbDrCX2JZJFS1HRrhACd9Hw/89VGPZZLyUdcJO\n",
    "plTnnwdxi16qE6BxKYBa9NuxpKVI4vTMYO74NZIxrwE0R6ME8PjEgs4QAyaEfx6y\n",
    "Mamw/I17aygtpjr0McFKjuwsYmLlBehh4SZoj8vcFwdLpo/uf3Z9oKcp6mdJmrtq\n",
    "nMGxAoGBANcqBz2NxtpjIiyol5v9gQidJTpvMgBvg0LaoI1k5Z0LkpEiRKSKTwOv\n",
    "oz+O+yXG5Icg79NffXbhVco7LvYeau54+vt3vGx6JWElI6rowIoe+NaseWZ++SRY\n",
    "dXtH/4AZxtJU+E6MVDsLjs3VAIG5pLNATvC92UkgivuzF9yvGBhfAoGBAMYan1Ic\n",
    "8Rk7dCoL/y9ekMD07x9lOd09dCVv6LKtairze7w6EYPWHa01mkuxzdK/q6swWFmP\n",
    "/5BEBWE9LZrx0b0Xlv8OMgPbMx4fqb6L2UlycRnWl+uJDYnxtthrvDxsLMrCgHAK\n",
    "+X4Bf/Wi7kOaXYCtDPjhXShbJ3OXx4eE6kCFAoGABzkJ9S8FNd+ODiG6tSnVYwyj\n",
    "a0rASvNzXJMqQJTagGMbEHQuCbf63wzOVhveom4CzeZ1JotWEt+NmbRS50AuJsM4\n",
    "6agjUyDmkFRG1j3p+LkBcXNov+ATTP0LNJA+K3ayDe18SGa9jR3eNVqpIbGxrbLC\n",
    "86Hr4WCOSdTBQE9AZ9ECgYEAlDsrZ3e8d9Li0utzIHC0A43Ct005BPCMzc504e2c\n",
    "eVMDDQ6uOGWogwiO0YDTr5Q30bo1AZ8b7UjYdbAfRccX11OlamemyPflwe6TRr7B\n",
    "8ZEuS9Uki9tbRBKXbE0A5n1S7sym6i9sC/r3Ukd93RvORxA1mqyW1jGOzZGOfTrZ\n",
    "RTkCgYEAx3exnkY9uP3KW0j+9Uw+lLEzocGW1I8QamxvmmD+M8hpYFsuGdkKgqJ0\n",
    "uv1N+rCRLDRFfQ0D5zq7/3ULUNdLVw0aWXsDl/4AkLudsR61mKr2JZJ3tYHCzDPw\n",
    "VUmyGfdRuyy4wlR9GG6G9OiP9gd5PDSXSy7agDWt9eI7Iu/ixhU=\n",
    "-----END RSA PRIVATE KEY-----\n",
);

/// An unrelated self-signed CA that does not sign httpmock's certificates.
const OTHER_CA_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIBjjCCATWgAwIBAgIUZ0mG/9DFaUPMjvkLouQm14hwDDswCgYIKoZIzj0EAwIw\n",
    "HDEaMBgGA1UEAwwRdW50cnVzdGVkLXRlc3QtY2EwIBcNMjYxMTEzMDU0OTE0WhgP\n",
    "MjEyNjEwMjAwNTQ5MTRaMBwxGjAYBgNVBAMMEXVudHJ1c3RlZC10ZXN0LWNhMFkw\n",
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFdmZ4Q/jQP5gnTnRNMwiwURJuHZWUuZW\n",
    "m12oGJ4coRnhzX6/yledl5c2RGyWRzsDSJwwIni8su7XkY4fm/PfOaNTMFEwHQYD\n",
    "VR0OBBYEFO4CVEO5/RhvIO4yWnz96Cd0L3HzMB8GA1UdIwQYMBaAFO4CVEO5/Rhv\n",
    "IO4yWnz96Cd0L3HzMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIg\n",
    "UcTNSa9MgP91P14Psbjpg7nZrytKb3KbhLMx+TsugUkCIFw6c6yytLVHbzatiKYq\n",
    "QgbRXCaCvwsCsJmqwIjc6h7X\n",
    "-----END CERTIFICATE-----\n",
);

// ---------------------------------------------------------------------------
// Fakes for the PAM side
// ---------------------------------------------------------------------------

/// Answers prompts from a script and records everything shown.
#[derive(Default)]
struct ScriptedConv {
    answers: RefCell<VecDeque<String>>,
    prompts: RefCell<Vec<String>>,
    infos: RefCell<Vec<String>>,
    errors: RefCell<Vec<String>>,
}

impl ScriptedConv {
    fn answering(answers: &[&str]) -> Self {
        let c = Self::default();
        c.answers
            .borrow_mut()
            .extend(answers.iter().map(|&a| a.to_owned()));
        c
    }

    fn prompts(&self) -> Vec<String> {
        self.prompts.borrow().clone()
    }

    fn shown(&self) -> String {
        let mut all = self.infos.borrow().join("\n");
        all.push('\n');
        all.push_str(&self.errors.borrow().join("\n"));
        all
    }
}

impl Conv for ScriptedConv {
    fn info(&self, msg: &str) -> Result<(), Error> {
        self.infos.borrow_mut().push(msg.to_owned());
        Ok(())
    }

    fn error_msg(&self, msg: &str) -> Result<(), Error> {
        self.errors.borrow_mut().push(msg.to_owned());
        Ok(())
    }

    fn prompt_echo_on(&self, prompt: &str) -> Result<String, Error> {
        self.prompts.borrow_mut().push(prompt.to_owned());
        self.answers.borrow_mut().pop_front().ok_or(Error::Conv)
    }
}

struct Items {
    user: &'static str,
}

impl PamItems for Items {
    fn user(&self) -> Result<String, Error> {
        Ok(self.user.to_owned())
    }

    fn service(&self) -> Option<String> {
        Some("sshd".to_owned())
    }

    fn rhost(&self) -> Option<String> {
        Some("192.0.2.7".to_owned())
    }
}

#[derive(Default)]
struct Lines(RefCell<Vec<String>>);

impl Logger for Lines {
    fn log(&self, msg: &str) {
        self.0.borrow_mut().push(msg.to_owned());
    }
}

/// Records the requested sleeps without sleeping.
#[derive(Default)]
struct NoSleep(RefCell<Vec<Duration>>);

impl Sleeper for NoSleep {
    fn sleep(&self, d: Duration) {
        self.0.borrow_mut().push(d);
        assert!(self.0.borrow().len() < 1000, "runaway poll loop");
    }
}

// ---------------------------------------------------------------------------
// The mock IdP
// ---------------------------------------------------------------------------

fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for c in chars.iter().take(chunk.len() + 1) {
            out.push(char::from(A[*c as usize]));
        }
    }
    out
}

fn key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY_PEM, Some(JsonWebKeyId::new("e2e".to_owned()))).unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign(claims: &Value) -> String {
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "e2e" });
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let sig = key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    format!("{input}.{}", b64url(&sig))
}

/// The always-present endpoints of the mock IdP.
struct Base<'a> {
    discovery: Mock<'a>,
    jwks: Mock<'a>,
    device: Mock<'a>,
}

/// Installs discovery, JWKS and device endpoints on `server`.
fn base(server: &MockServer) -> Base<'_> {
    let doc = json!({
        "issuer": server.url(ISSUER_PATH),
        "authorization_endpoint": server.url("/application/o/authorize/"),
        "token_endpoint": server.url(TOKEN_PATH),
        "userinfo_endpoint": server.url("/application/o/userinfo/"),
        "jwks_uri": server.url(JWKS_PATH),
        "device_authorization_endpoint": server.url(DEVICE_PATH),
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"]
    });
    let discovery = server.mock(|when, then| {
        when.method(GET)
            .path(format!("{ISSUER_PATH}.well-known/openid-configuration"));
        then.status(200)
            .header("content-type", "application/json")
            .body(doc.to_string());
    });
    let jwks_doc = json!({ "keys": [serde_json::to_value(key().as_verification_key()).unwrap()] });
    let jwks = server.mock(|when, then| {
        when.method(GET).path(JWKS_PATH);
        then.status(200)
            .header("content-type", "application/json")
            .body(jwks_doc.to_string());
    });
    let device_body = json!({
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": server.url("/if/device/"),
        "verification_uri_complete": server.url(format!("/if/device/?code={USER_CODE}")),
        "expires_in": 600,
        "interval": 1
    });
    let device = server.mock(|when, then| {
        when.method(POST)
            .path(DEVICE_PATH)
            .body_includes("scope=openid");
        then.status(200)
            .header("content-type", "application/json")
            .body(device_body.to_string());
    });
    Base {
        discovery,
        jwks,
        device,
    }
}

/// ID-token claims for `username`, valid now (the real clock is used end to end).
fn id_claims(server: &MockServer, username: &str, groups: &[&str]) -> Value {
    let now = now_secs();
    json!({
        "iss": server.url(ISSUER_PATH),
        "sub": "8f2c1e",
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now - 5,
        "preferred_username": username,
        "groups": groups
    })
}

/// The token endpoint: answers `authorization_pending` `pending` times, then
/// issues tokens with `claims`. Returns (pending mock, success mock).
fn token<'a>(
    server: &'a MockServer,
    pending: usize,
    claims: &Value,
) -> (Option<Mock<'a>>, Mock<'a>) {
    // Created first, so that it answers until its call limit is used up.
    let pending_mock = (pending > 0).then(|| {
        server.mock(|when, then| {
            when.method(POST)
                .path(TOKEN_PATH)
                .body_includes(format!("device_code={DEVICE_CODE}"));
            then.status(400)
                .header("content-type", "application/json")
                .body(r#"{"error":"authorization_pending"}"#)
                .up_to_n_times(pending);
        })
    });
    (pending_mock, token_ok(server, claims))
}

fn token_ok<'a>(server: &'a MockServer, claims: &Value) -> Mock<'a> {
    let body = json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": sign(claims)
    });
    server.mock(|when, then| {
        when.method(POST)
            .path(TOKEN_PATH)
            .body_includes(format!("device_code={DEVICE_CODE}"));
        then.status(200)
            .header("content-type", "application/json")
            .body(body.to_string());
    })
}

/// The token endpoint answering with an OAuth error, every time.
fn token_error<'a>(server: &'a MockServer, error: &str) -> Mock<'a> {
    let body = json!({ "error": error });
    server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(400)
            .header("content-type", "application/json")
            .body(body.to_string());
    })
}

// ---------------------------------------------------------------------------
// Running authenticate()
// ---------------------------------------------------------------------------

/// Temp files (CA bundle and client secret) for one run.
struct Files {
    _dir: tempfile::TempDir,
    ca: PathBuf,
    secret: PathBuf,
}

fn files(ca_pem: &str, secret_mode: u32) -> Files {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    fs::write(&ca, ca_pem).unwrap();
    let secret = dir.path().join("client-secret");
    fs::write(&secret, format!("{CLIENT_SECRET}\n")).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(secret_mode)).unwrap();
    Files {
        _dir: dir,
        ca,
        secret,
    }
}

fn good_files() -> Files {
    files(httpmock::server::DEFAULT_CA_CERTIFICATE, 0o600)
}

/// Module arguments as on the PAM stack line, plus `extra`.
fn args(server: &MockServer, f: &Files, extra: &[&str]) -> Vec<String> {
    let mut a = vec![
        "methods=password,sso".to_owned(),
        "default=sso".to_owned(),
        format!("issuer={}", server.url(ISSUER_PATH)),
        format!("client_id={CLIENT_ID}"),
        format!("secret_file={}", f.secret.display()),
        format!("ca_file={}", f.ca.display()),
        "qr=off".to_owned(),
    ];
    a.extend(extra.iter().map(|&s| s.to_owned()));
    a
}

struct Outcome {
    code: PamCode,
    conv: ScriptedConv,
    log: Vec<String>,
    sleeps: Vec<Duration>,
}

fn run(args: &[String], user: &'static str, answers: &[&str]) -> Outcome {
    let conv = ScriptedConv::answering(answers);
    let items = Items { user };
    let lines = Lines::default();
    let sleeper = NoSleep::default();
    let deps = Deps {
        http: &build_client,
        sleeper: &sleeper,
        clock: &SystemClock,
        secrets: &FileSecretSource,
        logger: &lines,
    };
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let code = authenticate(&words, &conv, &items, &deps);
    Outcome {
        code,
        conv,
        log: lines.0.into_inner(),
        sleeps: sleeper.0.into_inner(),
    }
}

/// Exactly one syslog line, naming the user and free of every secret.
fn assert_one_clean_log_line(o: &Outcome, user: &str) {
    assert_eq!(o.log.len(), 1, "expected one syslog line: {:?}", o.log);
    let line = &o.log[0];
    assert!(line.contains(user), "{line:?}");
    for secret in [CLIENT_SECRET, DEVICE_CODE, USER_CODE, ACCESS_TOKEN, "eyJ"] {
        assert!(
            !line.contains(secret),
            "syslog line leaks {secret:?}: {line:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn sso_approved_after_pending_is_success() {
    let server = MockServer::start();
    let b = base(&server);
    let (pending, ok) = token(&server, 1, &id_claims(&server, "alice", &["users"]));
    let f = good_files();

    // Menu: item 2 is SSO; then Enter at the approval prompt.
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", ""]);

    assert_eq!(o.code, PamCode::Success, "shown: {}", o.conv.shown());
    let prompts = o.conv.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert_eq!(prompts[1], ENTER_PROMPT);
    let shown = o.conv.shown();
    assert!(shown.contains(USER_CODE), "user code not shown: {shown}");
    assert!(
        shown.contains("/if/device/"),
        "verification URI not shown: {shown}"
    );
    assert!(!shown.contains(CLIENT_SECRET) && !shown.contains(DEVICE_CODE));

    b.discovery.assert_calls(1);
    b.jwks.assert_calls(1);
    b.device.assert_calls(1);
    pending.unwrap().assert_calls(1);
    ok.assert_calls(1);
    assert_eq!(o.sleeps, vec![Duration::from_secs(1)]);
    assert_one_clean_log_line(&o, "alice");
}

#[test]
fn sso_default_with_poll_mode_needs_no_enter() {
    let server = MockServer::start();
    let b = base(&server);
    let (_, ok) = token(&server, 0, &id_claims(&server, "alice", &[]));
    let f = good_files();

    // Empty menu answer picks the default (sso); wait=poll skips the Enter prompt.
    let o = run(&args(&server, &f, &["wait=poll"]), "alice", &[""]);

    assert_eq!(o.code, PamCode::Success, "shown: {}", o.conv.shown());
    assert_eq!(o.conv.prompts().len(), 1, "{:?}", o.conv.prompts());
    b.device.assert_calls(1);
    ok.assert_calls(1);
    assert_one_clean_log_line(&o, "alice");
}

#[test]
fn sso_with_required_group_present_is_success() {
    let server = MockServer::start();
    base(&server);
    token(
        &server,
        0,
        &id_claims(&server, "alice", &["users", "admins"]),
    );
    let f = good_files();
    let o = run(
        &args(&server, &f, &["wait=poll", "require_group=admins,ops"]),
        "alice",
        &["2"],
    );
    assert_eq!(o.code, PamCode::Success, "shown: {}", o.conv.shown());
}

#[test]
fn sso_denied_is_maxtries() {
    let server = MockServer::start();
    let b = base(&server);
    let t = token_error(&server, "access_denied");
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", ""]);
    assert_eq!(o.code, PamCode::MaxTries);
    b.device.assert_calls(1);
    t.assert_calls(1);
    assert_one_clean_log_line(&o, "alice");
}

#[test]
fn sso_expired_is_maxtries() {
    let server = MockServer::start();
    base(&server);
    token_error(&server, "expired_token");
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=poll"]), "alice", &["2"]);
    assert_eq!(o.code, PamCode::MaxTries);
}

#[test]
fn sso_wrong_user_is_auth_err() {
    let server = MockServer::start();
    base(&server);
    // The IdP vouches for alice, but PAM is authenticating bob.
    let (_, ok) = token(&server, 0, &id_claims(&server, "alice", &["admins"]));
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=enter"]), "bob", &["2", ""]);
    assert_eq!(o.code, PamCode::AuthErr);
    ok.assert_calls(1);
    assert_one_clean_log_line(&o, "bob");
}

#[test]
fn sso_missing_required_group_is_auth_err() {
    let server = MockServer::start();
    base(&server);
    token(&server, 0, &id_claims(&server, "alice", &["users"]));
    let f = good_files();
    let o = run(
        &args(&server, &f, &["wait=poll", "require_group=admins"]),
        "alice",
        &["2"],
    );
    assert_eq!(o.code, PamCode::AuthErr);
}

#[test]
fn sso_token_signed_by_unknown_key_is_auth_err() {
    let server = MockServer::start();
    base(&server);
    // Same claims, but the JWT header names a key the JWKS does not have.
    let claims = id_claims(&server, "alice", &[]);
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": "other" });
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let sig = key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    let body = json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "id_token": format!("{input}.{}", b64url(&sig))
    });
    server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200)
            .header("content-type", "application/json")
            .body(body.to_string());
    });
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=poll"]), "alice", &["2"]);
    assert_eq!(o.code, PamCode::AuthErr);
}

#[test]
fn cancel_at_enter_prompt_is_maxtries_without_polling() {
    let server = MockServer::start();
    let b = base(&server);
    let t = token_error(&server, "authorization_pending");
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", "q"]);
    assert_eq!(o.code, PamCode::MaxTries);
    b.device.assert_calls(1);
    assert_eq!(t.calls(), 0, "polled after cancel");
}

#[test]
fn password_choice_is_ignore_without_network() {
    let server = MockServer::start();
    let b = base(&server);
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["1"]);
    assert_eq!(o.code, PamCode::Ignore);
    assert_eq!(b.discovery.calls(), 0);
    assert_eq!(b.device.calls(), 0);
    assert_one_clean_log_line(&o, "alice");
}

#[test]
fn untrusted_ca_is_authinfo_unavail() {
    let server = MockServer::start();
    let b = base(&server);
    let f = files(OTHER_CA_PEM, 0o600);
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", ""]);
    assert_eq!(o.code, PamCode::AuthInfoUnavail);
    assert_eq!(b.discovery.calls(), 0);
    assert_eq!(b.device.calls(), 0);
}

#[test]
fn idp_down_is_authinfo_unavail() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.any_request();
        then.status(503).body("maintenance");
    });
    let f = good_files();
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", ""]);
    assert_eq!(o.code, PamCode::AuthInfoUnavail);
}

#[test]
fn unsafe_secret_file_is_authinfo_unavail() {
    let server = MockServer::start();
    let b = base(&server);
    let f = files(httpmock::server::DEFAULT_CA_CERTIFICATE, 0o644);
    let o = run(&args(&server, &f, &["wait=enter"]), "alice", &["2", ""]);
    assert_eq!(o.code, PamCode::AuthInfoUnavail);
    assert_eq!(
        b.device.calls(),
        0,
        "secret sent although the file is unsafe"
    );
    assert_one_clean_log_line(&o, "alice");
}

#[test]
fn plain_http_issuer_is_service_err() {
    let server = MockServer::start();
    let b = base(&server);
    let f = good_files();
    let mut a = args(&server, &f, &["wait=enter"]);
    a[2] = format!("issuer=http://{}{ISSUER_PATH}", server.address());
    let o = run(&a, "alice", &["2", ""]);
    assert_eq!(o.code, PamCode::ServiceErr);
    assert_eq!(b.discovery.calls(), 0);
}
