#[allow(unused_imports)]
use super::*;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{HttpRequest, HttpResponse, JsonWebKeyId, PrivateSigningKey};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::args::DEFAULT_SECRET_FILE;
use crate::log::auth_line;
use crate::prompt::ENTER_PROMPT;

// ---------------------------------------------------------------------------
// Fixed values of the fake IdP. The "SECRET" markers let the tests check that
// nothing secret reaches the log or the user's screen.
// ---------------------------------------------------------------------------

const HOST: &str = "https://idp.example.test";
const ISSUER: &str = "https://idp.example.test/application/o/login/";
const CLIENT_ID: &str = "login-sso";
const CLIENT_SECRET: &str = "client-SECRET-5c0ffee0d15ea5e";
const DEVICE_CODE: &str = "device-code-SECRET-4f1d9a";
const ACCESS_TOKEN: &str = "access-token-SECRET-77aa";
const USER_CODE: &str = "WXYZ-1234";
const VERIFY_URI: &str = "https://idp.example.test/device";
const VERIFY_URI_COMPLETE: &str = "https://idp.example.test/device?code=WXYZ-1234";
const RHOST: &str = "192.0.2.7";
const KID: &str = "test-key-1";

const DISCOVERY_PATH: &str = "/application/o/login/.well-known/openid-configuration";
const JWKS_PATH: &str = "/application/o/login/jwks/";
const DEVICE_PATH: &str = "/application/o/device/";
const TOKEN_PATH: &str = "/application/o/token/";

const ISSUER_ARG: &str = "issuer=https://idp.example.test/application/o/login/";
const CLIENT_ARG: &str = "client_id=login-sso";

/// A throwaway 2048-bit RSA key generated for these tests only (PKCS#1 body,
/// base64). It signs fake ID tokens for the fake `IdP` and protects nothing.
/// The PEM armour is added at run time.
const TEST_KEY_B64: &[&str] = &[
    "MIIEowIBAAKCAQEAsQXegI2hLbDv8RQ/BF5WBrIwnJ0x9e7Rc0VIQc+UoXYC726GpHyTA47WXHy7",
    "z2ljA7o9VYr8vykFuAPapjsc4mop84ze6e42HHIOS0d8/IGCyPVAsv6r1NWO747KQgXDzqDdYol1",
    "4GTVe43zWWJIDOTkfR9oq7N76jK7RQFONP0W51IiGyvBscc7ZZ1zPmkKEgEmnADV89qVzHCHm872",
    "BDZCrw7YjUAzN8D0z2vxY48xAjkrMNbWQUA5eE/hNAsShN5foAtTDSby5jo+BA02cSXRrvXGyUE7",
    "6VQIrneC+nVMHpXjqa+5UL8tC6+8nMHDx+7vgStsdbJHvym+HmZJTQIDAQABAoIBAFNNwEG9pHok",
    "eB16Whdbr17yTrb8sGybyHvWwCScI0UCDGqRGBJivyoe9xhJ6HW4EczIwSE2yS7KBrNsOOIeEj8o",
    "F3rRsXrjSxqCv+BEEXigF6Qq6ZnyB3meT+fCycJdBSKBB/1dU5fXy7Cbgcdv3RkYQ7/v3mliiq8Q",
    "1Zio/x0mq9iHmelxkSIe7jIwPrbR5w/MOsOdU6KwvI1MqLNyuTHlGuB7IuNco5Ol9dnbMZEko2dP",
    "lkP0scWMdH9s8Yq+uO3yv5Hm8g7igVJCcuy9MezCgf2G60Po/RLx6o67Ghab0njTO4R/iIjEpcX5",
    "s34m/2heeW+ZTWHFoWtbsW7amu8CgYEA+VwNPitUlLRZciXmHHv/c/QZbTw9G7oggOj+yVee4D9f",
    "iGy0Dp2tqoSFcRyQ3DAdiuo45GxxG7vG47v+wNYilF8auhgQuLbhzXP5NohbnMU4IHROfWJZVG6+",
    "ovS9sqKx0nGn/hjMT71ABGzja8Nddzrf/zPnZ584GsIRhp6FWvMCgYEAtbyuDakMLPBHp2W4xHdP",
    "a0/tZ829ofISTvoaihlpEZN2mjR+A6SP7qTI4GppEXRasmALJ2owZf0KYuoBPXSQHOxc6GSElCNB",
    "1jJV+HYcSNwbUt+6QGa1bWZhLEudYHvn6B7G3zjmU2GsiNVja1FCWj6GlV/h4hcT8itiB2zaWr8C",
    "gYEAyBBP27JeIRT1sryve+kMkpalE9xB1w4lZ+gIC7iOErMlzcoRSKy/mlDK026s1syP11WGodZT",
    "hYHJ2AuMIGFtywbm5anLOLgaQIGs0FDk18nv9zH5i2Wt8C0OLKYZ0Mnxy7s+ooJ44f0f8K0AZgSP",
    "58pHz3RwU9YN6IIOF6j1q3sCgYBpbaq/S/k/PKkkyFMWzmwpQfXkiStgfnD2lgq9YJ5eTuC39onA",
    "DUBeXgQWhEStloVjA2qVE/o9wDy9QykzAKL11HzVaDKtSYLRAuRyvfoMnnvPaPDAmZTYgVMQAlGq",
    "/lZ7hxcxue2MI5aWzsvdHwfSGIG0uCnvIho1G8vDqPdHOwKBgHK9WaJSQivHTn5GgiMiSG0DNayj",
    "9I4BPWLgFea45OgnngBPSINRUBVMz6XULWMlHgt6JyHCa08DTCDzeRFcj/2L65YbgdiZIcO1ZWXv",
    "Jvv0c7fqoqqbGvBEvqBr5H1ksLyF3yOVNF/IWMumfZ0epzINQ1YG76Dwu0W2HweHt7os",
];

// ---------------------------------------------------------------------------
// Signing ID tokens
// ---------------------------------------------------------------------------

fn test_key() -> &'static CoreRsaPrivateSigningKey {
    static KEY: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let body = TEST_KEY_B64.concat();
        let armour = "PRIVATE KEY";
        let mut pem = format!("-----BEGIN RSA {armour}-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END RSA ");
        pem.push_str(armour);
        pem.push_str("-----\n");
        CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new(KID.to_owned()))).unwrap()
    })
}

/// Unpadded base64url (RFC 7515 §2).
fn b64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..=chunk.len() {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap();
            out.push(char::from(ALPHABET[idx]));
        }
    }
    out
}

#[test]
fn b64url_helper_matches_rfc4648_vectors() {
    assert_eq!(b64url(b""), "");
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
    assert_eq!(b64url(b"foob"), "Zm9vYg");
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
}

/// A compact RS256 JWT over `claims`, signed with the test key.
fn sign_jwt(claims: &Value) -> String {
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": KID});
    let signing_input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let sig = test_key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!("{signing_input}.{}", b64url(&sig))
}

/// Replaces the payload of `jwt` with `claims`, keeping the old signature.
fn tamper_jwt(jwt: &str, claims: &Value) -> String {
    let parts: Vec<&str> = jwt.split('.').collect();
    format!(
        "{}.{}.{}",
        parts[0],
        b64url(claims.to_string().as_bytes()),
        parts[2]
    )
}

/// Standard claims for `username` issued at `now` (seconds since the epoch).
fn claims_for(now: u64, username: &str, groups: &[&str]) -> Value {
    json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": format!("uid-{username}"),
        "iat": now,
        "exp": now + 600,
        "preferred_username": username,
        "groups": groups,
    })
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type Timeline = Rc<RefCell<Vec<String>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Info(String),
    ErrorMsg(String),
    Prompt(String),
}

/// Scripted conversation; running out of answers is a conversation failure.
struct FakeConv {
    answers: RefCell<VecDeque<String>>,
    events: RefCell<Vec<Ev>>,
    timeline: Timeline,
    fail_info: Cell<bool>,
    fail_prompt: Cell<bool>,
}

impl FakeConv {
    fn events(&self) -> Vec<Ev> {
        self.events.borrow().clone()
    }

    fn prompts(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Prompt(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    fn infos(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Info(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Everything shown to the user, as one string.
    fn screen(&self) -> String {
        self.events()
            .into_iter()
            .map(|e| match e {
                Ev::Info(s) | Ev::ErrorMsg(s) | Ev::Prompt(s) => s,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Conv for FakeConv {
    fn info(&self, msg: &str) -> Result<(), Error> {
        self.events.borrow_mut().push(Ev::Info(msg.to_owned()));
        self.timeline.borrow_mut().push(format!("info {msg}"));
        if self.fail_info.get() {
            Err(Error::Conv)
        } else {
            Ok(())
        }
    }

    fn error_msg(&self, msg: &str) -> Result<(), Error> {
        self.events.borrow_mut().push(Ev::ErrorMsg(msg.to_owned()));
        self.timeline.borrow_mut().push(format!("error {msg}"));
        Ok(())
    }

    fn prompt_echo_on(&self, prompt: &str) -> Result<String, Error> {
        self.events.borrow_mut().push(Ev::Prompt(prompt.to_owned()));
        self.timeline.borrow_mut().push(format!("prompt {prompt}"));
        if self.fail_prompt.get() {
            return Err(Error::Conv);
        }
        self.answers.borrow_mut().pop_front().ok_or(Error::Conv)
    }
}

struct FakeItems {
    user: Result<String, Error>,
    service: Option<String>,
    rhost: Option<String>,
}

impl FakeItems {
    fn new(service: Option<&str>) -> Self {
        Self {
            user: Ok("alice".to_owned()),
            service: service.map(str::to_owned),
            rhost: Some(RHOST.to_owned()),
        }
    }
}

impl PamItems for FakeItems {
    fn user(&self) -> Result<String, Error> {
        self.user.clone()
    }

    fn service(&self) -> Option<String> {
        self.service.clone()
    }

    fn rhost(&self) -> Option<String> {
        self.rhost.clone()
    }
}

/// Fake wall clock (whole seconds since the epoch), shared with the sleeper.
#[derive(Clone)]
struct FakeClock(Arc<AtomicU64>);

impl FakeClock {
    fn secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn advance(&self, d: Duration) {
        self.0.fetch_add(d.as_secs().max(1), Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.secs())
    }
}

/// Advances the fake clock instead of sleeping; panics on a runaway poll loop.
struct FakeSleeper {
    clock: FakeClock,
    calls: Cell<u32>,
}

impl Sleeper for FakeSleeper {
    fn sleep(&self, d: Duration) {
        self.calls.set(self.calls.get() + 1);
        assert!(self.calls.get() < 10_000, "runaway poll loop");
        self.clock.advance(d);
    }
}

struct FakeSecrets {
    value: Result<String, Error>,
    reads: RefCell<Vec<PathBuf>>,
}

impl SecretSource for FakeSecrets {
    fn read(&self, path: &Path) -> Result<SecretString, Error> {
        self.reads.borrow_mut().push(path.to_owned());
        self.value.clone().map(SecretString::from)
    }
}

#[derive(Default)]
struct FakeLogger {
    lines: RefCell<Vec<String>>,
}

impl Logger for FakeLogger {
    fn log(&self, msg: &str) {
        self.lines.borrow_mut().push(msg.to_owned());
    }
}

/// How the token endpoint answers one poll.
#[derive(Clone, Debug)]
enum TokenReply {
    Pending,
    SlowDown,
    Denied,
    ExpiredToken,
    Ok(String),
}

/// The fake identity provider behind the injected HTTP client.
struct FakeIdp {
    discovery: Value,
    discovery_status: u16,
    jwks: Value,
    device: Value,
    /// Replies in order; the last one repeats.
    token_script: VecDeque<TokenReply>,
    timeline: Timeline,
}

fn json_response(status: u16, body: &Value) -> HttpResponse {
    openidconnect::http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
        .unwrap()
}

impl FakeIdp {
    fn new(now: u64, timeline: Timeline) -> Self {
        let jwk = serde_json::to_value(test_key().as_verification_key()).unwrap();
        Self {
            discovery: json!({
                "issuer": ISSUER,
                "authorization_endpoint": format!("{HOST}/application/o/authorize/"),
                "token_endpoint": format!("{HOST}{TOKEN_PATH}"),
                "device_authorization_endpoint": format!("{HOST}{DEVICE_PATH}"),
                "jwks_uri": format!("{HOST}{JWKS_PATH}"),
                "response_types_supported": ["code", "id_token", "id_token token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "grant_types_supported": [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:device_code"
                ],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post"
                ],
                "scopes_supported": ["openid", "profile", "email"]
            }),
            discovery_status: 200,
            jwks: json!({ "keys": [jwk] }),
            device: json!({
                "device_code": DEVICE_CODE,
                "user_code": USER_CODE,
                "verification_uri": VERIFY_URI,
                "verification_uri_complete": VERIFY_URI_COMPLETE,
                "expires_in": 600,
                "interval": 5
            }),
            token_script: VecDeque::from([
                TokenReply::Pending,
                TokenReply::Ok(sign_jwt(&claims_for(now, "alice", &["users", "admins"]))),
            ]),
            timeline,
        }
    }

    fn handle(&mut self, req: &HttpRequest) -> HttpResponse {
        let path = req.uri().path().to_owned();
        self.timeline
            .borrow_mut()
            .push(format!("{} {path}", req.method()));
        match path.as_str() {
            DISCOVERY_PATH => json_response(self.discovery_status, &self.discovery),
            JWKS_PATH => json_response(200, &self.jwks),
            DEVICE_PATH => json_response(200, &self.device),
            TOKEN_PATH => {
                let reply = if self.token_script.len() > 1 {
                    self.token_script.pop_front().unwrap()
                } else {
                    self.token_script.front().cloned().unwrap()
                };
                match reply {
                    TokenReply::Pending => {
                        json_response(400, &json!({"error": "authorization_pending"}))
                    }
                    TokenReply::SlowDown => json_response(400, &json!({"error": "slow_down"})),
                    TokenReply::Denied => json_response(400, &json!({"error": "access_denied"})),
                    TokenReply::ExpiredToken => {
                        json_response(400, &json!({"error": "expired_token"}))
                    }
                    TokenReply::Ok(id_token) => json_response(
                        200,
                        &json!({
                            "access_token": ACCESS_TOKEN,
                            "token_type": "Bearer",
                            "expires_in": 300,
                            "scope": "openid profile",
                            "id_token": id_token
                        }),
                    ),
                }
            }
            _ => json_response(404, &json!({"error": "not_found"})),
        }
    }
}

/// What the HTTP factory hands out.
#[derive(Clone)]
enum HttpMode {
    /// A client backed by the fake `IdP`.
    Idp,
    /// A client whose every request fails at the transport level.
    Down,
    /// The factory itself fails (e.g. unreadable CA bundle).
    BuildFails(Error),
}

/// One authentication's worth of fakes.
struct Env {
    now: u64,
    timeline: Timeline,
    idp: Rc<RefCell<FakeIdp>>,
    http_mode: HttpMode,
    /// Every config the HTTP factory was called with. Shared via `Rc`
    /// because `HttpFactory` is `dyn Fn(..) + 'static`.
    factory_cfgs: Rc<RefCell<Vec<Config>>>,
    clock: FakeClock,
    sleeper: FakeSleeper,
    secrets: FakeSecrets,
    logger: FakeLogger,
}

impl Env {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timeline: Timeline = Rc::default();
        let clock = FakeClock(Arc::new(AtomicU64::new(now)));
        Self {
            now,
            idp: Rc::new(RefCell::new(FakeIdp::new(now, Rc::clone(&timeline)))),
            timeline,
            http_mode: HttpMode::Idp,
            factory_cfgs: Rc::default(),
            sleeper: FakeSleeper {
                clock: clock.clone(),
                calls: Cell::new(0),
            },
            clock,
            secrets: FakeSecrets {
                value: Ok(CLIENT_SECRET.to_owned()),
                reads: RefCell::default(),
            },
            logger: FakeLogger::default(),
        }
    }

    fn conv(&self, answers: &[&str]) -> FakeConv {
        FakeConv {
            answers: RefCell::new(answers.iter().map(|&a| a.to_owned()).collect()),
            events: RefCell::default(),
            timeline: Rc::clone(&self.timeline),
            fail_info: Cell::new(false),
            fail_prompt: Cell::new(false),
        }
    }

    /// Sets the token endpoint's replies.
    fn tokens(&self, script: Vec<TokenReply>) {
        self.idp.borrow_mut().token_script = script.into();
    }

    /// An ID token for `username` signed with the test key.
    fn id_token(&self, username: &str, groups: &[&str]) -> String {
        sign_jwt(&claims_for(self.now, username, groups))
    }

    fn run(&self, args: &[&str], conv: &FakeConv, items: &FakeItems) -> PamCode {
        let idp = Rc::clone(&self.idp);
        let cfgs = Rc::clone(&self.factory_cfgs);
        let mode = self.http_mode.clone();
        let factory = move |cfg: &Config| -> Result<HttpClientFn, Error> {
            cfgs.borrow_mut().push(cfg.clone());
            match &mode {
                HttpMode::Idp => {
                    let idp = Rc::clone(&idp);
                    Ok(Box::new(move |req: HttpRequest| {
                        Ok(idp.borrow_mut().handle(&req))
                    }))
                }
                HttpMode::Down => Ok(Box::new(|_req: HttpRequest| {
                    Err(HttpError::Network("connection refused".to_owned()))
                })),
                HttpMode::BuildFails(e) => Err(e.clone()),
            }
        };
        let deps = Deps {
            http: &factory,
            sleeper: &self.sleeper,
            clock: &self.clock,
            secrets: &self.secrets,
            logger: &self.logger,
        };
        authenticate(args, conv, items, &deps)
    }

    /// The single syslog line; fails unless exactly one was written.
    fn log_line(&self) -> String {
        let lines = self.logger.lines.borrow();
        assert_eq!(lines.len(), 1, "expected exactly one log line: {lines:?}");
        lines[0].clone()
    }

    fn requests(&self) -> Vec<String> {
        self.timeline
            .borrow()
            .iter()
            .filter(|l| l.starts_with("GET ") || l.starts_with("POST "))
            .cloned()
            .collect()
    }

    fn token_polls(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.ends_with(TOKEN_PATH))
            .count()
    }

    fn position(&self, pred: impl Fn(&str) -> bool) -> Option<usize> {
        self.timeline.borrow().iter().position(|l| pred(l))
    }
}

/// `issuer`, `client_id`, then `extra`.
fn args(extra: &[&'static str]) -> Vec<&'static str> {
    let mut v = vec![ISSUER_ARG, CLIENT_ARG];
    v.extend_from_slice(extra);
    v
}

fn expect_line(user: Option<&str>, method: Option<Method>, code: PamCode) -> String {
    auth_line(user, Some(RHOST), method, code)
}

/// Runs a single-method SSO login for `alice` on `service` and returns the code.
fn run_sso(env: &Env, extra: &[&'static str], service: Option<&str>, answers: &[&str]) -> PamCode {
    let mut a = args(&["methods=sso"]);
    a.extend_from_slice(extra);
    let conv = env.conv(answers);
    env.run(&a, &conv, &FakeItems::new(service))
}

// ---------------------------------------------------------------------------
// setcred
// ---------------------------------------------------------------------------

#[test]
fn setcred_is_success() {
    assert_eq!(setcred(), PamCode::Success);
}

// ---------------------------------------------------------------------------
// The password hand-off
// ---------------------------------------------------------------------------

#[test]
fn password_choice_is_ignore_without_network_or_secret() {
    let env = Env::new();
    let conv = env.conv(&["1"]);
    let code = env.run(&args(&[]), &conv, &FakeItems::new(Some("sshd")));
    assert_eq!(code, PamCode::Ignore);
    assert!(env.requests().is_empty(), "{:?}", env.requests());
    assert!(env.secrets.reads.borrow().is_empty());
    assert_eq!(conv.prompts().len(), 1, "only the menu prompt");
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Pass), PamCode::Ignore)
    );
}

#[test]
fn empty_answer_takes_the_default_password() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    let code = env.run(
        &args(&["methods=sso,password", "default=password"]),
        &conv,
        &FakeItems::new(Some("login")),
    );
    assert_eq!(code, PamCode::Ignore);
}

#[test]
fn password_only_skips_the_menu() {
    let env = Env::new();
    let conv = env.conv(&[]);
    let code = env.run(
        &args(&["methods=password"]),
        &conv,
        &FakeItems::new(Some("sshd")),
    );
    assert_eq!(code, PamCode::Ignore);
    assert!(conv.events().is_empty(), "{:?}", conv.events());
    assert!(env.requests().is_empty());
}

// ---------------------------------------------------------------------------
// SSO success
// ---------------------------------------------------------------------------

#[test]
fn sso_via_menu_succeeds() {
    let env = Env::new();
    let conv = env.conv(&["2"]);
    let code = env.run(&args(&[]), &conv, &FakeItems::new(Some("login")));
    assert_eq!(code, PamCode::Success);
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::Success)
    );
    assert_eq!(
        *env.secrets.reads.borrow(),
        vec![PathBuf::from(DEFAULT_SECRET_FILE)]
    );
    let cfgs = env.factory_cfgs.borrow();
    assert_eq!(cfgs.len(), 1, "one HTTP client per authentication");
    assert_eq!(cfgs[0].client_id, CLIENT_ID);
    assert!(env.token_polls() >= 2, "pending, then the token");
}

#[test]
fn sso_by_default_on_empty_answer() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    let code = env.run(
        &args(&["default=sso"]),
        &conv,
        &FakeItems::new(Some("login")),
    );
    assert_eq!(code, PamCode::Success);
}

#[test]
fn sso_only_skips_the_menu() {
    let env = Env::new();
    let conv = env.conv(&[]);
    assert_eq!(
        env.run(
            &args(&["methods=sso"]),
            &conv,
            &FakeItems::new(Some("login"))
        ),
        PamCode::Success
    );
    assert!(conv.prompts().is_empty(), "{:?}", conv.events());
}

#[test]
fn the_code_and_links_are_shown() {
    let env = Env::new();
    let conv = env.conv(&[]);
    let code = env.run(
        &args(&["methods=sso", "qr=off"]),
        &conv,
        &FakeItems::new(Some("login")),
    );
    assert_eq!(code, PamCode::Success);
    let screen = conv.screen();
    assert!(screen.contains(USER_CODE), "{screen}");
    assert!(screen.contains(VERIFY_URI_COMPLETE), "{screen}");
    let start = crate::oidc::DeviceStart {
        verification_uri: VERIFY_URI.to_owned(),
        verification_uri_complete: Some(VERIFY_URI_COMPLETE.to_owned()),
        user_code: USER_CODE.to_owned(),
        expires_in: Duration::from_secs(600),
    };
    assert_eq!(
        conv.infos(),
        crate::prompt::device_messages(&start, QrMode::Off)
    );
}

#[test]
fn nothing_secret_is_logged_or_shown() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    let code = run_sso_with_conv(&env, &conv, Some("sshd"));
    assert_eq!(code, PamCode::Success);
    let line = env.log_line();
    let screen = conv.screen();
    let id_token = env.id_token("alice", &["users", "admins"]);
    for secret in [
        CLIENT_SECRET,
        DEVICE_CODE,
        ACCESS_TOKEN,
        &id_token,
        "SECRET",
    ] {
        assert!(!line.contains(secret), "log leaks {secret}: {line}");
        assert!(!screen.contains(secret), "screen leaks {secret}: {screen}");
    }
    assert!(!line.contains(USER_CODE), "log has the user code: {line}");
}

fn run_sso_with_conv(env: &Env, conv: &FakeConv, service: Option<&str>) -> PamCode {
    env.run(&args(&["methods=sso"]), conv, &FakeItems::new(service))
}

#[test]
fn slow_down_is_handled() {
    let env = Env::new();
    env.tokens(vec![
        TokenReply::SlowDown,
        TokenReply::Pending,
        TokenReply::Ok(env.id_token("alice", &[])),
    ]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::Success);
    assert_eq!(env.token_polls(), 3);
    assert!(env.sleeper.calls.get() >= 2, "sleeps between polls");
}

#[test]
fn settings_reach_the_http_factory_and_secret_source() {
    let env = Env::new();
    let code = run_sso(
        &env,
        &[
            "timeout=7",
            "connect_timeout=3",
            "secret_file=/run/keys/sso",
        ],
        Some("login"),
        &[],
    );
    assert_eq!(code, PamCode::Success);
    let cfgs = env.factory_cfgs.borrow();
    assert_eq!(cfgs[0].timeout, Duration::from_secs(7));
    assert_eq!(cfgs[0].connect_timeout, Duration::from_secs(3));
    assert_eq!(
        *env.secrets.reads.borrow(),
        vec![PathBuf::from("/run/keys/sso")]
    );
}

#[test]
fn required_group_present_succeeds() {
    let env = Env::new();
    let code = run_sso(&env, &["require_group=wheel,admins"], Some("login"), &[]);
    assert_eq!(code, PamCode::Success);
}

// ---------------------------------------------------------------------------
// Wait mode: Enter prompt vs. polling
// ---------------------------------------------------------------------------

#[test]
fn sshd_waits_for_enter_before_polling() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    let code = run_sso_with_conv(&env, &conv, Some("sshd"));
    assert_eq!(code, PamCode::Success);
    assert_eq!(conv.prompts(), vec![ENTER_PROMPT.to_owned()]);
    let shown = env
        .position(|l| l.starts_with("info") && l.contains(USER_CODE))
        .expect("code shown");
    let prompted = env
        .position(|l| l == format!("prompt {ENTER_PROMPT}"))
        .expect("Enter prompt");
    let first_poll = env
        .position(|l| l.ends_with(TOKEN_PATH))
        .expect("token polled");
    assert!(shown < prompted, "code shown before the prompt");
    assert!(prompted < first_poll, "no polling before Enter");
}

#[test]
fn login_service_polls_without_a_prompt() {
    let env = Env::new();
    let conv = env.conv(&[]);
    assert_eq!(
        run_sso_with_conv(&env, &conv, Some("login")),
        PamCode::Success
    );
    assert!(conv.prompts().is_empty(), "{:?}", conv.events());
}

#[test]
fn unknown_service_polls_without_a_prompt() {
    let env = Env::new();
    let conv = env.conv(&[]);
    assert_eq!(run_sso_with_conv(&env, &conv, None), PamCode::Success);
    assert!(conv.prompts().is_empty());
}

#[test]
fn wait_enter_overrides_the_service() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    let code = env.run(
        &args(&["methods=sso", "wait=enter"]),
        &conv,
        &FakeItems::new(Some("login")),
    );
    assert_eq!(code, PamCode::Success);
    assert_eq!(conv.prompts(), vec![ENTER_PROMPT.to_owned()]);
}

#[test]
fn wait_poll_overrides_sshd() {
    let env = Env::new();
    let conv = env.conv(&[]);
    let code = env.run(
        &args(&["methods=sso", "wait=poll"]),
        &conv,
        &FakeItems::new(Some("sshd")),
    );
    assert_eq!(code, PamCode::Success);
    assert!(conv.prompts().is_empty());
}

#[test]
fn any_non_q_answer_at_the_enter_prompt_continues() {
    let env = Env::new();
    assert_eq!(run_sso(&env, &[], Some("sshd"), &["yes"]), PamCode::Success);
}

#[test]
fn q_at_the_enter_prompt_cancels_without_polling() {
    for answer in ["q", "Q", " q "] {
        let env = Env::new();
        let code = run_sso(&env, &[], Some("sshd"), &[answer]);
        assert_eq!(code, PamCode::MaxTries, "{answer:?}");
        assert_eq!(env.token_polls(), 0, "{answer:?}");
        assert_eq!(
            env.log_line(),
            expect_line(Some("alice"), Some(Method::Sso), PamCode::MaxTries)
        );
    }
}

// ---------------------------------------------------------------------------
// Denied, expired, deadline -> MAXTRIES
// ---------------------------------------------------------------------------

#[test]
fn denied_is_maxtries() {
    let env = Env::new();
    env.tokens(vec![TokenReply::Pending, TokenReply::Denied]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::MaxTries);
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::MaxTries)
    );
}

#[test]
fn expired_device_code_is_maxtries() {
    let env = Env::new();
    env.tokens(vec![TokenReply::ExpiredToken]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::MaxTries);
}

#[test]
fn max_wait_deadline_is_maxtries() {
    let env = Env::new();
    env.tokens(vec![TokenReply::Pending]);
    let start = env.clock.secs();
    assert_eq!(
        run_sso(&env, &["max_wait=30"], Some("login"), &[]),
        PamCode::MaxTries
    );
    let waited = env.clock.secs() - start;
    assert!(waited >= 25, "gave up too early: {waited}s");
    assert!(waited <= 60, "kept polling past max_wait: {waited}s");
}

#[test]
fn device_expires_in_bounds_the_wait() {
    let env = Env::new();
    env.idp.borrow_mut().device["expires_in"] = json!(20);
    env.tokens(vec![TokenReply::Pending]);
    let start = env.clock.secs();
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::MaxTries);
    assert!(env.clock.secs() - start <= 60, "ignored expires_in");
}

#[test]
fn bad_menu_input_is_maxtries() {
    let env = Env::new();
    let conv = env.conv(&["x", "7", "sso"]);
    let code = env.run(&args(&[]), &conv, &FakeItems::new(Some("sshd")));
    assert_eq!(code, PamCode::MaxTries);
    assert!(env.requests().is_empty());
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), None, PamCode::MaxTries)
    );
}

// ---------------------------------------------------------------------------
// Claim and token failures -> AUTH_ERR
// ---------------------------------------------------------------------------

#[test]
fn wrong_user_is_auth_err() {
    let env = Env::new();
    env.tokens(vec![TokenReply::Ok(env.id_token("mallory", &[]))]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::AuthErr);
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::AuthErr)
    );
}

#[test]
fn missing_required_group_is_auth_err() {
    let env = Env::new();
    env.tokens(vec![TokenReply::Ok(env.id_token("alice", &["users"]))]);
    assert_eq!(
        run_sso(&env, &["require_group=admins"], Some("login"), &[]),
        PamCode::AuthErr
    );
}

#[test]
fn tampered_id_token_is_auth_err() {
    let env = Env::new();
    let good = env.id_token("mallory", &[]);
    let forged = tamper_jwt(&good, &claims_for(env.now, "alice", &[]));
    env.tokens(vec![TokenReply::Ok(forged)]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::AuthErr);
}

#[test]
fn expired_id_token_is_auth_err() {
    let env = Env::new();
    let mut claims = claims_for(env.now - 7200, "alice", &[]);
    claims["exp"] = json!(env.now - 3600);
    env.tokens(vec![TokenReply::Ok(sign_jwt(&claims))]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::AuthErr);
}

#[test]
fn id_token_for_another_client_is_auth_err() {
    let env = Env::new();
    let mut claims = claims_for(env.now, "alice", &[]);
    claims["aud"] = json!("some-other-app");
    env.tokens(vec![TokenReply::Ok(sign_jwt(&claims))]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::AuthErr);
}

#[test]
fn id_token_from_another_issuer_is_auth_err() {
    let env = Env::new();
    let mut claims = claims_for(env.now, "alice", &[]);
    claims["iss"] = json!("https://idp.example.test/application/o/other/");
    env.tokens(vec![TokenReply::Ok(sign_jwt(&claims))]);
    assert_eq!(run_sso(&env, &[], Some("login"), &[]), PamCode::AuthErr);
}

// ---------------------------------------------------------------------------
// IdP, network, TLS and secret problems -> AUTHINFO_UNAVAIL
// ---------------------------------------------------------------------------

#[test]
fn idp_down_is_authinfo_unavail() {
    let mut env = Env::new();
    env.http_mode = HttpMode::Down;
    assert_eq!(
        run_sso(&env, &[], Some("login"), &[]),
        PamCode::AuthInfoUnavail
    );
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::AuthInfoUnavail)
    );
}

#[test]
fn http_client_build_failure_is_authinfo_unavail() {
    let mut env = Env::new();
    env.http_mode = HttpMode::BuildFails(Error::Tls("no certificate in ca_file".into()));
    assert_eq!(
        run_sso(&env, &[], Some("login"), &[]),
        PamCode::AuthInfoUnavail
    );
}

#[test]
fn discovery_error_status_is_authinfo_unavail() {
    let env = Env::new();
    env.idp.borrow_mut().discovery_status = 500;
    assert_eq!(
        run_sso(&env, &[], Some("login"), &[]),
        PamCode::AuthInfoUnavail
    );
}

#[test]
fn discovery_without_device_endpoint_is_authinfo_unavail() {
    let env = Env::new();
    env.idp
        .borrow_mut()
        .discovery
        .as_object_mut()
        .unwrap()
        .remove("device_authorization_endpoint");
    assert_eq!(
        run_sso(&env, &[], Some("login"), &[]),
        PamCode::AuthInfoUnavail
    );
}

#[test]
fn bad_device_authorization_response_is_authinfo_unavail() {
    let env = Env::new();
    env.idp.borrow_mut().device = json!({ "error": "invalid_client" });
    let conv = env.conv(&[""]);
    assert_eq!(
        run_sso_with_conv(&env, &conv, Some("login")),
        PamCode::AuthInfoUnavail
    );
    assert!(
        conv.infos().is_empty(),
        "no code shown without a device code"
    );
    assert_eq!(env.token_polls(), 0);
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::AuthInfoUnavail)
    );
}

#[test]
fn unreadable_secret_is_authinfo_unavail() {
    let mut env = Env::new();
    env.secrets.value = Err(Error::Secret("mode 0644".into()));
    assert_eq!(
        run_sso(&env, &[], Some("login"), &[]),
        PamCode::AuthInfoUnavail
    );
    assert_eq!(env.token_polls(), 0);
}

// ---------------------------------------------------------------------------
// Bad arguments -> SERVICE_ERR
// ---------------------------------------------------------------------------

fn assert_service_err(argv: &[&str]) {
    let env = Env::new();
    let conv = env.conv(&["2", ""]);
    let code = env.run(argv, &conv, &FakeItems::new(Some("sshd")));
    assert_eq!(code, PamCode::ServiceErr, "{argv:?}");
    assert!(
        conv.events().is_empty(),
        "no menu on bad arguments: {argv:?}"
    );
    assert!(env.factory_cfgs.borrow().is_empty(), "{argv:?}");
    assert!(env.requests().is_empty(), "{argv:?}");
    let line = env.log_line();
    assert!(
        line == expect_line(Some("alice"), None, PamCode::ServiceErr)
            || line == expect_line(None, None, PamCode::ServiceErr),
        "{line}"
    );
}

#[test]
fn unknown_key_is_service_err() {
    assert_service_err(&[ISSUER_ARG, CLIENT_ARG, "colour=blue"]);
}

#[test]
fn missing_issuer_is_service_err() {
    assert_service_err(&[CLIENT_ARG]);
}

#[test]
fn missing_client_id_is_service_err() {
    assert_service_err(&[ISSUER_ARG]);
}

#[test]
fn http_issuer_is_service_err() {
    assert_service_err(&[
        "issuer=http://idp.example.test/application/o/login/",
        CLIENT_ARG,
    ]);
}

#[test]
fn no_arguments_is_service_err() {
    assert_service_err(&[]);
}

// ---------------------------------------------------------------------------
// No user -> USER_UNKNOWN
// ---------------------------------------------------------------------------

#[test]
fn no_user_is_user_unknown() {
    let env = Env::new();
    let conv = env.conv(&["2"]);
    let mut items = FakeItems::new(Some("sshd"));
    items.user = Err(Error::UserUnknown);
    let code = env.run(&args(&[]), &conv, &items);
    assert_eq!(code, PamCode::UserUnknown);
    assert!(conv.events().is_empty(), "user is fetched before the menu");
    assert!(env.requests().is_empty());
    assert_eq!(
        env.log_line(),
        expect_line(None, None, PamCode::UserUnknown)
    );
}

#[test]
fn missing_rhost_is_logged_as_dash() {
    let env = Env::new();
    let conv = env.conv(&["1"]);
    let mut items = FakeItems::new(Some("login"));
    items.rhost = None;
    assert_eq!(env.run(&args(&[]), &conv, &items), PamCode::Ignore);
    assert_eq!(
        env.log_line(),
        auth_line(Some("alice"), None, Some(Method::Pass), PamCode::Ignore)
    );
}

// ---------------------------------------------------------------------------
// Conversation failures -> CONV_ERR
// ---------------------------------------------------------------------------

#[test]
fn menu_prompt_failure_is_conv_err() {
    let env = Env::new();
    let conv = env.conv(&["2"]);
    conv.fail_prompt.set(true);
    let code = env.run(&args(&[]), &conv, &FakeItems::new(Some("sshd")));
    assert_eq!(code, PamCode::ConvErr);
    assert!(env.requests().is_empty());
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), None, PamCode::ConvErr)
    );
}

#[test]
fn showing_the_code_fails_is_conv_err() {
    let env = Env::new();
    let conv = env.conv(&[""]);
    conv.fail_info.set(true);
    assert_eq!(
        run_sso_with_conv(&env, &conv, Some("login")),
        PamCode::ConvErr
    );
    assert_eq!(
        env.token_polls(),
        0,
        "no polling when the code was not shown"
    );
    assert_eq!(
        env.log_line(),
        expect_line(Some("alice"), Some(Method::Sso), PamCode::ConvErr)
    );
}

#[test]
fn enter_prompt_failure_is_conv_err() {
    let env = Env::new();
    let conv = env.conv(&[]);
    conv.fail_prompt.set(true);
    assert_eq!(
        run_sso_with_conv(&env, &conv, Some("sshd")),
        PamCode::ConvErr
    );
    assert_eq!(env.token_polls(), 0);
}

// ---------------------------------------------------------------------------
// Fixture self-checks: these pass against the stubs and make sure the red
// tests above fail because of the stubs, not because of a broken fake IdP.
// ---------------------------------------------------------------------------

fn token_json(env: &Env) -> Value {
    let reply = env.idp.borrow().token_script.back().cloned().unwrap();
    let TokenReply::Ok(id_token) = reply else {
        panic!("default script ends with a token");
    };
    json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token
    })
}

#[test]
fn fixture_documents_parse_as_the_oidc_types() {
    let env = Env::new();
    let idp = env.idp.borrow();
    let meta: crate::oidc::DeviceProviderMetadata =
        serde_json::from_value(idp.discovery.clone()).unwrap();
    assert_eq!(meta.issuer().as_str(), ISSUER);
    assert_eq!(
        meta.additional_metadata()
            .device_authorization_endpoint
            .as_str(),
        format!("{HOST}{DEVICE_PATH}")
    );
    let details: crate::oidc::DeviceDetails = serde_json::from_value(idp.device.clone()).unwrap();
    assert_eq!(details.user_code().secret(), USER_CODE);
    drop(idp);
    let _: crate::oidc::Tokens = serde_json::from_value(token_json(&env)).unwrap();
}

#[test]
fn fixture_id_token_verifies_with_openidconnect() {
    use openidconnect::core::CoreJsonWebKeySet;
    use openidconnect::{ClientId, IdTokenVerifier, IssuerUrl, Nonce, TokenResponse};

    let env = Env::new();
    let tokens: crate::oidc::Tokens = serde_json::from_value(token_json(&env)).unwrap();
    let jwks: CoreJsonWebKeySet = serde_json::from_value(env.idp.borrow().jwks.clone()).unwrap();
    let verifier = IdTokenVerifier::new_public_client(
        ClientId::new(CLIENT_ID.to_owned()),
        IssuerUrl::new(ISSUER.to_owned()).unwrap(),
        jwks,
    );
    let id_token = tokens.id_token().expect("id_token present");
    let claims = id_token
        .claims(&verifier, |_: Option<&Nonce>| Ok(()))
        .expect("fixture token verifies");
    // `preferred_username` is a standard claim (not in `ExtraClaims`);
    // `groups` is not, so it lands in `ExtraClaims::other`.
    assert_eq!(
        claims.preferred_username().map(|u| u.as_str()),
        Some("alice")
    );
    assert_eq!(
        claims.additional_claims().other["groups"],
        json!(["users", "admins"])
    );

    // And the tampered token does not.
    let forged = tamper_jwt(
        &env.id_token("mallory", &[]),
        &claims_for(env.now, "alice", &[]),
    );
    let forged: crate::oidc::Tokens = serde_json::from_value(json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "id_token": forged
    }))
    .unwrap();
    assert!(
        forged
            .id_token()
            .unwrap()
            .claims(&verifier, |_: Option<&Nonce>| Ok(()))
            .is_err()
    );
}
