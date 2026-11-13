//! Unit tests for `oidc`: discovery (device endpoint, https-same-host rule),
//! device start, token polling (with a fake clock and sleeper), ID-token
//! verification and claim checks.
//!
//! The `IdP` is a hand-written fake HTTP client (no network): every request
//! is recorded and answered from a per-URL queue of scripted replies.
#![allow(
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::doc_markdown
)]

#[allow(unused_imports)]
use super::*;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::core::{CoreHmacKey, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::url::Url;
use openidconnect::{
    DeviceAuthorizationUrl, HttpRequest, HttpResponse, JsonWebKeyId, PrivateSigningKey,
};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::args::Config;
use crate::error::Error;
use crate::http::HttpError;
use crate::time::{Clock, Sleeper};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ISSUER: &str = "https://idp.test/application/o/login/";
const DISCOVERY_URL: &str = "https://idp.test/application/o/login/.well-known/openid-configuration";
const JWKS_URL: &str = "https://idp.test/application/o/login/jwks/";
const DEVICE_URL: &str = "https://idp.test/application/o/device/";
const TOKEN_URL: &str = "https://idp.test/application/o/token/";
const CLIENT_ID: &str = "pam-login";
const CLIENT_SECRET: &str = "client-s3cret-value";
const DEVICE_CODE: &str = "dev-code-123";
const USER_CODE: &str = "WDJB-MJHT";
/// Fake "now": 2027-01-15, after the real date these tests were written, so a
/// verifier or poller that reads the real clock instead of the injected one
/// sees `iat` in the future (and the token expired in the past would not be).
const T0: u64 = 1_800_000_000;

/// Test-only RSA key (2048 bit, PKCS#1). Never used outside these tests.
const KEY1_PEM: &str = concat!(
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
/// A second test-only RSA key, not in the JWKS.
const KEY2_PEM: &str = concat!(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEowIBAAKCAQEAveE9OEH53ru75u4tS35RMYhWNKtTeKAaumRy3l1EePJl3oY+\n",
    "T8bmZTd/8tPaBIKPYsGsVSpjP0IZp6uziMU+3V1C4DlWLLoNJtCYJJbsTHdWBf5o\n",
    "vKEA22SATl5+CSRdvAh0wzAK45U6ELG5bjEPranMxvjxwt7ggiOpKCDBXrNhpNRH\n",
    "OVRcFgUlm8HuxyS+5Xu35atwjyMkxl1EqVKYqGvJ/78TxwFFbeohkAUwZ0uQHCFg\n",
    "x+aY53pnzvGDjQN2b1WEm3vtm+NTtZEcyDjq5sTsyiNILTOy3p4fhci0WCx8M++3\n",
    "0TmotW5rBr9E0HJ6d/WYUziM4dkeG7rb0efwwwIDAQABAoIBAFKgXZoKB7gXXIyA\n",
    "r4Au/xj9WXoA5clTbl4W0O+XiXDSFmcvZpUjmeWIsapS6wfUYp3YZmwHDnocAvr2\n",
    "GiGVp6X/a9cTzD6ZVZjC47nkXP5nXa0tCJmwvCU8RiMUNmc3Bn0I9vprAQoIyWQz\n",
    "WlwriEWLYrtg4B9rCipHZ1g5bLwOtWEdj/SuEObFrvs5N0FLVdYviBZL2EmU5h6M\n",
    "Zkeb1MuiLXYeubx8H4nMX1hwneBiMaqtqtRR6U0upu2zSKQ8Q50bz0zUSKlHuySq\n",
    "Q9NxSs6H5ELXIfruT6knV2AEbkyypf7+IdAbPAVlN9wV6aH3pHDeFneaZ4Zv0+xG\n",
    "6LmGg7ECgYEA8hpJf4XMr7WtxPGPKsmkuTaYPdHqS+PPX66Z3CjQDR8IUKm8dtTN\n",
    "35WTVcCpXNozn7Jma0AHa8+0rTNBVeaqHSqWteqDaU+D95n/3IWr1tpH9SvWm/Oy\n",
    "QfF7YIZc+SW3JsMYqq9zeQNCHBk7KtVpBUqFLoXpGCS+keYHL83G+fMCgYEAyMeI\n",
    "yobZPkU8UdvVMqiUkrE93C8tveMzWVei58btFcXImEe9fD8wqgu0QUjKVtx8ltBd\n",
    "uAJw5ayIkxzAlH2JoYAIPK5BLHhtIEr4JCb7mKmARupy/t8z3mavCqP8k0W7S72C\n",
    "HuPaWwwl7r/c6Okz0JT5rSkxGtkgJVh7uZ7skfECgYAN8RGWdGALJk0xcC+saRxB\n",
    "RjGSLcpuQFoqymU11mvUtZrG+l9OAIcyfuyTHZsjK7WZVq6rMm66+KUQ7Eiw562Y\n",
    "LGGtbCnRILEayxV+33u7zaojJjkflfMH9R4DuvkTp+ZaJxX+jkf6CgP+lj1gBBYe\n",
    "JeJxgWig6UzIHhT/3bu9nQKBgQCQtZe2+NgtFHO0QDB6UZy72blPMEXUnaON2icU\n",
    "zIBmd+XrM5Gzskud08+4WgFT95hojodtr3y1XNQWy9tVauG+n+vP6Hwa1DU62C3e\n",
    "yKX/0vMcqa/2WOMmgXXZwnWxo8mpfk4Be5IOm0PfvzM2P5ZT2HvXvV+iDSopIIwU\n",
    "LiIt0QKBgA6+73U77TF0sWyoPsWQHYlSCCYrPteSY6XIsK0dLGrdcfiFJ5H3CzKB\n",
    "ddS8f7hEVSxMnE5NARPNYMVPp6pTuubZGwTufLlrqpPM105lHzV/AEhfQl1iVe98\n",
    "CwHIue8dDZnaSVFdnljnEcjWnVwEbuWUTur7YeelAJTgQXVCxBjc\n",
    "-----END RSA PRIVATE KEY-----\n",
);

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(T0)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn cfg() -> Config {
    Config::new(Url::parse(ISSUER).unwrap(), CLIENT_ID)
}

fn secret() -> SecretString {
    SecretString::from(CLIENT_SECRET)
}

// ---------------------------------------------------------------------------
// Fake clock and sleeper
// ---------------------------------------------------------------------------

/// A settable clock (`Mutex` because `Clock: Send + Sync`).
struct FakeClock {
    now: Mutex<SystemTime>,
}

impl FakeClock {
    fn at(t: SystemTime) -> Self {
        Self { now: Mutex::new(t) }
    }

    fn advance(&self, d: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += d;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().unwrap()
    }
}

/// Records each sleep and advances the fake clock by it instead of sleeping.
/// Panics (fails the test) instead of looping forever if the code under test
/// ignores the deadline.
struct FakeSleeper<'a> {
    clock: &'a FakeClock,
    sleeps: RefCell<Vec<Duration>>,
}

impl<'a> FakeSleeper<'a> {
    fn new(clock: &'a FakeClock) -> Self {
        Self {
            clock,
            sleeps: RefCell::new(Vec::new()),
        }
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.borrow().clone()
    }

    fn total(&self) -> Duration {
        self.sleeps.borrow().iter().sum()
    }
}

impl Sleeper for FakeSleeper<'_> {
    fn sleep(&self, d: Duration) {
        self.sleeps.borrow_mut().push(d);
        self.clock.advance(d);
        assert!(
            self.total() < secs(100_000),
            "slept more than 100000 s of fake time: the deadline is ignored"
        );
    }
}

// ---------------------------------------------------------------------------
// Fake IdP (HTTP client)
// ---------------------------------------------------------------------------

/// One scripted answer.
#[derive(Clone)]
enum Reply {
    /// Status + JSON body (`application/json`).
    Json(u16, Value),
    /// Status + content type + raw body.
    Raw(u16, &'static str, &'static str),
    /// Transport failure.
    Fail(HttpError),
}

/// A recorded request.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// Answers by exact URL from a queue; the last reply of a queue repeats.
/// Unknown URLs get a 404. Panics after 5000 requests (runaway poll loop).
///
/// Cloning shares the state (an `Rc`): `Sso::http` is a `&DynHttpClient`,
/// whose trait object is `'static`, so the client closure must own its fake.
#[derive(Clone, Default)]
struct FakeIdp(Rc<IdpState>);

#[derive(Default)]
struct IdpState {
    routes: RefCell<HashMap<String, VecDeque<Reply>>>,
    seen: RefCell<Vec<Seen>>,
}

impl std::ops::Deref for FakeIdp {
    type Target = IdpState;
    fn deref(&self) -> &IdpState {
        &self.0
    }
}

impl FakeIdp {
    /// The HTTP client closure handed to `Sso`.
    fn client(&self) -> impl Fn(HttpRequest) -> Result<HttpResponse, HttpError> + 'static {
        let idp = self.clone();
        move |r| idp.handle(r)
    }

    fn on(&self, url: &str, reply: Reply) -> &Self {
        self.routes
            .borrow_mut()
            .entry(url.to_owned())
            .or_default()
            .push_back(reply);
        self
    }

    fn handle(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        let uri = req.uri().to_string();
        let seen = Seen {
            method: req.method().to_string(),
            uri: uri.clone(),
            headers: req
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body: String::from_utf8_lossy(req.body()).into_owned(),
        };
        self.seen.borrow_mut().push(seen);
        assert!(self.seen.borrow().len() < 5000, "runaway request loop");

        let reply = {
            let mut routes = self.routes.borrow_mut();
            match routes.get_mut(&uri) {
                Some(q) if q.len() > 1 => q.pop_front().unwrap(),
                Some(q) if q.len() == 1 => q.front().unwrap().clone(),
                _ => Reply::Raw(404, "text/plain", "not found"),
            }
        };
        match reply {
            Reply::Json(status, v) => Ok(response(status, "application/json", v.to_string())),
            Reply::Raw(status, ct, body) => Ok(response(status, ct, body.to_owned())),
            Reply::Fail(e) => Err(e),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.borrow().clone()
    }

    fn count(&self, url: &str) -> usize {
        self.seen.borrow().iter().filter(|s| s.uri == url).count()
    }

    fn count_host(&self, host: &str) -> usize {
        self.seen
            .borrow()
            .iter()
            .filter(|s| Url::parse(&s.uri).is_ok_and(|u| u.host_str() == Some(host)))
            .count()
    }
}

fn response(status: u16, content_type: &str, body: String) -> HttpResponse {
    ::http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(body.into_bytes())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Discovery document, JWKS, provider
// ---------------------------------------------------------------------------

fn discovery_doc() -> Value {
    json!({
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.test/application/o/authorize/",
        "token_endpoint": TOKEN_URL,
        "userinfo_endpoint": "https://idp.test/application/o/userinfo/",
        "jwks_uri": JWKS_URL,
        "device_authorization_endpoint": DEVICE_URL,
        "response_types_supported": ["code", "id_token", "id_token token", "code token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "preferred_username", "groups"]
    })
}

fn doc_with(field: &str, value: Value) -> Value {
    let mut d = discovery_doc();
    d[field] = value;
    d
}

fn doc_without(field: &str) -> Value {
    let mut d = discovery_doc();
    d.as_object_mut().unwrap().remove(field);
    d
}

fn key1() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY1_PEM, Some(JsonWebKeyId::new("k1".to_owned()))).unwrap()
}

fn key2() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY2_PEM, Some(JsonWebKeyId::new("k1".to_owned()))).unwrap()
}

fn jwks() -> Value {
    json!({ "keys": [serde_json::to_value(key1().as_verification_key()).unwrap()] })
}

/// A fake IdP serving a good discovery document and JWKS.
fn idp_with_doc(doc: Value) -> FakeIdp {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Json(200, doc));
    idp.on(JWKS_URL, Reply::Json(200, jwks()));
    idp
}

/// A provider built directly (not through `discover`), so that the device,
/// token and verification tests do not depend on discovery.
fn provider() -> Provider {
    let metadata: DeviceProviderMetadata = serde_json::from_value(discovery_doc()).unwrap();
    let metadata = metadata.set_jwks(serde_json::from_value(jwks()).unwrap());
    Provider {
        metadata,
        device_endpoint: DeviceAuthorizationUrl::new(DEVICE_URL.to_owned()).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// JWT helpers
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

fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    )
}

fn jwt_with_key(key: &CoreRsaPrivateSigningKey, kid: &str, claims: &Value) -> String {
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let input = signing_input(&header, claims);
    let sig = key
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    format!("{input}.{}", b64url(&sig))
}

/// A correctly signed RS256 token (key `k1`).
fn jwt(claims: &Value) -> String {
    jwt_with_key(&key1(), "k1", claims)
}

/// The claims of a good token for `alice`, issued at the fake `T0`.
fn good_claims() -> Value {
    json!({
        "iss": ISSUER,
        "sub": "8f2c1e",
        "aud": CLIENT_ID,
        "exp": T0 + 300,
        "iat": T0,
        "preferred_username": "alice",
        "groups": ["users", "admins"]
    })
}

fn claims_with(field: &str, value: Value) -> Value {
    let mut c = good_claims();
    c[field] = value;
    c
}

fn claims_without(field: &str) -> Value {
    let mut c = good_claims();
    c.as_object_mut().unwrap().remove(field);
    c
}

fn token_json(id_token: Option<&str>) -> Value {
    let mut v = json!({
        "access_token": "at-opaque-1",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "openid profile"
    });
    if let Some(t) = id_token {
        v["id_token"] = json!(t);
    }
    v
}

fn tokens(id_token: &str) -> Tokens {
    serde_json::from_value(token_json(Some(id_token))).unwrap()
}

/// Runs `verify_id_token` at the fake time `T0` with `cfg`.
fn verify_with(cfg: &Config, id_token: &str) -> Result<Claims, Error> {
    let idp = FakeIdp::default();
    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let sso = Sso {
        cfg,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let out = sso.verify_id_token(&provider(), &tokens(id_token));
    assert!(
        idp.seen().is_empty(),
        "ID-token verification must use the discovered JWKS, not the network"
    );
    out
}

fn verify(id_token: &str) -> Result<Claims, Error> {
    verify_with(&cfg(), id_token)
}

fn assert_token_err(r: Result<Claims, Error>) {
    assert!(
        matches!(r, Err(Error::Token(_))),
        "expected Error::Token, got {r:?}"
    );
}

fn assert_claim_err<T: std::fmt::Debug>(r: Result<T, Error>) {
    assert!(
        matches!(r, Err(Error::Claim(_))),
        "expected Error::Claim, got {r:?}"
    );
}

fn assert_idp_err<T: std::fmt::Debug>(r: Result<T, Error>) {
    assert!(
        matches!(r, Err(Error::Idp(_))),
        "expected Error::Idp, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

fn discover_with(cfg: &Config, idp: &FakeIdp) -> Result<Provider, Error> {
    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let sso = Sso {
        cfg,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    sso.discover()
}

#[test]
fn discover_reads_metadata_device_endpoint_and_jwks() {
    let idp = idp_with_doc(discovery_doc());
    let p = discover_with(&cfg(), &idp).unwrap();

    assert_eq!(p.device_endpoint.as_str(), DEVICE_URL);
    assert_eq!(
        p.metadata
            .additional_metadata()
            .device_authorization_endpoint
            .as_str(),
        DEVICE_URL
    );
    assert_eq!(p.metadata.issuer().as_str(), ISSUER);
    assert_eq!(p.metadata.token_endpoint().unwrap().as_str(), TOKEN_URL);
    assert_eq!(p.metadata.jwks().keys().len(), 1);

    let seen = idp.seen();
    assert_eq!(seen.len(), 2, "exactly discovery + JWKS: {seen:?}");
    assert!(seen.iter().all(|s| s.method == "GET"));
    assert_eq!(idp.count(DISCOVERY_URL), 1);
    assert_eq!(idp.count(JWKS_URL), 1);
}

#[test]
fn discover_uses_configured_device_endpoint_override() {
    let mut c = cfg();
    c.device_endpoint = Some(Url::parse("https://idp.test/custom/device/").unwrap());
    let idp = idp_with_doc(discovery_doc());
    let p = discover_with(&c, &idp).unwrap();
    assert_eq!(
        p.device_endpoint.as_str(),
        "https://idp.test/custom/device/"
    );
}

#[test]
fn discover_override_works_when_discovery_lacks_device_endpoint() {
    let mut c = cfg();
    c.device_endpoint = Some(Url::parse("https://idp.test/custom/device/").unwrap());
    let idp = idp_with_doc(doc_without("device_authorization_endpoint"));
    let p = discover_with(&c, &idp).unwrap();
    assert_eq!(
        p.device_endpoint.as_str(),
        "https://idp.test/custom/device/"
    );
}

#[test]
fn discover_without_device_endpoint_is_idp_error() {
    let idp = idp_with_doc(doc_without("device_authorization_endpoint"));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_without_token_endpoint_is_idp_error() {
    let idp = idp_with_doc(doc_without("token_endpoint"));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_issuer_mismatch() {
    let idp = idp_with_doc(doc_with(
        "issuer",
        json!("https://idp.test/application/o/other/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_device_endpoint_on_other_host() {
    let idp = idp_with_doc(doc_with(
        "device_authorization_endpoint",
        json!("https://evil.test/application/o/device/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
    assert_eq!(idp.count_host("evil.test"), 0);
}

#[test]
fn discover_rejects_device_endpoint_over_http() {
    let idp = idp_with_doc(doc_with(
        "device_authorization_endpoint",
        json!("http://idp.test/application/o/device/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_device_endpoint_on_other_port() {
    let idp = idp_with_doc(doc_with(
        "device_authorization_endpoint",
        json!("https://idp.test:8443/application/o/device/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_token_endpoint_on_other_host() {
    let idp = idp_with_doc(doc_with(
        "token_endpoint",
        json!("https://evil.test/application/o/token/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_token_endpoint_over_http() {
    let idp = idp_with_doc(doc_with(
        "token_endpoint",
        json!("http://idp.test/application/o/token/"),
    ));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_rejects_jwks_on_other_host_without_fetching_it() {
    let evil_jwks = "https://evil.test/application/o/login/jwks/";
    let idp = idp_with_doc(doc_with("jwks_uri", json!(evil_jwks)));
    // Serve a valid JWKS there, so that only the host rule can reject it.
    idp.on(evil_jwks, Reply::Json(200, jwks()));
    assert_idp_err(discover_with(&cfg(), &idp));
    assert_eq!(
        idp.count_host("evil.test"),
        0,
        "must not contact a host other than the issuer's"
    );
}

#[test]
fn discover_rejects_jwks_over_http() {
    let plain = "http://idp.test/application/o/login/jwks/";
    let idp = idp_with_doc(doc_with("jwks_uri", json!(plain)));
    idp.on(plain, Reply::Json(200, jwks()));
    assert_idp_err(discover_with(&cfg(), &idp));
    assert_eq!(idp.count(plain), 0);
}

#[test]
fn discover_rejects_device_endpoint_override_on_other_host() {
    let mut c = cfg();
    c.device_endpoint = Some(Url::parse("https://evil.test/device/").unwrap());
    let idp = idp_with_doc(discovery_doc());
    assert_idp_err(discover_with(&c, &idp));
}

#[test]
fn discover_rejects_device_endpoint_override_over_http() {
    let mut c = cfg();
    c.device_endpoint = Some(Url::parse("http://idp.test/custom/device/").unwrap());
    let idp = idp_with_doc(discovery_doc());
    assert_idp_err(discover_with(&c, &idp));
}

#[test]
fn discover_http_error_status_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Raw(500, "text/html", "<h1>oops</h1>"));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_malformed_document_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(
        DISCOVERY_URL,
        Reply::Raw(200, "application/json", "{not json"),
    );
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_jwks_http_error_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Json(200, discovery_doc()));
    idp.on(JWKS_URL, Reply::Raw(503, "text/plain", "unavailable"));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_malformed_jwks_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Json(200, discovery_doc()));
    idp.on(JWKS_URL, Reply::Raw(200, "application/json", "[]"));
    assert_idp_err(discover_with(&cfg(), &idp));
}

#[test]
fn discover_maps_tls_failure_to_tls_error() {
    let idp = FakeIdp::default();
    idp.on(
        DISCOVERY_URL,
        Reply::Fail(HttpError::Tls("unknown issuer".to_owned())),
    );
    let r = discover_with(&cfg(), &idp);
    assert!(matches!(r, Err(Error::Tls(_))), "{r:?}");
}

#[test]
fn discover_maps_network_failure_to_network_error() {
    let idp = FakeIdp::default();
    idp.on(
        DISCOVERY_URL,
        Reply::Fail(HttpError::Network("connection refused".to_owned())),
    );
    let r = discover_with(&cfg(), &idp);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

#[test]
fn discover_maps_jwks_transport_failure() {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Json(200, discovery_doc()));
    idp.on(
        JWKS_URL,
        Reply::Fail(HttpError::Network("timed out".to_owned())),
    );
    let r = discover_with(&cfg(), &idp);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

#[test]
fn discover_maps_oversized_body_to_network_error() {
    let idp = FakeIdp::default();
    idp.on(DISCOVERY_URL, Reply::Fail(HttpError::TooLarge));
    let r = discover_with(&cfg(), &idp);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

// ---------------------------------------------------------------------------
// Device authorization (start)
// ---------------------------------------------------------------------------

fn device_json(complete: bool, expires_in: u64, interval: u64) -> Value {
    let mut v = json!({
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": "https://idp.test/device",
        "expires_in": expires_in,
        "interval": interval
    });
    if complete {
        v["verification_uri_complete"] = json!(format!("https://idp.test/device?code={USER_CODE}"));
    }
    v
}

fn start_with(
    cfg: &Config,
    provider: &Provider,
    idp: &FakeIdp,
    clock: &FakeClock,
) -> Result<(DeviceStart, DeviceSession), Error> {
    let client = idp.client();
    let sleeper = FakeSleeper::new(clock);
    let sso = Sso {
        cfg,
        http: &client,
        clock,
        sleeper: &sleeper,
    };
    let out = sso.start_device(provider, &secret());
    assert!(sleeper.sleeps().is_empty(), "start_device must not sleep");
    out
}

fn start(idp: &FakeIdp) -> Result<(DeviceStart, DeviceSession), Error> {
    start_with(&cfg(), &provider(), idp, &FakeClock::at(t0()))
}

/// The client must authenticate with its secret: either HTTP Basic or `client_secret` in the form.
fn assert_client_authenticated(s: &Seen) {
    let basic = s
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.starts_with("Basic "));
    let post = s.body.contains(&format!("client_secret={CLIENT_SECRET}"));
    assert!(basic || post, "client secret not sent: {s:?}");
}

#[test]
fn start_device_parses_response_with_complete_uri() {
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 5)));
    let (start, session) = start(&idp).unwrap();

    assert_eq!(
        start,
        DeviceStart {
            verification_uri: "https://idp.test/device".to_owned(),
            verification_uri_complete: Some(format!("https://idp.test/device?code={USER_CODE}")),
            user_code: USER_CODE.to_owned(),
            expires_in: secs(1800),
        }
    );
    assert_eq!(session.details.device_code().secret(), DEVICE_CODE);
    assert_eq!(session.details.interval(), secs(5));

    let seen = idp.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].uri, DEVICE_URL);
    assert!(
        seen[0].body.contains("scope=openid+profile")
            || seen[0].body.contains("scope=openid%20profile"),
        "default scopes not requested: {:?}",
        seen[0].body
    );
    assert_client_authenticated(&seen[0]);
}

#[test]
fn start_device_without_complete_uri() {
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(false, 1800, 5)));
    let (start, _session) = start(&idp).unwrap();
    assert_eq!(start.verification_uri, "https://idp.test/device");
    assert_eq!(start.verification_uri_complete, None);
    assert_eq!(start.user_code, USER_CODE);
}

#[test]
fn start_device_deadline_is_max_wait_when_shorter() {
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 5)));
    // Default max_wait is 600 s < 1800 s.
    let (_, session) = start(&idp).unwrap();
    assert_eq!(session.deadline, t0() + secs(600));
}

#[test]
fn start_device_deadline_is_expires_in_when_shorter() {
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 120, 5)));
    let (start, session) = start(&idp).unwrap();
    assert_eq!(start.expires_in, secs(120));
    assert_eq!(session.deadline, t0() + secs(120));
}

#[test]
fn start_device_deadline_uses_configured_max_wait_and_clock() {
    let mut c = cfg();
    c.max_wait = secs(30);
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 5)));
    let clock = FakeClock::at(t0() + secs(1000));
    let (_, session) = start_with(&c, &provider(), &idp, &clock).unwrap();
    assert_eq!(session.deadline, t0() + secs(1030));
}

#[test]
fn start_device_posts_to_provider_device_endpoint() {
    let custom = "https://idp.test/custom/device/";
    let mut p = provider();
    p.device_endpoint = DeviceAuthorizationUrl::new(custom.to_owned()).unwrap();
    let idp = FakeIdp::default();
    idp.on(custom, Reply::Json(200, device_json(true, 1800, 5)));
    start_with(&cfg(), &p, &idp, &FakeClock::at(t0())).unwrap();
    assert_eq!(idp.count(custom), 1);
    assert_eq!(idp.count(DEVICE_URL), 0);
}

#[test]
fn start_device_requests_configured_scopes() {
    let mut c = cfg();
    c.scopes = vec!["openid".to_owned(), "groups".to_owned()];
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 5)));
    start_with(&c, &provider(), &idp, &FakeClock::at(t0())).unwrap();
    let body = &idp.seen()[0].body;
    assert!(
        body.contains("scope=openid+groups") || body.contains("scope=openid%20groups"),
        "{body:?}"
    );
}

#[test]
fn start_device_error_response_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Json(400, json!({ "error": "invalid_client" })),
    );
    let r = start(&idp);
    assert_idp_err(r);
}

#[test]
fn start_device_malformed_response_is_idp_error() {
    let mut v = device_json(true, 1800, 5);
    v.as_object_mut().unwrap().remove("user_code");
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, v));
    assert_idp_err(start(&idp));
}

#[test]
fn start_device_rejects_plain_http_verification_uri() {
    let mut v = device_json(false, 1800, 5);
    v["verification_uri"] = json!("http://idp.test/device");
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, v));
    assert_idp_err(start(&idp));
}

#[test]
fn start_device_rejects_plain_http_verification_uri_complete() {
    let mut v = device_json(true, 1800, 5);
    v["verification_uri_complete"] = json!("http://idp.test/device?code=X");
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, v));
    assert_idp_err(start(&idp));
}

#[test]
fn start_device_maps_transport_errors() {
    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Fail(HttpError::Tls("bad cert".to_owned())),
    );
    let r = start(&idp);
    assert!(matches!(r, Err(Error::Tls(_))), "{r:?}");

    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Fail(HttpError::Network("reset".to_owned())),
    );
    let r = start(&idp);
    assert!(matches!(r, Err(Error::Network(_))), "{r:?}");
}

#[test]
fn start_device_errors_never_leak_the_client_secret() {
    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Json(
            401,
            json!({ "error": "invalid_client", "error_description": CLIENT_SECRET }),
        ),
    );
    let err = start(&idp).unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(CLIENT_SECRET), "{shown}");
}

// ---------------------------------------------------------------------------
// Polling for the token
// ---------------------------------------------------------------------------

fn session(interval: u64, expires_in: u64, deadline: SystemTime) -> DeviceSession {
    let details: DeviceDetails =
        serde_json::from_value(device_json(true, expires_in, interval)).unwrap();
    DeviceSession { details, deadline }
}

fn pending() -> Reply {
    Reply::Json(400, json!({ "error": "authorization_pending" }))
}

fn slow_down() -> Reply {
    Reply::Json(400, json!({ "error": "slow_down" }))
}

fn success() -> Reply {
    Reply::Json(200, token_json(Some(&jwt(&good_claims()))))
}

struct PollRun {
    result: Result<Tokens, Error>,
    sleeps: Vec<Duration>,
}

fn poll_with(cfg: &Config, idp: &FakeIdp, s: &DeviceSession) -> PollRun {
    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let sso = Sso {
        cfg,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let result = sso.wait_for_token(&provider(), &secret(), s);
    PollRun {
        result,
        sleeps: sleeper.sleeps(),
    }
}

fn poll(idp: &FakeIdp, s: &DeviceSession) -> PollRun {
    poll_with(&cfg(), idp, s)
}

#[test]
fn poll_pending_then_success() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(3, 1800, t0() + secs(600)));

    let tokens = run.result.unwrap();
    assert_eq!(
        openidconnect::OAuth2TokenResponse::access_token(&tokens).secret(),
        "at-opaque-1"
    );
    assert!(
        openidconnect::TokenResponse::id_token(&tokens).is_some(),
        "ID token missing"
    );
    assert_eq!(run.sleeps, vec![secs(3)]);

    let seen = idp.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for s in &seen {
        assert_eq!(s.method, "POST");
        assert_eq!(s.uri, TOKEN_URL);
        assert!(
            s.body
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"),
            "{:?}",
            s.body
        );
        assert!(
            s.body.contains(&format!("device_code={DEVICE_CODE}")),
            "{:?}",
            s.body
        );
        assert_client_authenticated(s);
    }
}

#[test]
fn poll_immediate_success_does_not_sleep() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert!(run.sleeps.is_empty());
}

#[test]
fn poll_slow_down_adds_five_seconds_each_time() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, slow_down());
    idp.on(TOKEN_URL, slow_down());
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(3, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(run.sleeps, vec![secs(8), secs(13), secs(13)]);
}

#[test]
fn poll_access_denied_is_denied() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    idp.on(
        TOKEN_URL,
        Reply::Json(400, json!({ "error": "access_denied" })),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert_eq!(run.result.err(), Some(Error::Denied));
    assert_eq!(run.sleeps, vec![secs(5)]);
}

#[test]
fn poll_expired_token_is_expired() {
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Json(400, json!({ "error": "expired_token" })),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert_eq!(run.result.err(), Some(Error::Expired));
}

#[test]
fn poll_other_error_response_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Json(400, json!({ "error": "invalid_grant" })),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert_idp_err(run.result);
}

#[test]
fn poll_garbage_response_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Raw(200, "text/html", "<html>login</html>"),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert_idp_err(run.result);
}

#[test]
fn poll_success_without_id_token_is_idp_error() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, Reply::Json(200, token_json(None)));
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert_idp_err(run.result);
}

#[test]
fn poll_stops_at_our_deadline_before_the_device_code_expires() {
    // The device code is valid for 1800 s, but our deadline is 30 s away:
    // polling must stop at about 30 s of (fake) time with Expired.
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    let run = poll(&idp, &session(5, 1800, t0() + secs(30)));
    assert_eq!(run.result.err(), Some(Error::Expired));
    let total: Duration = run.sleeps.iter().sum();
    assert!(
        total >= secs(25) && total <= secs(35),
        "polled for {total:?} of fake time, expected about 30 s"
    );
    assert!(run.sleeps.iter().all(|d| *d == secs(5)), "{:?}", run.sleeps);
}

#[test]
fn poll_with_deadline_already_passed_is_expired() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    let run = poll(&idp, &session(5, 1800, t0() - secs(1)));
    assert_eq!(run.result.err(), Some(Error::Expired));
    let total: Duration = run.sleeps.iter().sum();
    assert!(
        total <= secs(5),
        "kept polling after the deadline: {total:?}"
    );
    assert!(idp.count(TOKEN_URL) <= 1);
}

#[test]
fn start_then_poll_honours_min_of_expires_in_and_max_wait() {
    // End to end through start_device: expires_in 1800 s, max_wait 30 s.
    let mut c = cfg();
    c.max_wait = secs(30);
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 5)));
    idp.on(TOKEN_URL, pending());

    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let sso = Sso {
        cfg: &c,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let p = provider();
    let (_, s) = sso.start_device(&p, &secret()).unwrap();
    assert_eq!(s.deadline, t0() + secs(30));
    let r = sso.wait_for_token(&p, &secret(), &s);
    assert_eq!(r.err(), Some(Error::Expired));
    assert!(sleeper.total() <= secs(35), "{:?}", sleeper.total());
}

#[test]
fn poll_retries_after_transport_failure() {
    // The library backs off (doubles the interval) on a transport error and keeps polling.
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Network("connection reset".to_owned())),
    );
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(3, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(run.sleeps, vec![secs(6)]);
}

#[test]
fn poll_with_persistent_tls_failure_is_tls_error_not_expired() {
    // An IdP that stops answering after the code was issued is an outage
    // (PAM_AUTHINFO_UNAVAIL), not an expired code (PAM_MAXTRIES).
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Tls("handshake".to_owned())),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert!(matches!(run.result, Err(Error::Tls(_))), "{:?}", run.result);
    // It gives up after a few consecutive failures, long before max_wait.
    assert_eq!(idp.count(TOKEN_URL), 3);
    assert_eq!(run.sleeps, vec![secs(10), secs(20)]);
}

#[test]
fn poll_with_persistent_network_failure_is_network_error() {
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Network("connection refused".to_owned())),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert!(
        matches!(run.result, Err(Error::Network(_))),
        "{:?}",
        run.result
    );
}

#[test]
fn poll_transport_failure_when_the_deadline_comes_is_a_transport_error() {
    // Fails, backs off 10 s, fails again; the next wait (20 s) would pass the
    // deadline (15 s): the outcome is the transport error, not Expired.
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Network("connection reset".to_owned())),
    );
    let run = poll(&idp, &session(5, 1800, t0() + secs(15)));
    assert!(
        matches!(run.result, Err(Error::Network(_))),
        "{:?}",
        run.result
    );
    assert_eq!(run.sleeps, vec![secs(10)]);
}

#[test]
fn poll_transport_failures_are_counted_only_while_consecutive() {
    let idp = FakeIdp::default();
    let fail = || Reply::Fail(HttpError::Network("reset".to_owned()));
    idp.on(TOKEN_URL, fail());
    idp.on(TOKEN_URL, fail());
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, fail());
    idp.on(TOKEN_URL, fail());
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(
        run.sleeps,
        vec![secs(10), secs(20), secs(5), secs(10), secs(20)]
    );
}

#[test]
fn poll_backoff_never_drops_below_the_slowed_down_interval() {
    // RFC 8628 §3.5: after slow_down the interval grows by 5 s for all later
    // requests. A transport error must back off from there, not reset to 10 s.
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, slow_down());
    idp.on(TOKEN_URL, slow_down());
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Network("timeout".to_owned())),
    );
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(5, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(run.sleeps, vec![secs(10), secs(15), secs(30), secs(15)]);
}

#[test]
fn poll_backoff_respects_a_long_server_interval() {
    let idp = FakeIdp::default();
    idp.on(
        TOKEN_URL,
        Reply::Fail(HttpError::Network("timeout".to_owned())),
    );
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(15, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(run.sleeps, vec![secs(30)]);
}

#[test]
fn poll_never_sleeps_past_the_deadline() {
    // An interval longer than the time left must not block past the deadline.
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    let run = poll(&idp, &session(45, 1800, t0() + secs(30)));
    assert_eq!(run.result.err(), Some(Error::Expired));
    let total: Duration = run.sleeps.iter().sum();
    assert!(total <= secs(30), "slept {total:?} past a 30 s deadline");
}

#[test]
fn poll_slow_down_never_sleeps_past_the_deadline() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, slow_down());
    let run = poll(&idp, &session(5, 1800, t0() + secs(30)));
    assert_eq!(run.result.err(), Some(Error::Expired));
    let total: Duration = run.sleeps.iter().sum();
    assert!(total <= secs(30), "slept {total:?} past a 30 s deadline");
}

#[test]
fn poll_rejects_an_interval_above_the_cap_without_polling() {
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    let run = poll(&idp, &session(3600, 1800, t0() + secs(600)));
    assert_idp_err(run.result);
    assert!(run.sleeps.is_empty(), "{:?}", run.sleeps);
    assert_eq!(idp.count(TOKEN_URL), 0);
}

#[test]
fn poll_huge_interval_with_slow_down_does_not_panic() {
    // oauth2 adds 5 s to the interval on slow_down with an unchecked add.
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, slow_down());
    let run = poll(&idp, &session(u64::MAX, 1800, t0() + secs(600)));
    assert_idp_err(run.result);
    assert!(run.sleeps.is_empty(), "{:?}", run.sleeps);
}

#[test]
fn poll_without_a_token_endpoint_is_idp_error() {
    // Not a provider `discover` returns, but `wait_for_token` takes any.
    let mut p = provider();
    p.metadata = p.metadata.set_token_endpoint(None);
    let idp = FakeIdp::default();
    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let c = cfg();
    let sso = Sso {
        cfg: &c,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let r = sso.wait_for_token(&p, &secret(), &session(5, 1800, t0() + secs(600)));
    assert_idp_err(r);
    assert!(idp.seen().is_empty());
}

#[test]
fn poll_zero_interval_still_waits_a_second() {
    // `"interval": 0` must not turn into a busy loop against the IdP.
    let idp = FakeIdp::default();
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, pending());
    idp.on(TOKEN_URL, success());
    let run = poll(&idp, &session(0, 1800, t0() + secs(600)));
    assert!(run.result.is_ok(), "{:?}", run.result.err());
    assert_eq!(run.sleeps, vec![MIN_INTERVAL, MIN_INTERVAL]);
}

#[test]
fn start_device_rejects_an_interval_longer_than_max_wait() {
    let mut c = cfg();
    c.max_wait = secs(30);
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 45)));
    let r = start_with(&c, &provider(), &idp, &FakeClock::at(t0()));
    assert_idp_err(r);
}

#[test]
fn start_device_rejects_an_interval_above_the_cap() {
    let idp = FakeIdp::default();
    idp.on(DEVICE_URL, Reply::Json(200, device_json(true, 1800, 3600)));
    assert_idp_err(start(&idp));
    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Json(200, device_json(true, 1800, u64::MAX)),
    );
    assert_idp_err(start(&idp));
}

#[test]
fn start_device_accepts_an_interval_at_the_cap() {
    let idp = FakeIdp::default();
    idp.on(
        DEVICE_URL,
        Reply::Json(200, device_json(true, 1800, MAX_INTERVAL.as_secs())),
    );
    assert!(start(&idp).is_ok());
}

// ---------------------------------------------------------------------------
// ID-token verification
// ---------------------------------------------------------------------------

#[test]
fn verify_good_token_returns_claims() {
    let c = verify(&jwt(&good_claims())).unwrap();
    assert_eq!(
        c,
        Claims {
            username: "alice".to_owned(),
            groups: vec!["users".to_owned(), "admins".to_owned()],
        }
    );
}

#[test]
fn verify_accepts_audience_array_containing_only_client_id() {
    let c = verify(&jwt(&claims_with("aud", json!([CLIENT_ID])))).unwrap();
    assert_eq!(c.username, "alice");
}

#[test]
fn verify_accepts_matching_azp() {
    let c = verify(&jwt(&claims_with("azp", json!(CLIENT_ID)))).unwrap();
    assert_eq!(c.username, "alice");
}

#[test]
fn verify_uses_configured_username_and_groups_claims() {
    let mut cfg = cfg();
    cfg.username_claim = "email".to_owned();
    cfg.groups_claim = "roles".to_owned();
    let mut claims = good_claims();
    claims["email"] = json!("alice@example.org");
    claims["roles"] = json!(["ops"]);
    let c = verify_with(&cfg, &jwt(&claims)).unwrap();
    assert_eq!(c.username, "alice@example.org");
    assert_eq!(c.groups, vec!["ops".to_owned()]);
}

#[test]
fn verify_missing_groups_claim_gives_no_groups() {
    let c = verify(&jwt(&claims_without("groups"))).unwrap();
    assert_eq!(c.username, "alice");
    assert!(c.groups.is_empty());
}

#[test]
fn verify_empty_groups_claim_gives_no_groups() {
    let c = verify(&jwt(&claims_with("groups", json!([])))).unwrap();
    assert!(c.groups.is_empty());
}

#[test]
fn verify_non_array_groups_claim_is_claim_error() {
    assert_claim_err(verify(&jwt(&claims_with("groups", json!("admins")))));
    assert_claim_err(verify(&jwt(&claims_with("groups", json!({ "a": 1 })))));
}

#[test]
fn verify_non_string_group_is_claim_error() {
    assert_claim_err(verify(&jwt(&claims_with("groups", json!(["admins", 7])))));
}

#[test]
fn verify_missing_username_claim_is_claim_error() {
    assert_claim_err(verify(&jwt(&claims_without("preferred_username"))));
}

#[test]
fn verify_non_string_username_claim_is_claim_error() {
    // A non-string `preferred_username` already fails to parse inside
    // openidconnect (it is a typed standard claim), so use a custom claim.
    let mut cfg = cfg();
    cfg.username_claim = "uname".to_owned();
    assert_claim_err(verify_with(&cfg, &jwt(&claims_with("uname", json!(42)))));
    assert_claim_err(verify_with(
        &cfg,
        &jwt(&claims_with("uname", json!(["alice"]))),
    ));
    assert_claim_err(verify_with(&cfg, &jwt(&claims_with("uname", json!(null)))));
}

#[test]
fn verify_custom_username_claim_missing_is_claim_error() {
    let mut cfg = cfg();
    cfg.username_claim = "uname".to_owned();
    // preferred_username is present, but it is not the configured claim.
    assert_claim_err(verify_with(&cfg, &jwt(&good_claims())));
}

#[test]
fn verify_reads_standard_claims_by_name() {
    // `username_claim` may name a claim that openidconnect models itself.
    let mut cfg = cfg();
    cfg.username_claim = "sub".to_owned();
    assert_eq!(
        verify_with(&cfg, &jwt(&good_claims())).unwrap().username,
        "8f2c1e"
    );
    cfg.username_claim = "email".to_owned();
    let c = verify_with(
        &cfg,
        &jwt(&claims_with("email", json!("alice@example.org"))),
    )
    .unwrap();
    assert_eq!(c.username, "alice@example.org");
}

#[test]
fn verify_rejects_wrong_issuer() {
    assert_token_err(verify(&jwt(&claims_with(
        "iss",
        json!("https://evil.test/application/o/login/"),
    ))));
}

#[test]
fn verify_rejects_wrong_audience() {
    assert_token_err(verify(&jwt(&claims_with("aud", json!("other-client")))));
    assert_token_err(verify(&jwt(&claims_with("aud", json!(["other-client"])))));
}

#[test]
fn verify_rejects_azp_mismatch_with_multiple_audiences() {
    let mut claims = claims_with("aud", json!([CLIENT_ID, "other-client"]));
    claims["azp"] = json!("other-client");
    assert_token_err(verify(&jwt(&claims)));
}

#[test]
fn verify_rejects_azp_mismatch_with_single_audience() {
    assert_token_err(verify(&jwt(&claims_with("azp", json!("other-client")))));
}

#[test]
fn verify_rejects_multiple_audiences_without_azp() {
    assert_token_err(verify(&jwt(&claims_with(
        "aud",
        json!([CLIENT_ID, "other-client"]),
    ))));
}

#[test]
fn verify_rejects_expired_token() {
    let mut claims = good_claims();
    claims["iat"] = json!(T0 - 600);
    claims["exp"] = json!(T0 - 1);
    assert_token_err(verify(&jwt(&claims)));
}

#[test]
fn verify_rejects_iat_in_the_future() {
    let mut claims = good_claims();
    claims["iat"] = json!(T0 + 3600);
    claims["exp"] = json!(T0 + 7200);
    assert_token_err(verify(&jwt(&claims)));
}

#[test]
fn verify_uses_the_injected_clock() {
    // At the fake time T0 + 400 the token (exp = T0 + 300) has expired, even
    // though by the real clock it is not yet issued.
    let idp = FakeIdp::default();
    let client = idp.client();
    let clock = FakeClock::at(t0() + secs(400));
    let sleeper = FakeSleeper::new(&clock);
    let c = cfg();
    let sso = Sso {
        cfg: &c,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let r = sso.verify_id_token(&provider(), &tokens(&jwt(&good_claims())));
    assert_token_err(r);
}

#[test]
fn verify_rejects_hs256_signed_with_client_secret() {
    let header = json!({ "alg": "HS256", "typ": "JWT", "kid": "k1" });
    let input = signing_input(&header, &good_claims());
    let sig = CoreHmacKey::new(CLIENT_SECRET.as_bytes())
        .sign(&CoreJwsSigningAlgorithm::HmacSha256, input.as_bytes())
        .unwrap();
    assert_token_err(verify(&format!("{input}.{}", b64url(&sig))));
}

#[test]
fn verify_rejects_alg_none() {
    let header = json!({ "alg": "none", "typ": "JWT" });
    let input = signing_input(&header, &good_claims());
    assert_token_err(verify(&format!("{input}.")));
}

#[test]
fn verify_rejects_unknown_kid() {
    assert_token_err(verify(&jwt_with_key(
        &key1(),
        "unknown-kid",
        &good_claims(),
    )));
}

#[test]
fn verify_rejects_signature_from_another_key() {
    assert_token_err(verify(&jwt_with_key(&key2(), "k1", &good_claims())));
}

#[test]
fn verify_rejects_tampered_payload() {
    let good = jwt(&good_claims());
    let parts: Vec<&str> = good.split('.').collect();
    let forged_payload = b64url(
        claims_with("preferred_username", json!("root"))
            .to_string()
            .as_bytes(),
    );
    let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
    assert_token_err(verify(&forged));
}

#[test]
fn verify_without_id_token_is_token_error() {
    let idp = FakeIdp::default();
    let client = idp.client();
    let clock = FakeClock::at(t0());
    let sleeper = FakeSleeper::new(&clock);
    let c = cfg();
    let sso = Sso {
        cfg: &c,
        http: &client,
        clock: &clock,
        sleeper: &sleeper,
    };
    let t: Tokens = serde_json::from_value(token_json(None)).unwrap();
    assert_token_err(sso.verify_id_token(&provider(), &t));
}

#[test]
fn b64url_helper_matches_rfc4648_vectors() {
    // Guards the hand-written encoder the token tests rely on.
    assert_eq!(b64url(b""), "");
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
    assert_eq!(b64url(b"foob"), "Zm9vYg");
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
}

// ---------------------------------------------------------------------------
// Claim checks
// ---------------------------------------------------------------------------

fn claims(username: &str, groups: &[&str]) -> Claims {
    Claims {
        username: username.to_owned(),
        groups: groups.iter().map(|&g| g.to_owned()).collect(),
    }
}

#[test]
fn check_claims_accepts_exact_user_without_group_requirement() {
    assert_eq!(check_claims(&cfg(), "alice", &claims("alice", &[])), Ok(()));
}

#[test]
fn check_claims_rejects_other_user() {
    assert_claim_err(check_claims(&cfg(), "bob", &claims("alice", &[])));
}

#[test]
fn check_claims_username_match_is_exact() {
    assert_claim_err(check_claims(&cfg(), "alice", &claims("Alice", &[])));
    assert_claim_err(check_claims(&cfg(), "alice", &claims("alice ", &[])));
    assert_claim_err(check_claims(&cfg(), "alice", &claims(" alice", &[])));
    assert_claim_err(check_claims(
        &cfg(),
        "alice",
        &claims("alice@example.org", &[]),
    ));
    assert_claim_err(check_claims(&cfg(), "alice", &claims("alic", &[])));
    assert_claim_err(check_claims(&cfg(), "alice", &claims("", &[])));
}

#[test]
fn check_claims_empty_pam_user_never_matches() {
    assert_claim_err(check_claims(&cfg(), "", &claims("alice", &[])));
}

#[test]
fn check_claims_requires_one_of_the_groups() {
    let mut c = cfg();
    c.require_group = vec!["admins".to_owned(), "ops".to_owned()];
    assert_eq!(
        check_claims(&c, "alice", &claims("alice", &["users", "ops"])),
        Ok(())
    );
    assert_eq!(
        check_claims(&c, "alice", &claims("alice", &["admins"])),
        Ok(())
    );
    assert_claim_err(check_claims(&c, "alice", &claims("alice", &["users"])));
    assert_claim_err(check_claims(&c, "alice", &claims("alice", &[])));
}

#[test]
fn check_claims_group_match_is_exact() {
    let mut c = cfg();
    c.require_group = vec!["admins".to_owned()];
    assert_claim_err(check_claims(&c, "alice", &claims("alice", &["Admins"])));
    assert_claim_err(check_claims(&c, "alice", &claims("alice", &["admins-old"])));
}

#[test]
fn check_claims_checks_user_even_when_group_matches() {
    let mut c = cfg();
    c.require_group = vec!["admins".to_owned()];
    assert_claim_err(check_claims(&c, "bob", &claims("alice", &["admins"])));
}
