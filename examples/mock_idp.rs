//! A standalone mock `IdP` for manual `pamtester` runs against `pam_idp.so`.
//!
//! Serves HTTPS on `127.0.0.1:8443` (one request per connection, one
//! connection at a time) with an Authentik-like layout:
//!
//! | Path | What |
//! | --- | --- |
//! | `/application/o/login/.well-known/openid-configuration` | discovery, with `device_authorization_endpoint` |
//! | `/application/o/login/jwks/` | the RS256 signing key |
//! | `/application/o/device/` | device authorization (RFC 8628 §3.1) |
//! | `/application/o/token/` | device-code grant: answers by the current decision |
//! | `/if/device/` | a stand-in verification page |
//! | `/_test/approve?user=NAME&groups=A,B` | from now on, approve as `NAME` (groups optional) |
//! | `/_test/deny` | from now on, answer `access_denied` |
//! | `/_test/pending` | from now on, answer `authorization_pending` (the start state) |
//!
//! The device and token endpoints require the client credentials below
//! (HTTP Basic or form fields). At start it writes `ca.pem` (the CA that
//! signs its certificate), `issuer`, `client_id` and `client_secret` into
//! the directory named by its one argument (default: the current directory):
//!
//! ```text
//! cargo run --example mock_idp -- /tmp/pam-idp-mock
//! curl --cacert /tmp/pam-idp-mock/ca.pem 'https://127.0.0.1:8443/_test/approve?user=alice'
//! ```
//!
//! The keys below are throwaway test material, used nowhere else.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
    CoreTokenType,
};
use openidconnect::url::{Url, form_urlencoded};
use openidconnect::{
    AccessToken, EmptyExtraTokenFields, IdToken, IdTokenClaims, JsonWebKeyId, PrivateSigningKey,
};
use pam_idp::oidc::{ExtraClaims, IdpIdTokenFields, Tokens};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};

const LISTEN: &str = "127.0.0.1:8443";
const ORIGIN: &str = "https://127.0.0.1:8443";
const ISSUER_PATH: &str = "/application/o/login/";
const JWKS_PATH: &str = "/application/o/login/jwks/";
const DEVICE_PATH: &str = "/application/o/device/";
const TOKEN_PATH: &str = "/application/o/token/";
const VERIFY_PATH: &str = "/if/device/";
const CLIENT_ID: &str = "pam-login";
const CLIENT_SECRET: &str = "mock-client-s3cret";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const EXPIRES_IN: u64 = 600;
const INTERVAL: u64 = 1;
const MAX_REQUEST: usize = 65536;

/// Test CA (EC P-256, valid until 2126); its certificate is written to `ca.pem`.
const CA_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIBrjCCAVOgAwIBAgIUT2qyaRIAAiKUOWUjSNhWJ9NL0HcwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYcGFtX2lkcCBtb2NrIElkUCB0ZXN0IENBMCAXDTI2MTExMzA2
Mjg0NVoYDzIxMjYxMDIwMDYyODQ1WjAjMSEwHwYDVQQDDBhwYW1faWRwIG1vY2sg
SWRQIHRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARrJyRgb4N4HZyH
0iUvjDMWGY3sQ8j4mH/vxkEIon3BKVFVt1IqBoD9/w6bZxt7oKY7msUEwLTpAJiU
tWHGHxgBo2MwYTAdBgNVHQ4EFgQUG53yvc+xECpFSiqMRKgumSeMKGowHwYDVR0j
BBgwFoAUG53yvc+xECpFSiqMRKgumSeMKGowDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAP9cAbQINad91ks0WYqj91t2
Ioq0BDbosBaQGrFNaYiPAiEA4dMSnNYvBSvv9/MJ+DEmJR45J1Gwc18VZEl1HjmM
xtI=
-----END CERTIFICATE-----
";

/// Server certificate for `127.0.0.1` and `localhost`, signed by [`CA_PEM`].
const SERVER_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIBzjCCAXSgAwIBAgIUKK0pJRUBir91TqcgXoPJTP1egDEwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYcGFtX2lkcCBtb2NrIElkUCB0ZXN0IENBMCAXDTI2MTExMzA2
Mjg0NVoYDzIxMjYxMDIwMDYyODQ1WjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ78EjiXRBb52hqBQYf9D4e/Td6Y6/nHtF8
kUEsQvHtcfheK5KZTYVUjyJD9m/say6ksgUDcO4oA9+3+0v4RufGo4GSMIGPMAwG
A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MBoGA1UdEQQTMBGHBH8AAAGCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUD3iSOxCFQCkU
z+HSepFBbKPtqz4wHwYDVR0jBBgwFoAUG53yvc+xECpFSiqMRKgumSeMKGowCgYI
KoZIzj0EAwIDSAAwRQIgNp70rGpNknHtTlcjbVwu6aFZ8vNgOcMbcSHqUKdSyMAC
IQClRaaqcEhA7lPTwl47TSJGm6tJQcmhoRZD5nvnPpUNdQ==
-----END CERTIFICATE-----
";

/// Private key of [`SERVER_CERT_PEM`] (PKCS#8).
const SERVER_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZkev9vTJrnIC0gCV
i0Z3KLn7GXzhOurkPvvnDz4qLlChRANCAAQ78EjiXRBb52hqBQYf9D4e/Td6Y6/n
HtF8kUEsQvHtcfheK5KZTYVUjyJD9m/say6ksgUDcO4oA9+3+0v4RufG
-----END PRIVATE KEY-----
";

/// ID-token signing key (RSA 2048, PKCS#1).
const SIGNING_KEY_PEM: &str = r"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2xt5RA3zwyla2pCMxTKXedgBDzEz8ynSXeIEueqd54GlUo5r
Etjq8vsHYfxlpkWtWmBSF5w1BdtI49iZdPVN4zS4kIY6WzU3HZTu5jZNjPqSEUs7
BK6oJl8f69kGQIkAHbykrLDxPdiQouiOWTgNyAaT57Dea5VpVUtZKe7391grRP0y
7RkMqoA0J4yV7MBBuI1jq+gCeL1bGeb1u1BULvyFoxKAO1OTNJiBc5ZaROkmixBr
ig9wSCFXCD7jeOPVbibq0dclmJJgqKW19ifB05+g+sUrecInAN+SDQ13aVB6G9Vz
vyzi95JdHWC9FH3MzgSLjLkpsVzYVB4oSkPJswIDAQABAoIBAAul3kB77WWGoUnV
PWaOVfcoQIYqO3TF2GUdStsHWfWgssU8xPxvg63/IllXLaA1PA396N9QcpEpIyrZ
rO7Gy6k0eEtWl2uZ3KA59qlOYbkI6RL6SNzq3A2OKQhEtUxg/ByYlriHf4umI6pF
aqvbiwADOYGrqWdWvg7Gvqq4BX6knBQlIhANED5aLvyve1CghCCWlPygi/DBjjpq
EcXG7kipDUB+izlIXn4I2+W3a8X6BxcXT3a4svA1Zq+Fg53JyLcFL8K7XrgXCm2q
6wohGpyEzQBd7mDMySr26mKUIlpRuEoG5rd1ghqroSLHdPsL9jzqjSAOYHcZmw4j
smD88WECgYEA9wfo2B3fiUXcnpwVZ/KUKB3xPLP3kuitj1gu9O/KyzEQDCEELsZh
v9YA+PYbH4BTjqZY5yGv/dgwsWANBO7dG/X8H0JZmvH/gXDqiaxuvCK5qYY3bZzg
5ZB7DGbf0dqbaJEEv6XixGDeAmRZERNJAL054E3ltjIM4rpSNxgwUT8CgYEA4xAF
fyr9iG6/aF1u8y+tXgFH+g7AfGY3QVMvUaIHJa271pDERbaEgXwH9e5lE5MTBEQQ
F4KE8jk/NCNUnVdetw8ZizL4ldvv26N/wAzfLUAT/+SdHhD23FnBTNBRJFk1nJUp
aUVcOjQdlxeghn5YRDZa1MotpQ948vlpJgzMdo0CgYBac+X5hG6+d/tBhIt+BV/k
lJopjQhBHbu3eiWvgEI0RqHGnyxF6FQQh07R2mOyFC4EVLrG3xnvDANAX5hEzyXd
QCPyWjwvNR9GiU8H3ECr2Nc80K1pEIF07YNw1hZsY+x1zGv9tMMk/wcrvwyx6OrZ
P3B6xmsvXIJFXs4N6GiAxwKBgAjKMPxIRMJITz6SB16ApPxznj6u3YKzTkZIGxfU
5uPtgsz+k6qDM0Pz8jbyAJWuZtkObXULh2v9DVZOW9Mvc6owenOqCHd8qR9eh+5+
URFmXp/UUMS+MWA8VUBM/CclEO870vuRRM24AME9l+g88dvKIuAD55pxK+R0BT8E
1dFtAoGBAIu0Id2/WALqBCqAakF1OrJU68rq14ifVZRu+56M6lCQywMLPJDGqsL0
u8qMwPh6bvZBBtLIZKpP3oF1HV63/TeIjS43+i04oM4EldcSlYJNui7l03JHqjQF
7P4pjkvo8Wf2ybv16qs1XqmZiIG+hIMQ78qS5Qh+tqLHtpJyg3EO
-----END RSA PRIVATE KEY-----
";

/// How every pending device authorization resolves when polled.
#[derive(Clone, Debug)]
enum Decision {
    Pending,
    Approve { user: String, groups: Vec<String> },
    Deny,
}

/// One parsed request.
struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    form: HashMap<String, String>,
}

/// A response: status, content type, body.
type Response = (u16, &'static str, String);

struct Idp {
    key: CoreRsaPrivateSigningKey,
    decision: Decision,
    devices: HashSet<String>,
    issued: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let out = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    write_files(&out)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes())?],
                PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes())?,
            )?,
    );
    let mut idp = Idp {
        key: CoreRsaPrivateSigningKey::from_pem(
            SIGNING_KEY_PEM,
            Some(JsonWebKeyId::new("mock".to_owned())),
        )
        .map_err(|e| format!("signing key: {e}"))?,
        decision: Decision::Pending,
        devices: HashSet::new(),
        issued: 0,
    };

    let listener = TcpListener::bind(LISTEN)?;
    eprintln!("mock IdP: issuer {ORIGIN}{ISSUER_PATH}, client {CLIENT_ID}");
    eprintln!(
        "mock IdP: wrote ca.pem, issuer, client_id, client_secret to {}",
        out.display()
    );
    eprintln!("mock IdP: decide with {ORIGIN}/_test/approve?user=NAME[&groups=A,B] or /_test/deny");
    for tcp in listener.incoming() {
        if let Err(e) = tcp.map_err(Into::into).and_then(|t| idp.serve(&tls, t)) {
            eprintln!("mock IdP: connection error: {e}");
        }
    }
    Ok(())
}

/// Writes the files `scripts/pamtester.sh` reads.
fn write_files(dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("ca.pem"), CA_PEM)?;
    fs::write(dir.join("issuer"), format!("{ORIGIN}{ISSUER_PATH}\n"))?;
    fs::write(dir.join("client_id"), format!("{CLIENT_ID}\n"))?;
    let secret = dir.join("client_secret");
    fs::write(&secret, format!("{CLIENT_SECRET}\n"))?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

impl Idp {
    /// Reads one request from `tcp` over TLS, answers it and closes.
    fn serve(&mut self, tls: &Arc<ServerConfig>, tcp: TcpStream) -> Result<(), Box<dyn Error>> {
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone())?, tcp);
        let req = read_request(&mut BufReader::new(&mut stream))?;
        let (status, content_type, body) = self.handle(&req);
        let detail = match &self.decision {
            Decision::Approve { user, .. } => format!("approve {user}"),
            d => format!("{d:?}").to_lowercase(),
        };
        eprintln!(
            "{} {} -> {status} (decision: {detail})",
            req.method, req.path
        );
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            _ => "Not Found",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\n\
             content-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.conn.send_close_notify();
        stream.flush()?;
        Ok(())
    }

    fn handle(&mut self, req: &Request) -> Response {
        let issuer = format!("{ORIGIN}{ISSUER_PATH}");
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", p) if p == format!("{ISSUER_PATH}.well-known/openid-configuration") => {
                json_ok(&json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{ORIGIN}/application/o/authorize/"),
                    "token_endpoint": format!("{ORIGIN}{TOKEN_PATH}"),
                    "jwks_uri": format!("{ORIGIN}{JWKS_PATH}"),
                    "device_authorization_endpoint": format!("{ORIGIN}{DEVICE_PATH}"),
                    "response_types_supported": ["code", "id_token", "id_token token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported":
                        ["client_secret_basic", "client_secret_post"],
                    "grant_types_supported": [DEVICE_GRANT],
                }))
            }
            ("GET", JWKS_PATH) => json_ok(
                &serde_json::to_value(CoreJsonWebKeySet::new(vec![self.key.as_verification_key()]))
                    .unwrap_or_default(),
            ),
            ("POST", DEVICE_PATH) if client_ok(req) => self.device(),
            ("POST", TOKEN_PATH) if client_ok(req) => self.token(req),
            ("POST", DEVICE_PATH | TOKEN_PATH) => oauth_error(401, "invalid_client"),
            ("GET", VERIFY_PATH) => (
                200,
                "text/plain",
                format!("Mock IdP: approve with {ORIGIN}/_test/approve?user=NAME\n"),
            ),
            (_, "/_test/approve") => {
                let user = req.query.get("user").cloned().unwrap_or_default();
                let groups = req
                    .query
                    .get("groups")
                    .map(|g| {
                        g.split(',')
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                self.decide(Decision::Approve { user, groups })
            }
            (_, "/_test/deny") => self.decide(Decision::Deny),
            (_, "/_test/pending") => self.decide(Decision::Pending),
            _ => oauth_error(404, "not_found"),
        }
    }

    fn decide(&mut self, decision: Decision) -> Response {
        self.decision = decision;
        json_ok(&json!({ "decision": format!("{:?}", self.decision) }))
    }

    /// RFC 8628 §3.2: a fresh device code and user code.
    fn device(&mut self) -> Response {
        self.issued += 1;
        let device_code = format!("mock-device-{}", self.issued);
        let user_code = format!("MOCK-{:04}", self.issued % 10_000);
        self.devices.insert(device_code.clone());
        json_ok(&json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": format!("{ORIGIN}{VERIFY_PATH}"),
            "verification_uri_complete": format!("{ORIGIN}{VERIFY_PATH}?code={user_code}"),
            "expires_in": EXPIRES_IN,
            "interval": INTERVAL,
        }))
    }

    /// RFC 8628 §3.4/§3.5: answers by the current decision.
    fn token(&mut self, req: &Request) -> Response {
        if req.form.get("grant_type").map(String::as_str) != Some(DEVICE_GRANT) {
            return oauth_error(400, "unsupported_grant_type");
        }
        let Some(code) = req
            .form
            .get("device_code")
            .filter(|c| self.devices.contains(*c))
        else {
            return oauth_error(400, "invalid_grant");
        };
        match self.decision.clone() {
            Decision::Pending => oauth_error(400, "authorization_pending"),
            Decision::Deny => {
                self.devices.remove(code);
                oauth_error(400, "access_denied")
            }
            Decision::Approve { user, groups } => {
                self.devices.remove(code);
                match self.tokens(&user, &groups) {
                    Ok(body) => (200, "application/json", body),
                    Err(e) => (400, "application/json", json!({ "error": e }).to_string()),
                }
            }
        }
    }

    /// A signed ID token (RS256) for `user`, inside a token response.
    fn tokens(&self, user: &str, groups: &[String]) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let claims: IdTokenClaims<ExtraClaims, CoreGenderClaim> = serde_json::from_value(json!({
            "iss": format!("{ORIGIN}{ISSUER_PATH}"),
            "sub": format!("mock-{user}"),
            "aud": CLIENT_ID,
            "azp": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "preferred_username": user,
            "groups": groups,
        }))
        .map_err(|e| e.to_string())?;
        let id_token = IdToken::new(
            claims,
            &self.key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
        let tokens = Tokens::new(
            AccessToken::new(format!("mock-access-{}", self.issued)),
            CoreTokenType::Bearer,
            IdpIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        serde_json::to_string(&tokens).map_err(|e| e.to_string())
    }
}

fn json_ok(v: &Value) -> Response {
    (200, "application/json", v.to_string())
}

fn oauth_error(status: u16, error: &str) -> Response {
    (
        status,
        "application/json",
        json!({ "error": error }).to_string(),
    )
}

/// The client authenticated with HTTP Basic (RFC 6749 §2.3.1, form-encoded
/// parts) or with `client_id`/`client_secret` form fields.
fn client_ok(req: &Request) -> bool {
    let encode = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let basic = format!(
        "Basic {}",
        base64(format!("{}:{}", encode(CLIENT_ID), encode(CLIENT_SECRET)).as_bytes())
    );
    req.headers.get("authorization") == Some(&basic)
        || (req.form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
            && req.form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET))
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Parses one HTTP/1.1 request: request line, headers, `content-length` body.
fn read_request(r: &mut impl BufRead) -> Result<Request, Box<dyn Error>> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request")?.to_owned();
    let target = parts.next().ok_or("no request target")?;
    let url = Url::parse(&format!("{ORIGIN}{target}"))?;
    let mut headers = HashMap::new();
    let mut total = line.len();
    loop {
        line.clear();
        total += r.read_line(&mut line)?;
        if total > MAX_REQUEST {
            return Err("request too large".into());
        }
        let Some((name, value)) = line.split_once(':') else {
            break;
        };
        headers.insert(name.trim().to_lowercase(), value.trim().to_owned());
    }
    let len: usize = headers.get("content-length").map_or(Ok(0), |v| v.parse())?;
    if len > MAX_REQUEST {
        return Err("body too large".into());
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    Ok(Request {
        method,
        path: url.path().to_owned(),
        query: url.query_pairs().into_owned().collect(),
        headers,
        form: form_urlencoded::parse(&body).into_owned().collect(),
    })
}
