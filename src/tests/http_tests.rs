//! Unit tests for `http`: the ureq-based client against `httpmock` over TLS,
//! with the mock server's CA as the only trusted root.
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

#[allow(unused_imports)]
use super::*;

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use httpmock::prelude::*;
use openidconnect::url::Url;

use crate::args::Config;
use crate::error::Error;

/// An unrelated self-signed CA (P-256, no key kept): trusts nothing httpmock serves.
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

/// A config trusting only `ca_pem` (written to a temp file kept alive by the returned guard).
fn cfg_with_ca(ca_pem: &str) -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ca: PathBuf = dir.path().join("ca.pem");
    fs::write(&ca, ca_pem).unwrap();
    let mut cfg = Config::new(
        Url::parse("https://127.0.0.1/application/o/login/").unwrap(),
        "pam-login",
    );
    cfg.ca_file = ca;
    cfg.connect_timeout = Duration::from_secs(2);
    cfg.timeout = Duration::from_secs(2);
    (cfg, dir)
}

/// A config trusting httpmock's CA.
fn mock_cfg() -> (Config, tempfile::TempDir) {
    cfg_with_ca(httpmock::server::DEFAULT_CA_CERTIFICATE)
}

fn get(url: &str) -> HttpRequest {
    ::http::Request::builder()
        .method("GET")
        .uri(url)
        .header("accept", "application/json")
        .body(Vec::new())
        .unwrap()
}

#[test]
fn get_over_https_with_trusted_ca() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/openid-configuration")
            .header("accept", "application/json");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ok":true}"#);
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();

    let url = server.url("/.well-known/openid-configuration");
    assert!(
        url.starts_with("https://"),
        "httpmock must serve TLS: {url}"
    );
    let resp = client(get(&url)).unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(resp.body(), br#"{"ok":true}"#);
    m.assert_calls(1);
}

#[test]
fn post_sends_method_headers_and_body() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/application/o/token/")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "Basic cGFtOnNlY3JldA==")
            .body("grant_type=x&device_code=abc");
        then.status(200)
            .header("content-type", "application/json")
            .body("{}");
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();

    let req = ::http::Request::builder()
        .method("POST")
        .uri(server.url("/application/o/token/"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", "Basic cGFtOnNlY3JldA==")
        .body(b"grant_type=x&device_code=abc".to_vec())
        .unwrap();
    let resp = client(req).unwrap();
    assert_eq!(resp.status(), 200);
    m.assert_calls(1);
}

#[test]
fn error_status_is_returned_not_raised() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"authorization_pending"}"#);
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let req = ::http::Request::builder()
        .method("POST")
        .uri(server.url("/token"))
        .body(b"a=b".to_vec())
        .unwrap();
    let resp = client(req).unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.body(), br#"{"error":"authorization_pending"}"#);
}

#[test]
fn server_error_status_is_returned_not_raised() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/x");
        then.status(503).body("down");
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let resp = client(get(&server.url("/x"))).unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.body(), b"down");
}

#[test]
fn rejects_plain_http_without_sending() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.path("/x");
        then.status(200).body("should not be reached");
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();

    let url = format!("http://{}/x", server.address());
    let r = client(get(&url));
    assert!(matches!(r, Err(HttpError::Insecure(_))), "{r:?}");
    assert_eq!(m.calls(), 0, "a plain-http request reached the server");
}

#[test]
fn rejects_non_http_schemes() {
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    for url in ["ftp://127.0.0.1/x", "file:///etc/passwd"] {
        let req = ::http::Request::builder()
            .method("GET")
            .uri(url)
            .body(Vec::new());
        // Some of these are not even valid `http::Uri`s; only check the ones that are.
        if let Ok(req) = req {
            let r = client(req);
            assert!(matches!(r, Err(HttpError::Insecure(_))), "{url}: {r:?}");
        }
    }
}

#[test]
fn untrusted_ca_is_tls_error() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.path("/x");
        then.status(200).body("secret stuff");
    });
    let (cfg, _g) = cfg_with_ca(OTHER_CA_PEM);
    let client = build_client(&cfg).unwrap();
    let r = client(get(&server.url("/x")));
    assert!(matches!(r, Err(HttpError::Tls(_))), "{r:?}");
    assert_eq!(m.calls(), 0);
    // And it maps to Error::Tls.
    assert!(matches!(Error::from(r.unwrap_err()), Error::Tls(_)));
}

#[test]
fn trusts_ca_from_a_multi_certificate_bundle() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/x");
        then.status(204);
    });
    let bundle = format!(
        "{OTHER_CA_PEM}\n{}",
        httpmock::server::DEFAULT_CA_CERTIFICATE
    );
    let (cfg, _g) = cfg_with_ca(&bundle);
    let client = build_client(&cfg).unwrap();
    assert_eq!(client(get(&server.url("/x"))).unwrap().status(), 204);
}

#[test]
fn missing_ca_file_is_tls_error() {
    let (mut cfg, g) = mock_cfg();
    cfg.ca_file = g.path().join("does-not-exist.pem");
    let r = build_client(&cfg);
    assert!(matches!(r, Err(Error::Tls(_))), "{:?}", r.err());
}

#[test]
fn ca_file_without_certificates_is_tls_error() {
    let (cfg, _g) = cfg_with_ca("this is not a PEM bundle\n");
    let r = build_client(&cfg);
    assert!(matches!(r, Err(Error::Tls(_))), "{:?}", r.err());
}

#[test]
fn empty_ca_file_is_tls_error() {
    let (cfg, _g) = cfg_with_ca("");
    let r = build_client(&cfg);
    assert!(matches!(r, Err(Error::Tls(_))), "{:?}", r.err());
}

#[test]
fn corrupt_certificate_in_ca_file_is_tls_error() {
    let (cfg, _g) = cfg_with_ca(
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
    );
    let r = build_client(&cfg);
    assert!(matches!(r, Err(Error::Tls(_))), "{:?}", r.err());
}

#[test]
fn redirects_are_not_followed() {
    let server = MockServer::start();
    let redirect = server.mock(|when, then| {
        when.path("/start");
        then.status(302).header("location", "/elsewhere");
    });
    let target = server.mock(|when, then| {
        when.path("/elsewhere");
        then.status(200).body("followed");
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let resp = client(get(&server.url("/start"))).unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers().get("location").unwrap(), "/elsewhere");
    redirect.assert_calls(1);
    assert_eq!(target.calls(), 0, "redirect was followed");
}

#[test]
fn slow_response_times_out() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.path("/slow");
        then.status(200).body("late").delay(Duration::from_secs(10));
    });
    let (mut cfg, _g) = mock_cfg();
    cfg.timeout = Duration::from_secs(1);
    let client = build_client(&cfg).unwrap();
    let started = Instant::now();
    let r = client(get(&server.url("/slow")));
    let took = started.elapsed();
    assert!(matches!(r, Err(HttpError::Network(_))), "{r:?}");
    assert!(
        took < Duration::from_secs(5),
        "timeout not applied: {took:?}"
    );
}

#[test]
fn hung_server_times_out() {
    // A listener that never accepts: the TCP handshake completes in the
    // kernel, but no TLS ServerHello ever comes.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut cfg, _g) = mock_cfg();
    cfg.timeout = Duration::from_secs(1);
    cfg.connect_timeout = Duration::from_secs(1);
    let client = build_client(&cfg).unwrap();
    let started = Instant::now();
    let r = client(get(&format!("https://{addr}/x")));
    let took = started.elapsed();
    assert!(matches!(r, Err(HttpError::Network(_))), "{r:?}");
    assert!(
        took < Duration::from_secs(5),
        "timeout not applied: {took:?}"
    );
    drop(listener);
}

#[test]
fn connection_refused_is_network_error() {
    // Bind then drop to get a port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let r = client(get(&format!("https://127.0.0.1:{port}/x")));
    assert!(matches!(r, Err(HttpError::Network(_))), "{r:?}");
}

#[test]
fn body_at_the_cap_is_accepted() {
    let server = MockServer::start();
    let len = usize::try_from(MAX_BODY).unwrap();
    server.mock(|when, then| {
        when.path("/big");
        then.status(200).body(vec![b'a'; len]);
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let resp = client(get(&server.url("/big"))).unwrap();
    assert_eq!(resp.body().len(), len);
}

#[test]
fn body_over_the_cap_is_rejected() {
    let server = MockServer::start();
    let len = usize::try_from(MAX_BODY).unwrap() + 1;
    server.mock(|when, then| {
        when.path("/big");
        then.status(200).body(vec![b'a'; len]);
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let r = client(get(&server.url("/big")));
    assert_eq!(r.err(), Some(HttpError::TooLarge));
}

#[test]
fn error_body_over_the_cap_is_rejected() {
    let server = MockServer::start();
    let len = usize::try_from(MAX_BODY).unwrap() * 4;
    server.mock(|when, then| {
        when.path("/big");
        then.status(500).body(vec![b'e'; len]);
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    let r = client(get(&server.url("/big")));
    assert_eq!(r.err(), Some(HttpError::TooLarge));
}

#[test]
fn client_is_reusable() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.path("/x");
        then.status(200).body("ok");
    });
    let (cfg, _g) = mock_cfg();
    let client = build_client(&cfg).unwrap();
    for _ in 0..3 {
        assert_eq!(client(get(&server.url("/x"))).unwrap().status(), 200);
    }
    m.assert_calls(3);
}

#[test]
fn http_error_maps_to_error() {
    assert_eq!(
        Error::from(HttpError::Tls("bad cert".into())),
        Error::Tls("bad cert".into())
    );
    assert_eq!(
        Error::from(HttpError::Network("refused".into())),
        Error::Network("refused".into())
    );
    assert!(matches!(
        Error::from(HttpError::Insecure("http://x".into())),
        Error::Network(_)
    ));
    assert!(matches!(
        Error::from(HttpError::TooLarge),
        Error::Network(_)
    ));
}

#[test]
fn http_error_display_is_informative() {
    let cases = [
        (
            HttpError::Network("connection refused".into()),
            "connection refused",
        ),
        (HttpError::Tls("unknown issuer".into()), "unknown issuer"),
        (
            HttpError::Insecure("http://idp.test/x".into()),
            "http://idp.test/x",
        ),
    ];
    for (e, needle) in cases {
        let s = e.to_string();
        assert!(s.contains(needle), "{s:?} should contain {needle:?}");
    }
    assert!(!HttpError::TooLarge.to_string().is_empty());
}
