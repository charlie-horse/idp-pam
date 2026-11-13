//! End-to-end tests of the built `pam_idp` cdylib, loaded by the system's
//! libpam through `pam_start_confdir` with a temporary PAM service directory.
//!
//! These cover `src/ffi.rs` (the `pam_hooks!` glue, the conversation and
//! item adapters, and `pam_syslog`), which llvm-cov cannot instrument.
//! The module is found next to this test binary (`target/<profile>/`), which
//! `cargo test` builds before running integration tests.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

// ---- libpam FFI (declared here; the crate itself only exports hooks) ----

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

#[repr(C)]
struct PamHandleT {
    _private: [u8; 0],
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut PamHandleT,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandleT, flags: c_int) -> c_int;
    fn pam_setcred(pamh: *mut PamHandleT, flags: c_int) -> c_int;
    fn pam_set_item(pamh: *mut PamHandleT, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_end(pamh: *mut PamHandleT, pam_status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut PamHandleT, errnum: c_int) -> *const c_char;
}

const PAM_SUCCESS: c_int = 0;
const PAM_SERVICE_ERR: c_int = 3;
const PAM_AUTH_ERR: c_int = 7;
const PAM_BUF_ERR: c_int = 5;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_MAXTRIES: c_int = 11;
const PAM_CONV_ERR: c_int = 19;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_RHOST: c_int = 4;

/// The stack line control the plan uses for `pam_idp`.
const SPEC_CONTROL: &str = "[success=done ignore=ignore default=die]";

/// A throwaway CA certificate (no key kept), so `ca_file` parses without
/// depending on the host's bundle (absent in the Nix build sandbox).
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUKab7YdwqoxOXs6r7kvYxvQLvbKowCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTcGFtLWlkcCBmZmkgdGVzdCBDQTAgFw0yNjExMTMwNTU3Mzha
GA8yMTI2MTAyMDA1NTczOFowHjEcMBoGA1UEAwwTcGFtLWlkcCBmZmkgdGVzdCBD
QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFAO8PJ01xm7vyRKzQbDxsmPw8MY
Dkto/b0KPZclC4Bf0d1Kno/gktZs6nuAxQvx6/Kyhq13C2J4XWVgnOLtmbijUzBR
MB0GA1UdDgQWBBTGsYxK6baZhQ/GeoHzEeLb1QEAbDAfBgNVHSMEGDAWgBTGsYxK
6baZhQ/GeoHzEeLb1QEAbDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIE6lZUIV0v56Gca9WV5ry3Aw+2nv9homwqg7o8BSDGwEAiEAgvoCYHzhirN+
hG6UUV2fdT6uUx3iNH2sF2oo+hodpdA=
-----END CERTIFICATE-----
";

// ---- the conversation ----

/// What the scripted conversation saw and how it answers.
struct ConvState {
    /// Answer to every echo-on/off prompt; `None` makes the conversation fail.
    answer: Option<&'static str>,
    /// `(msg_style, text)` for every message, in order.
    seen: Mutex<Vec<(c_int, String)>>,
}

impl ConvState {
    fn answering(answer: &'static str) -> Self {
        Self {
            answer: Some(answer),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn failing() -> Self {
        Self {
            answer: None,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<(c_int, String)> {
        self.seen.lock().unwrap().clone()
    }

    fn count(&self, style: c_int) -> usize {
        self.seen().iter().filter(|(s, _)| *s == style).count()
    }

    fn texts(&self, style: c_int) -> Vec<String> {
        self.seen()
            .into_iter()
            .filter(|(s, _)| *s == style)
            .map(|(_, t)| t)
            .collect()
    }
}

/// Heap-allocates `s` with libc's allocator, as libpam frees responses with `free`.
fn c_strdup(s: &str) -> *mut c_char {
    let c = CString::new(s).unwrap();
    // SAFETY: `c` is a valid NUL-terminated string.
    unsafe { libc::strdup(c.as_ptr()) }
}

unsafe extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // SAFETY: appdata_ptr is the `&ConvState` passed to `pam_start_confdir`,
    // which outlives the handle.
    let state = unsafe { &*appdata_ptr.cast::<ConvState>() };
    let n = usize::try_from(num_msg).unwrap_or(0);
    for i in 0..n {
        // SAFETY: Linux-PAM passes an array of `num_msg` message pointers.
        let m = unsafe { &**msg.add(i) };
        let text = if m.msg.is_null() {
            String::new()
        } else {
            // SAFETY: libpam hands us NUL-terminated strings.
            unsafe { CStr::from_ptr(m.msg) }
                .to_string_lossy()
                .into_owned()
        };
        state.seen.lock().unwrap().push((m.msg_style, text));
    }
    let Some(answer) = state.answer else {
        return PAM_CONV_ERR;
    };
    // SAFETY: calloc of `n` zeroed responses; libpam frees it.
    let replies = unsafe { libc::calloc(n.max(1), size_of::<PamResponse>()) }.cast::<PamResponse>();
    if replies.is_null() {
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        // SAFETY: as above.
        let m = unsafe { &**msg.add(i) };
        if m.msg_style == PAM_PROMPT_ECHO_ON || m.msg_style == PAM_PROMPT_ECHO_OFF {
            // SAFETY: `i < n`, inside the allocation.
            unsafe { (*replies.add(i)).resp = c_strdup(answer) };
        }
    }
    // SAFETY: libpam passes a valid out pointer.
    unsafe { *resp = replies };
    PAM_SUCCESS
}

// ---- locating the module and running a stack ----

const MODULE_FILE: &str = "libpam_idp.so";

/// The `libpam_idp.so` cargo built for this very test run.
///
/// Only this run's target directory is searched: cargo sets
/// `CARGO_TARGET_TMPDIR` to `<target-dir>/tmp` at compile time, which is right
/// under `--target-dir`, `CARGO_TARGET_DIR`, `cargo llvm-cov` and the Nix
/// build. Where the cdylib lands inside `<target-dir>/<profile>/` depends on
/// the cargo version (`deps/`, or `build/pam-idp/<hash>/` with the newer
/// build-dir layout), so that profile tree is searched and the newest copy
/// wins. Nothing outside it is considered, so a stale build elsewhere can never
/// stand in for the module under test.
fn module_path() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .expect("CARGO_TARGET_TMPDIR has a parent")
        .join(profile);
    let mut found: Option<(std::time::SystemTime, PathBuf)> = None;
    let mut dirs = vec![(root.clone(), 0u8)];
    while let Some((dir, depth)) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                // Skip `incremental/` and `.fingerprint/`; the module sits at
                // most four levels down.
                let name = entry.file_name();
                if depth < 4 && name != "incremental" && name != ".fingerprint" {
                    dirs.push((path, depth + 1));
                }
            } else if entry.file_name() == MODULE_FILE {
                let modified = meta.modified().expect("mtime is supported");
                if found.as_ref().is_none_or(|(t, _)| modified > *t) {
                    found = Some((modified, path));
                }
            }
        }
    }
    found.map_or_else(
        || {
            panic!(
                "{MODULE_FILE} not built under {} (run `cargo test` or `cargo build` first)",
                root.display()
            )
        },
        |(_, p)| p,
    )
}

/// A temporary PAM confdir holding one service file.
struct Service {
    dir: tempfile::TempDir,
    name: &'static str,
}

impl Service {
    fn new(stack: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let name = "idp-ffi-test";
        fs::write(dir.path().join(name), format!("{stack}\n")).unwrap();
        Self { dir, name }
    }

    /// A service whose first line is `pam_idp` with `control` and `args`,
    /// followed by `rest` (more stack lines, possibly empty).
    fn idp(control: &str, args: &str, rest: &str) -> Self {
        let module = module_path();
        Self::new(&format!(
            "auth {control} {} {args}\n{rest}",
            module.display()
        ))
    }
}

/// The outcome of one PAM transaction.
struct Outcome {
    auth: c_int,
}

#[derive(Clone, Copy)]
enum Op {
    Authenticate,
    Setcred,
}

fn run(
    service: &Service,
    user: Option<&str>,
    rhost: Option<&str>,
    conv: &ConvState,
    op: Op,
) -> Outcome {
    let svc = CString::new(service.name).unwrap();
    let user = user.map(|u| CString::new(u).unwrap());
    let confdir = CString::new(service.dir.path().as_os_str().as_encoded_bytes()).unwrap();
    let pam_conv = PamConv {
        conv: Some(conversation),
        appdata_ptr: ptr::from_ref(conv).cast_mut().cast::<c_void>(),
    };
    let mut pamh: *mut PamHandleT = ptr::null_mut();
    // SAFETY: every pointer is valid for the duration of the call; libpam
    // copies the strings and the conv struct.
    let rc = unsafe {
        pam_start_confdir(
            svc.as_ptr(),
            user.as_ref().map_or(ptr::null(), |u| u.as_ptr()),
            &raw const pam_conv,
            confdir.as_ptr(),
            &raw mut pamh,
        )
    };
    assert_eq!(rc, PAM_SUCCESS, "pam_start_confdir");
    assert!(!pamh.is_null());
    if let Some(rhost) = rhost {
        let rhost = CString::new(rhost).unwrap();
        // SAFETY: valid handle and string; libpam copies the item.
        let rc = unsafe { pam_set_item(pamh, PAM_RHOST, rhost.as_ptr().cast()) };
        assert_eq!(rc, PAM_SUCCESS, "pam_set_item(PAM_RHOST)");
    }
    // SAFETY: valid handle; `conv` outlives it.
    let auth = unsafe {
        match op {
            Op::Authenticate => pam_authenticate(pamh, 0),
            Op::Setcred => pam_setcred(pamh, PAM_ESTABLISH_CRED),
        }
    };
    // SAFETY: valid handle, ended exactly once.
    unsafe { pam_end(pamh, auth) };
    Outcome { auth }
}

fn authenticate(service: &Service, conv: &ConvState) -> c_int {
    run(
        service,
        Some("alice"),
        Some("192.0.2.7"),
        conv,
        Op::Authenticate,
    )
    .auth
}

fn strerror(code: c_int) -> String {
    // SAFETY: pam_strerror accepts a null handle in Linux-PAM and returns a static string.
    let s = unsafe { pam_strerror(ptr::null_mut(), code) };
    if s.is_null() {
        return code.to_string();
    }
    // SAFETY: static NUL-terminated string.
    let text = unsafe { CStr::from_ptr(s) }.to_string_lossy();
    format!("{code} ({text})")
}

#[track_caller]
fn assert_code(got: c_int, want: c_int) {
    assert_eq!(got, want, "got {}, want {}", strerror(got), strerror(want));
}

/// A client-secret file that passes the module's ownership and mode checks.
fn secret_file(dir: &Path) -> PathBuf {
    let path = dir.join("client-secret");
    fs::write(&path, "not-a-real-secret\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn ca_file(dir: &Path) -> PathBuf {
    let path = dir.join("ca.pem");
    fs::write(&path, TEST_CA_PEM).unwrap();
    path
}

const BASE_ARGS: &str = "issuer=https://idp.invalid client_id=x";

// ---- harness self-checks (libpam semantics only; pass without our module) ----

/// `pam_debug.so auth=ignore` stands in for our module returning `PAM_IGNORE`:
/// with the plan's control and `pam_permit` after it, the stack succeeds.
#[test]
fn harness_ignore_falls_through_to_next_module() {
    let svc = Service::new(&format!(
        "auth {SPEC_CONTROL} pam_debug.so auth=ignore\nauth required pam_permit.so"
    ));
    assert_code(authenticate(&svc, &ConvState::answering("1")), PAM_SUCCESS);
}

/// The stack used by [`password_choice_returns_ignore_not_success`] tells
/// `PAM_IGNORE` apart from `PAM_SUCCESS`.
#[test]
fn harness_ignore_detector_rejects_success() {
    let svc =
        Service::new("auth [ignore=ignore default=die] pam_permit.so\nauth required pam_permit.so");
    let got = authenticate(&svc, &ConvState::answering("1"));
    assert_ne!(got, PAM_SUCCESS, "got {}", strerror(got));
}

/// A failing code under the plan's control is returned as is (`default=die`),
/// and `pam_permit` after it is never reached.
#[test]
fn harness_die_returns_module_code() {
    let svc = Service::new(&format!(
        "auth {SPEC_CONTROL} pam_debug.so auth=service_err\nauth required pam_permit.so"
    ));
    assert_code(
        authenticate(&svc, &ConvState::answering("1")),
        PAM_SERVICE_ERR,
    );
}

/// `pam_deny` after an ignoring module gives `PAM_AUTH_ERR`.
#[test]
fn harness_ignore_then_deny_is_auth_err() {
    let svc = Service::new(&format!(
        "auth {SPEC_CONTROL} pam_debug.so auth=ignore\nauth required pam_deny.so"
    ));
    assert_code(authenticate(&svc, &ConvState::answering("1")), PAM_AUTH_ERR);
}

// ---- the module ----

#[test]
fn module_is_built() {
    let path = module_path();
    assert!(path.is_file(), "{}", path.display());
}

/// The plan's stack: a single `password` method skips the menu, returns
/// `PAM_IGNORE`, and the next module decides.
#[test]
fn single_password_method_hands_off_to_next_module() {
    let svc = Service::idp(
        SPEC_CONTROL,
        &format!("methods=password {BASE_ARGS}"),
        "auth required pam_permit.so",
    );
    let conv = ConvState::answering("1");
    assert_code(authenticate(&svc, &conv), PAM_SUCCESS);
    assert_eq!(
        conv.count(PAM_PROMPT_ECHO_ON),
        0,
        "no menu: {:?}",
        conv.seen()
    );
}

/// The same choice with the following module denying: `ignore=ignore`
/// passes the decision on, so the stack fails with `pam_deny`'s code.
#[test]
fn password_choice_then_deny_fails() {
    let svc = Service::idp(
        SPEC_CONTROL,
        &format!("methods=password {BASE_ARGS}"),
        "auth required pam_deny.so",
    );
    assert_code(authenticate(&svc, &ConvState::answering("1")), PAM_AUTH_ERR);
}

/// Only `PAM_IGNORE` gets past `[ignore=ignore default=die]`.
#[test]
fn password_choice_returns_ignore_not_success() {
    let svc = Service::idp(
        "[ignore=ignore default=die]",
        &format!("methods=password {BASE_ARGS}"),
        "auth required pam_permit.so",
    );
    assert_code(authenticate(&svc, &ConvState::answering("1")), PAM_SUCCESS);
}

/// The menu: info lines with the labels, one echo-on prompt answered "1"
/// (the password entry, listed first), then `PAM_IGNORE`.
#[test]
fn menu_answer_one_picks_password() {
    let svc = Service::idp(
        SPEC_CONTROL,
        &format!("methods=password,sso default=sso {BASE_ARGS}"),
        "auth required pam_permit.so",
    );
    let conv = ConvState::answering("1");
    assert_code(authenticate(&svc, &conv), PAM_SUCCESS);
    assert_eq!(conv.count(PAM_PROMPT_ECHO_ON), 1, "{:?}", conv.seen());
    assert_eq!(conv.count(PAM_PROMPT_ECHO_OFF), 0, "{:?}", conv.seen());
    let shown = conv.texts(PAM_TEXT_INFO).join("\n");
    assert!(shown.contains("1)"), "{:?}", conv.seen());
    assert!(shown.contains("2)"), "{:?}", conv.seen());
    assert!(
        shown.contains("Password"),
        "default label shown: {:?}",
        conv.seen()
    );
}

/// Custom labels reach the conversation unchanged.
#[test]
fn menu_shows_custom_labels() {
    let svc = Service::idp(
        SPEC_CONTROL,
        &format!("methods=password,sso labels=Directory,Browser {BASE_ARGS}"),
        "auth required pam_permit.so",
    );
    let conv = ConvState::answering("1");
    assert_code(authenticate(&svc, &conv), PAM_SUCCESS);
    let shown = conv.texts(PAM_TEXT_INFO).join("\n");
    assert!(
        shown.contains("Directory") && shown.contains("Browser"),
        "{:?}",
        conv.seen()
    );
}

/// Three bad menu answers: error lines through the conversation, then `PAM_MAXTRIES`.
#[test]
fn bad_menu_answers_give_maxtries() {
    let svc = Service::idp("required", &format!("methods=password,sso {BASE_ARGS}"), "");
    let conv = ConvState::answering("9");
    assert_code(authenticate(&svc, &conv), PAM_MAXTRIES);
    assert_eq!(conv.count(PAM_PROMPT_ECHO_ON), 3, "{:?}", conv.seen());
    assert!(conv.count(PAM_ERROR_MSG) >= 1, "{:?}", conv.seen());
}

/// A failing conversation function is `PAM_CONV_ERR`.
#[test]
fn failing_conversation_gives_conv_err() {
    let svc = Service::idp("required", &format!("methods=password,sso {BASE_ARGS}"), "");
    assert_code(authenticate(&svc, &ConvState::failing()), PAM_CONV_ERR);
}

/// SSO against an unresolvable issuer: `PAM_AUTHINFO_UNAVAIL`, and the
/// plan's control does not fall through to the next module.
#[test]
fn sso_with_unreachable_idp_is_authinfo_unavail() {
    let dir = tempfile::tempdir().unwrap();
    let args = format!(
        "methods=sso {BASE_ARGS} secret_file={} ca_file={} connect_timeout=2 timeout=2 max_wait=5 wait=poll qr=off",
        secret_file(dir.path()).display(),
        ca_file(dir.path()).display(),
    );
    let required = Service::idp("required", &args, "");
    assert_code(
        authenticate(&required, &ConvState::answering("")),
        PAM_AUTHINFO_UNAVAIL,
    );

    let spec = Service::idp(SPEC_CONTROL, &args, "auth required pam_permit.so");
    let got = authenticate(&spec, &ConvState::answering(""));
    assert_ne!(
        got,
        PAM_SUCCESS,
        "default=die must stop the stack: {}",
        strerror(got)
    );
}

// ---- bad arguments ----

fn assert_service_err(args: &str) {
    let svc = Service::idp("required", args, "");
    let conv = ConvState::answering("1");
    assert_code(authenticate(&svc, &conv), PAM_SERVICE_ERR);
    assert!(
        conv.seen().is_empty(),
        "no conversation on bad args: {:?}",
        conv.seen()
    );
}

#[test]
fn unknown_argument_is_service_err() {
    assert_service_err(&format!("methods=password {BASE_ARGS} bogus=1"));
}

#[test]
fn missing_issuer_is_service_err() {
    assert_service_err("methods=password client_id=x");
}

#[test]
fn missing_client_id_is_service_err() {
    assert_service_err("methods=password issuer=https://idp.invalid");
}

#[test]
fn http_issuer_is_service_err() {
    assert_service_err("methods=password issuer=http://idp.invalid client_id=x");
}

#[test]
fn unknown_method_is_service_err() {
    assert_service_err(&format!("methods=password,carrier-pigeon {BASE_ARGS}"));
}

/// Bad arguments under the plan's control stop the stack (`default=die`)
/// even though `pam_permit` follows.
#[test]
fn bad_args_in_plan_stack_fail() {
    let svc = Service::idp(
        SPEC_CONTROL,
        &format!("methods=password {BASE_ARGS} bogus=1"),
        "auth required pam_permit.so",
    );
    assert_code(
        authenticate(&svc, &ConvState::answering("1")),
        PAM_SERVICE_ERR,
    );
}

// ---- setcred ----

#[test]
fn setcred_succeeds() {
    let svc = Service::idp("required", &format!("methods=password {BASE_ARGS}"), "");
    let conv = ConvState::answering("1");
    let out = run(&svc, Some("alice"), None, &conv, Op::Setcred);
    assert_code(out.auth, PAM_SUCCESS);
    assert!(conv.seen().is_empty(), "{:?}", conv.seen());
}
