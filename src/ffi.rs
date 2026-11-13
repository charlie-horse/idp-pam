//! PAM entry points: glue from `pam-bindings` to [`crate::authenticate`].
//!
//! Kept tiny and branch-free; excluded from coverage and exercised end to end
//! by `tests/ffi.rs` and `scripts/pamtester.sh`. `pam_hooks!` wraps each hook
//! in `catch_unwind` and returns `PAM_ABORT` on a panic.

use std::ffi::{CStr, CString, c_char, c_int};

use pam_bindings::constants::{
    PAM_ERROR_MSG, PAM_PROMPT_ECHO_ON, PAM_TEXT_INFO, PamFlag, PamMessageStyle, PamResultCode,
};
use pam_bindings::items::{RHost, Service};
use pam_bindings::module::{PamHandle, PamHooks};
use pam_bindings::pam_hooks;
use pam_bindings::secret::SecretBytes;

use crate::error::Error;
use crate::pam::{Conv, Logger, PamItems};
use crate::{Deps, authenticate, setcred};

unsafe extern "C" {
    /// `void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)`.
    /// Always called with the format `"%s"`.
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// The hook implementation registered with `pam_hooks!`.
pub struct PamIdp;

pam_hooks!(PamIdp);

impl PamHooks for PamIdp {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let items = HandleItems::new(pamh);
        let pamh: &PamHandle = pamh;
        let conv = HandleConv::new(pamh);
        let logger = Syslog(pamh);
        let deps = Deps {
            http: &crate::http::build_client,
            sleeper: &crate::time::ThreadSleeper,
            clock: &crate::time::SystemClock,
            secrets: &crate::secret::FileSecretSource,
            logger: &logger,
        };
        authenticate(&args, &conv, &items, &deps).to_pam()
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        setcred().to_pam()
    }
}

/// [`PamItems`] over a handle. The user is fetched up front with
/// `pam_get_user` (which needs `&mut`), before the conversation borrows the handle.
struct HandleItems {
    user: Result<String, Error>,
    service: Option<String>,
    rhost: Option<String>,
}

impl HandleItems {
    fn new(pamh: &mut PamHandle) -> Self {
        let user = pamh.get_user(None).map_err(|_| Error::UserUnknown);
        let pamh: &PamHandle = pamh;
        Self {
            user,
            service: pamh
                .get_item::<Service>()
                .ok()
                .flatten()
                .map(|s| s.to_string_lossy().into_owned()),
            rhost: pamh
                .get_item::<RHost>()
                .ok()
                .flatten()
                .map(|r| r.to_string_lossy().into_owned()),
        }
    }
}

impl PamItems for HandleItems {
    fn user(&self) -> Result<String, Error> {
        self.user.clone()
    }

    fn service(&self) -> Option<String> {
        self.service.clone()
    }

    fn rhost(&self) -> Option<String> {
        self.rhost.clone()
    }

    fn account_name(&self) -> Option<String> {
        crate::nss::account_name(self.user.as_ref().ok()?)
    }
}

/// [`Conv`] over the handle's `PAM_CONV` item (one message per call).
struct HandleConv<'a> {
    conv: Option<pam_bindings::conv::Conv<'a>>,
}

impl<'a> HandleConv<'a> {
    fn new(pamh: &'a PamHandle) -> Self {
        Self {
            conv: pamh.get_item().ok().flatten(),
        }
    }

    /// Sends one message; any failure (no conversation, error code) is [`Error::Conv`].
    fn send(&self, style: PamMessageStyle, msg: &str) -> Result<Option<SecretBytes>, Error> {
        self.conv
            .as_ref()
            .ok_or(Error::Conv)?
            .send(style, msg)
            .map_err(|_| Error::Conv)
    }
}

impl Conv for HandleConv<'_> {
    fn info(&self, msg: &str) -> Result<(), Error> {
        self.send(PAM_TEXT_INFO, msg).map(drop)
    }

    fn error_msg(&self, msg: &str) -> Result<(), Error> {
        self.send(PAM_ERROR_MSG, msg).map(drop)
    }

    fn prompt_echo_on(&self, prompt: &str) -> Result<String, Error> {
        Ok(self
            .send(PAM_PROMPT_ECHO_ON, prompt)?
            .map(|answer| String::from_utf8_lossy(answer.as_bytes()).into_owned())
            .unwrap_or_default())
    }
}

/// [`Logger`] over `pam_syslog(pamh, LOG_AUTHPRIV | LOG_INFO, "%s", msg)`.
struct Syslog<'a>(&'a PamHandle);

impl Logger for Syslog<'_> {
    fn log(&self, msg: &str) {
        // `log::auth_line` replaces control characters, so there is no NUL to reject.
        if let Ok(msg) = CString::new(msg) {
            // SAFETY: `self.0` is the live handle of this hook call, and the
            // format `"%s"` consumes exactly the one NUL-terminated string passed.
            unsafe {
                pam_syslog(
                    self.0,
                    libc::LOG_AUTHPRIV | libc::LOG_INFO,
                    c"%s".as_ptr(),
                    msg.as_ptr(),
                );
            }
        }
    }
}
