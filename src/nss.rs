//! The account behind `PAM_USER`, from NSS (`getpwnam_r`).
//!
//! The ID token's username claim is compared with `PAM_USER`, but sshd and
//! login start the session for whatever passwd entry `getpwnam(PAM_USER)`
//! returns. With a case-insensitive NSS backend (SSSD with
//! `case_sensitive = false`, nslcd with `ignorecase`), `Alice` can resolve to
//! `alice`'s entry. [`crate::authenticate`] therefore also requires the
//! entry's own name to equal `PAM_USER`.

use std::ffi::{CStr, CString, c_char};
use std::mem::MaybeUninit;
use std::ptr;

/// Buffer for `getpwnam_r`'s strings. Far above glibc's
/// `_SC_GETPW_R_SIZE_MAX` (1024); an entry that does not fit is treated as
/// missing (fail closed).
const BUF_LEN: usize = 16 * 1024;

/// The `pw_name` of the passwd entry that `user` resolves to, or `None` if
/// there is none (or the lookup fails, or `user` holds a NUL).
#[must_use]
pub fn account_name(user: &str) -> Option<String> {
    let name = CString::new(user).ok()?;
    let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
    let mut buf: Vec<c_char> = vec![0; BUF_LEN];
    let mut result: *mut libc::passwd = ptr::null_mut();
    // SAFETY: every pointer is valid for the call: `name` is NUL-terminated,
    // `pwd` and `result` are writable, and `buf` is writable for `buf.len()`
    // bytes. `getpwnam_r` is thread-safe and sets `result` to NULL on any
    // failure or a missing entry.
    unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        );
    }
    if result.is_null() {
        return None;
    }
    // SAFETY: `result` points at `pwd`, filled in by the successful call;
    // its `pw_name` is a NUL-terminated string inside `buf`, still alive.
    let pw_name = unsafe { CStr::from_ptr((*result).pw_name) };
    Some(pw_name.to_string_lossy().into_owned())
}

#[cfg(test)]
#[path = "tests/nss_tests.rs"]
mod tests;
