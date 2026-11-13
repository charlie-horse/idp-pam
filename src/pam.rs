//! Traits over the PAM side effects, so that the logic can be tested
//! without a PAM handle. `ffi.rs` implements them over `pam-bindings`.

use crate::error::Error;

/// The PAM conversation (one message per call).
pub trait Conv {
    /// Shows an informational line (`PAM_TEXT_INFO`).
    ///
    /// # Errors
    /// [`Error::Conv`] if the conversation function fails.
    fn info(&self, msg: &str) -> Result<(), Error>;

    /// Shows an error line (`PAM_ERROR_MSG`).
    ///
    /// # Errors
    /// [`Error::Conv`] if the conversation function fails.
    fn error_msg(&self, msg: &str) -> Result<(), Error>;

    /// Asks a question with echo on (`PAM_PROMPT_ECHO_ON`) and returns the answer.
    /// A missing (null) answer is returned as an empty string.
    ///
    /// # Errors
    /// [`Error::Conv`] if the conversation function fails.
    fn prompt_echo_on(&self, prompt: &str) -> Result<String, Error>;
}

/// The PAM items the module reads.
pub trait PamItems {
    /// `PAM_USER`, via `pam_get_user` (which may prompt).
    ///
    /// # Errors
    /// [`Error::UserUnknown`] if PAM cannot supply it.
    fn user(&self) -> Result<String, Error>;

    /// `PAM_SERVICE`, e.g. `"sshd"` or `"login"`.
    fn service(&self) -> Option<String>;

    /// `PAM_RHOST`, the remote host, if any.
    fn rhost(&self) -> Option<String>;
}

/// Destination for the single syslog line per authentication (`pam_syslog` in production).
pub trait Logger {
    /// Writes one line; the caller has already formatted and sanitised it.
    fn log(&self, msg: &str);
}

#[cfg(test)]
#[path = "tests/pam_tests.rs"]
mod tests;
