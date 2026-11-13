//! Reading the OAuth client secret.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use secrecy::SecretString;

use crate::error::Error;

/// Source of the client secret (a file in production).
pub trait SecretSource {
    /// Reads the secret stored at `path`.
    ///
    /// # Errors
    /// [`Error::Secret`] if it cannot be read or fails the safety checks.
    fn read(&self, path: &Path) -> Result<SecretString, Error>;
}

/// Reads the secret from a file, refusing it unless it is a regular file
/// (symlinks are not followed), owned by the effective uid, with
/// `mode & 0o077 == 0`. One trailing `\n` (or `\r\n`) is removed; an empty
/// secret is an error. Error messages name the path but never the content.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileSecretSource;

impl SecretSource for FileSecretSource {
    fn read(&self, path: &Path) -> Result<SecretString, Error> {
        let fail = |why: &dyn std::fmt::Display| {
            Error::Secret(format!("client secret file {}: {why}", path.display()))
        };
        // O_NOFOLLOW refuses a symlink; O_NONBLOCK keeps a FIFO from blocking
        // the open (it is then refused as not a regular file).
        let (mut file, meta) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|f| f.metadata().map(|m| (f, m)))
            .map_err(|e| fail(&e))?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !meta.is_file() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
            return Err(fail(
                &"must be a regular file owned by the effective uid, with no group or other permissions",
            ));
        }
        let mut text = String::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        file.read_to_string(&mut text).map_err(|e| fail(&e))?;
        let len = text
            .strip_suffix('\n')
            .map_or(text.len(), |s| s.strip_suffix('\r').unwrap_or(s).len());
        if len == 0 {
            return Err(fail(&"is empty"));
        }
        text.truncate(len);
        Ok(SecretString::from(text))
    }
}

#[cfg(test)]
#[path = "tests/secret_tests.rs"]
mod tests;
