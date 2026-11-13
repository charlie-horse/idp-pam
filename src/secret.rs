//! Reading the OAuth client secret.

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
    fn read(&self, _path: &Path) -> Result<SecretString, Error> {
        todo!()
    }
}

#[cfg(test)]
#[path = "tests/secret_tests.rs"]
mod tests;
