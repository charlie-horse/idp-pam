//! Unit tests for `secret::FileSecretSource`: ownership, mode and file-type
//! checks, newline trimming, and secret-free error messages.

#[allow(unused_imports)]
use super::*;

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

use crate::error::Error;

const CONTENT: &str = "s3cret-Value_42";

/// Writes `content` to `dir/name` with `mode` and returns the path.
fn write(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, content).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn read(p: &Path) -> Result<String, Error> {
    FileSecretSource
        .read(p)
        .map(|s| s.expose_secret().to_owned())
}

fn assert_secret_err(r: Result<String, Error>, path: &Path) {
    match r {
        Err(Error::Secret(msg)) => {
            assert!(
                !msg.contains(CONTENT),
                "error message leaks the secret: {msg:?}"
            );
            assert!(
                msg.contains(&*path.to_string_lossy()),
                "error message should name the path: {msg:?}"
            );
        }
        other => panic!("expected Error::Secret, got {other:?}"),
    }
}

#[test]
fn reads_0600_file_and_trims_newline() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", &format!("{CONTENT}\n"), 0o600);
    assert_eq!(read(&p).unwrap(), CONTENT);
}

#[test]
fn reads_file_without_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", CONTENT, 0o600);
    assert_eq!(read(&p).unwrap(), CONTENT);
}

#[test]
fn trims_crlf() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", &format!("{CONTENT}\r\n"), 0o600);
    assert_eq!(read(&p).unwrap(), CONTENT);
}

#[test]
fn trims_only_one_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", &format!("{CONTENT}\n\n"), 0o600);
    assert_eq!(read(&p).unwrap(), format!("{CONTENT}\n"));
}

#[test]
fn keeps_inner_and_leading_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", " a b\tc\n", 0o600);
    assert_eq!(read(&p).unwrap(), " a b\tc");
}

#[test]
fn accepts_0400_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", CONTENT, 0o400);
    assert_eq!(read(&p).unwrap(), CONTENT);
}

#[test]
fn rejects_world_readable_0644() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", CONTENT, 0o644);
    assert_secret_err(read(&p), &p);
}

#[test]
fn rejects_any_group_or_other_bit() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o660, 0o666] {
        let p = write(dir.path(), &format!("s{mode:o}"), CONTENT, mode);
        assert_secret_err(read(&p), &p);
    }
}

#[test]
fn rejects_symlink_to_good_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = write(dir.path(), "target", CONTENT, 0o600);
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    assert_secret_err(read(&link), &link);
}

#[test]
fn rejects_directory() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().join("d");
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    assert_secret_err(read(&d), &d);
}

#[test]
fn rejects_fifo_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("fifo");
    let c = CString::new(f.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
    // Opening a FIFO for reading blocks until a writer appears; the check
    // must reject it without hanging.
    assert_secret_err(read(&f), &f);
}

#[test]
fn rejects_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("missing");
    assert_secret_err(read(&p), &p);
}

#[test]
fn rejects_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", "", 0o600);
    assert_secret_err(read(&p), &p);
}

#[test]
fn rejects_file_with_only_a_newline() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", "\n", 0o600);
    assert_secret_err(read(&p), &p);
}

#[test]
fn rejects_file_owned_by_another_user() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", CONTENT, 0o600);
    // Only possible as root; elsewhere (e.g. the Nix build sandbox) skip.
    if std::os::unix::fs::chown(&p, Some(54_321), None).is_err() {
        eprintln!("skipping: cannot chown (not root)");
        return;
    }
    assert_secret_err(read(&p), &p);
}

#[test]
fn unreadable_file_depends_on_privilege() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(dir.path(), "s", CONTENT, 0o000);
    if fs::read(&p).is_ok() {
        // Root can read a 0000 file it owns, and the mode has no group/other bits.
        assert_eq!(read(&p).unwrap(), CONTENT);
    } else {
        assert_secret_err(read(&p), &p);
    }
}

#[test]
fn rejects_non_utf8_content() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s");
    fs::write(&p, [0xff, 0xfe, b'\n']).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert_secret_err(read(&p), &p);
}
