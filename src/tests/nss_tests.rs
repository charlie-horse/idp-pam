//! Unit tests for `nss`. They use `root`, which every passwd database
//! (including the Nix build sandbox's) has.

#[allow(unused_imports)]
use super::*;

#[test]
fn root_resolves_to_root() {
    assert_eq!(account_name("root").as_deref(), Some("root"));
}

#[test]
fn unknown_user_has_no_account() {
    assert_eq!(account_name("pam-idp-no-such-user-7f3a"), None);
}

#[test]
fn empty_name_has_no_account() {
    assert_eq!(account_name(""), None);
}

#[test]
fn name_with_nul_has_no_account() {
    assert_eq!(account_name("root\0x"), None);
}
