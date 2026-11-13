# Security policy

`pam_idp` runs inside sshd and login as root and decides who may log in, so we take reports seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (<https://github.com/charlie-horse/idp-pam/security/advisories/new>).

Do not open a public issue or pull request for a vulnerability.

Please include:

- what an attacker can do, and what they need first (network position, a valid account, an IdP account, …);
- the module arguments, the PAM stack and the sshd settings involved;
- steps to reproduce, ideally against `examples/mock_idp` or with the tests in this repository;
- the commit or release you tested.

Never include real client secrets, tokens or device codes in a report.

We aim to acknowledge a report within a week, agree on a fix and a disclosure date with you, and credit you in the advisory unless you prefer otherwise.

## Supported versions

Only the latest commit on `main` is supported. Fixes are not backported.

## Scope

In scope: the module itself (argument parsing, the menu, the device flow, ID-token and claim checks, TLS, handling of the client secret, logging, the FFI glue), its Nix packaging, and the CI workflows in this repository.

Out of scope: vulnerabilities in the identity provider, OpenSSH, Linux-PAM or the dependencies themselves (please report those upstream; tell us too if `pam_idp` is affected), and the device-code phishing risk inherent in RFC 8628, which the README describes.
