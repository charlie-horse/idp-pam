# idp-pam

`pam_idp` is a PAM module for SSH and console logins. It shows a numbered menu that lets the user pick between their directory password and single sign-on. When the user picks SSO, it runs the OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) against an OpenID Connect provider (built and tested against [Authentik](https://goauthentik.io/)), shows a link, a code and a QR code, waits for approval, and verifies the ID token.

```
1) Password
2) Single sign-on (browser or phone)
Choose a login method (Enter for Single sign-on (browser or phone)): 2
To sign in, open https://auth.example.com/device?code=WDJB-MJHT
Or go to https://auth.example.com/device and enter the code WDJB-MJHT
█▀▀▀▀▀█ ▄▀▄ █▀▀▀▀▀█
...
Press Enter once you've approved (q to cancel):
```

It works with a stock OpenSSH client (keyboard-interactive) and at the console, with no daemon and no client-side software.

- If the user picks the password, the module returns `PAM_IGNORE`, and the next module in the stack (for example `pam_sss`) asks for the password.
- If the user picks SSO, the module returns `PAM_SUCCESS` only when the ID token's signature, issuer, audience, expiry and `iat` check out, the username claim equals `PAM_USER`, and (if configured) the user is in one of the required groups.

The module is written in Rust on top of [`openidconnect`](https://crates.io/crates/openidconnect) (discovery, device flow, polling, ID-token verification), [`ureq`](https://crates.io/crates/ureq) with rustls (HTTPS), [`pam-bindings`](https://crates.io/crates/pam-bindings) and [`qrcode`](https://crates.io/crates/qrcode). It has no async runtime, starts no threads and reads no environment variables.

## Build and install

### With Nix

The flake builds the module for `x86_64-linux` and `aarch64-linux`. The output is `lib/security/pam_idp.so`.

```console
$ nix build github:charlie-horse/idp-pam
$ ls result/lib/security/
pam_idp.so
```

On NixOS, add the flake as an input (with `inputs.nixpkgs.follows = "nixpkgs"`), apply `overlays.default`, and refer to the module by its store path, `${pkgs.pam-idp}/lib/security/pam_idp.so`, in the PAM service's rules.

The flake also provides:

| Output | What it is |
| --- | --- |
| `packages.<system>.{default,pam-idp}` | The module; the build runs `cargo test` |
| `overlays.default` | Adds `pam-idp` to nixpkgs |
| `checks.<system>.{build,clippy,fmt}` | The build with its tests, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` |
| `devShells.<system>.default` | cargo, clippy, rustfmt, rust-analyzer, PAM headers, pamtester, cargo-deny and cargo-llvm-cov |
| `formatter.<system>` | nixfmt |

### Without Nix

You need Rust 1.88 or newer and the PAM headers (`libpam0g-dev` on Debian and Ubuntu, `pam-devel` on Fedora).

```console
$ cargo build --release --locked
# install -m 0644 target/release/libpam_idp.so /lib/x86_64-linux-gnu/security/pam_idp.so
```

The module directory depends on the distribution (`/lib/security`, `/usr/lib64/security`, …). If you install the file somewhere else, give the full path in the PAM config.

## Module arguments

Arguments are `key=value` words on the PAM line. Lists are comma-separated and durations are whole seconds. An unknown key, a key given twice, a bad value or any URL that isn't `https` makes the module return `PAM_SERVICE_ERR`.

| Key | Default | Meaning |
| --- | --- | --- |
| `methods` | `password,sso` | Menu entries, in order. With a single entry the menu is skipped |
| `default` | first of `methods` | The method an empty answer picks |
| `labels` | `Password`, `Single sign-on (browser or phone)` | Menu labels, comma-separated, in `methods` order |
| `issuer` | required | OIDC issuer URL (`https`) |
| `client_id` | required | OAuth client ID |
| `secret_file` | `/var/lib/secrets/login-sso-client-secret` | File holding the client secret |
| `ca_file` | `/etc/ssl/certs/ca-certificates.crt` | PEM bundle; the only TLS roots the module trusts |
| `device_endpoint` | from discovery | Overrides `device_authorization_endpoint` (`https`, on the issuer's host) |
| `scopes` | `openid,profile` | Requested scopes |
| `username_claim` | `preferred_username` | ID-token claim that must equal `PAM_USER` |
| `groups_claim` | `groups` | ID-token claim that holds the user's groups |
| `require_group` | none (no check) | The user must be in at least one of these groups |
| `connect_timeout` | `10` | TCP and TLS connect timeout |
| `timeout` | `30` | Timeout for each later phase of an HTTP request |
| `max_wait` | `600` | Upper bound on the whole device flow, from the start; the IdP's code expiry also applies |
| `wait` | `auto` | `enter`: show "Press Enter once you've approved (q to cancel)" and poll after Enter. `poll`: poll right after showing the code. `auto`: `enter` for the `sshd` service, `poll` otherwise |
| `qr` | `on` | `on`, `off` (for console fonts without half-block characters) or `invert` |
| `debug` | off | Bare flag, or `debug=true` / `debug=false`. Accepted, but it currently changes nothing |

PAM splits arguments at spaces. To put spaces in a label, wrap the whole argument in brackets: `[labels=Directory password,Single sign-on]`.

Every endpoint the module talks to (discovery, JWKS, device authorization, token) must be `https` and on the issuer's host. The HTTP client follows no redirects, uses no proxy and caps response bodies at 64 KiB.

## PAM stack

The intended `auth` stack, for example in `/etc/pam.d/sshd`:

```
auth [success=1 default=ignore]               pam_succeed_if.so uid >= 10000 uid <= 99999 quiet
auth [success=done default=die]               pam_unix.so          # local accounts (root, admins)
auth [success=done ignore=ignore default=die] pam_idp.so methods=password,sso default=sso issuer=https://auth.example.com/application/o/login/ client_id=...
auth [success=done default=die]               pam_sss.so           # the directory password
```

1. Directory users (uids 10000–99999 here) skip `pam_unix`. Local accounts are handled by `pam_unix` alone and never see the menu.
2. `pam_idp` shows the menu.
   - SSO verified: `success=done`, the login succeeds.
   - Password chosen: `PAM_IGNORE`, so `ignore=ignore` falls through to `pam_sss`, which asks for the password.
   - Anything else (denied, expired, cancelled, wrong user, IdP unreachable, …): `default=die`, the login fails and `pam_sss` is never asked.

What the module returns:

| Outcome | PAM code |
| --- | --- |
| SSO verified | `PAM_SUCCESS` |
| Password chosen | `PAM_IGNORE` |
| Wrong username, missing group, bad ID-token signature or claims | `PAM_AUTH_ERR` |
| Denied at the IdP, code expired, `max_wait` reached, cancelled with `q`, or three invalid menu answers | `PAM_MAXTRIES` |
| Network, TLS, IdP or client-secret file problem | `PAM_AUTHINFO_UNAVAIL` |
| `PAM_USER` unavailable | `PAM_USER_UNKNOWN` |
| Conversation failure | `PAM_CONV_ERR` |
| Bad arguments | `PAM_SERVICE_ERR` |
| Panic inside the module | `PAM_ABORT` |

`pam_sm_setcred` returns `PAM_SUCCESS`. The account, session and password hooks return `PAM_IGNORE`.

### The account phase

`pam_idp` only authenticates. It does not decide whether the account may log in, so the `account` stack must still do that, for example:

```
account required pam_unix.so
# once SSSD serves the directory users:
account [default=bad success=ok user_unknown=ignore] pam_sss.so
```

The user must also exist for NSS (through SSSD, LDAP or a local entry) before sshd even starts PAM. An SSO approval for a name that doesn't resolve is useless.

## sshd

In `sshd_config`:

```
UsePAM yes
KbdInteractiveAuthentication yes
# Longer than max_wait (default 600 s), or sshd drops the connection while the user approves.
LoginGraceTime 660
```

- The menu and the device-flow prompts run over keyboard-interactive authentication, so every stock OpenSSH client works.
- Keep `PasswordAuthentication no` if you want every password to go through the menu (and therefore through PAM's keyboard-interactive path).
- SSH keys keep working as usual. With the default `AuthenticationMethods`, a key, or keyboard-interactive (SSO or password), is enough.
- sshd shows PAM info messages only together with the next prompt. That is why `wait=auto` uses the Enter prompt for the `sshd` service: without it the user wouldn't see the code until polling had ended.

## Authentik setup

1. Create an **OAuth2/OpenID Provider**:
   - **Client type: Confidential.** Put the client secret into `secret_file` (see below).
   - **Signing key:** choose an RSA certificate. The module accepts only RS256-signed ID tokens. Without a signing key, Authentik signs with HS256, which is refused.
   - **Access code validity:** longer than `max_wait`. Authentik uses it as the device code's lifetime, and its default (1 minute) is far too short to approve on a phone.
   - **Scopes:** `openid` and `profile`. Authentik's default `profile` mapping puts `groups` into the token. If you use your own mappings, add one that provides the `groups_claim` and list its scope in `scopes`.
   - **Include claims in id_token:** on. The module reads `preferred_username` and `groups` from the ID token, not from the userinfo endpoint.
   - No redirect URI is needed for the device flow.
2. Create an **Application** for the provider. Its slug is part of the issuer: `https://auth.example.com/application/o/<slug>/`, trailing slash included. Bind the users or groups allowed to use it.
3. Enable the device flow: under **System → Brands**, set **Device code flow** for the brand that serves the issuer's host. Authentik shows that flow at `/device`, where users enter the code (see Authentik's device code flow documentation).
4. Check that `https://auth.example.com/application/o/<slug>/.well-known/openid-configuration` lists `device_authorization_endpoint`. If it doesn't, set `device_endpoint`.

## Security notes

- **Device-code phishing.** The device flow lets anyone who can get a user to open a link and approve it sign in as that user. The approval page shows which application is asking; teach users to approve only a code they have just been shown by their own login. Keep `max_wait` and the code validity short, and use `require_group` to limit SSO to the people who need it.
- **The client secret.** `secret_file` must be a regular file (symlinks are not followed), owned by the user the module runs as (root for sshd and login), with no group or other permission bits (`chmod 0600`). Otherwise the module refuses it and returns `PAM_AUTHINFO_UNAVAIL`. Error messages name the path, never the content. The secret is held in a `secrecy::SecretString`, which is zeroed when dropped and never printed.
- **TLS.** The module trusts only the certificates in `ca_file`, never the system store or a bundled root list. Point `ca_file` at a bundle with just your IdP's CA to narrow it further. TLS is rustls with the ring provider.
- **Token checks.** RS256 signature against the provider's JWKS, issuer, audience (`client_id`), expiry, and `iat` no more than 60 seconds in the future. The username claim must equal `PAM_USER` exactly.
- **What is logged.** One syslog line per authentication (facility `authpriv`, level `info`), with the user, remote host, method and outcome, for example `pam_idp: user=alice rhost=192.0.2.7 method=sso outcome=success`. Never secrets, codes, tokens or claims. Control characters, whitespace and `=` in the user and remote host are replaced with `?`, so a crafted name cannot forge or split the line.
- **No panics across FFI.** `pam-bindings` catches panics in the hooks and returns `PAM_ABORT`; the release profile keeps `panic = "unwind"` so that this works.
- **The `.so` dependency tree** has no tokio, reqwest or webpki-roots; `deny.toml` bans tokio and reqwest, and `cargo deny check` enforces it.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Testing

```console
$ nix develop          # or install Rust, the PAM headers and pamtester yourself
$ cargo test
```

- Unit tests sit next to each module (`src/tests/`). Every side effect (the PAM conversation and items, HTTP, time, the secret file, syslog) is behind a trait, so `authenticate` is tested without PAM or a network.
- `tests/sso.rs` runs `authenticate` end to end against [`httpmock`](https://crates.io/crates/httpmock) over TLS: approval after `authorization_pending`, required groups, denial, expiry, wrong user, missing group, a token signed by an unknown key, cancel at the Enter prompt, the password choice, an untrusted CA, an unreachable IdP, an unsafe secret file and an `http://` issuer. The unit tests of `http.rs` and `oidc.rs` cover `slow_down`, the deadline, the ID-token checks and the HTTP client's limits.
- `tests/ffi.rs` loads the built `pam_idp.so` into the system's libpam with `pam_start_confdir` and a temporary PAM service directory.

### Coverage

CI requires 100% line and region coverage:

```console
$ cargo llvm-cov --all-targets --fail-under-lines 100 --fail-under-regions 100 \
    --ignore-filename-regex '(src/ffi\.rs|src/tests/|tests/|examples/)'
```

The exclusions:

- `src/ffi.rs` is the only excluded library code. It holds the `pam_hooks!` glue that turns the raw PAM handle into the traits, plus the `pam_syslog` call. It only runs when libpam loads the module, where llvm-cov cannot measure it, so `tests/ffi.rs` and `scripts/pamtester.sh` cover it end to end.
- Test code (`src/tests/`, `tests/`) and `examples/` are not measured.

### pamtester

`scripts/pamtester.sh` exercises the built module through the real PAM stack against a mock IdP. Run it on a scratch machine or container, because it writes `/etc/pam.d/idp-test*` and adds two throwaway users (it removes both on exit):

```console
$ cargo build --release
$ cargo run --release --example mock_idp      # leave running
# scripts/pamtester.sh                          # as root, in a second terminal
```

It covers SSO approval, denial, wrong user, menu option 1 (password), bad menu input, cancel and approve at the Enter prompt, an unreachable IdP, and a local uid that skips the menu.

## CI

| Workflow | What it does |
| --- | --- |
| `check.yml` | `nix flake check -L` on `ubuntu-24.04` and `ubuntu-24.04-arm` (build, tests, clippy, rustfmt on both architectures), plus the coverage gate |
| `codeql.yml` | CodeQL for Rust (`build-mode: none`) on pushes, pull requests and weekly |
| `deny.yml` | `cargo deny check`: RustSec advisories, licences, banned crates and sources, on pushes, pull requests and daily |
| `zizmor.yml` | Lints the workflows with zizmor and uploads the results to code scanning |
| `dependabot.yml` | Weekly grouped updates for Cargo and GitHub Actions |

Every action is pinned to a full commit SHA, the workflows default to `permissions: {}` with per-job grants, and checkouts don't keep credentials.

### Repository settings to turn on by hand

These can't be set from files in the repository. Under **Settings → Advanced Security** (or **Code security**):

- Dependabot alerts (and Dependabot security updates)
- Secret scanning and push protection
- Private vulnerability reporting
- Code scanning: leave CodeQL's *default setup* off, since `codeql.yml` is the advanced setup

Optionally, add a branch ruleset for `main` that requires the `check`, `cargo-deny`, `codeql` and `zizmor` workflows, and code-scanning results with no new alerts.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
