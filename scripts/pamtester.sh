#!/usr/bin/env bash
# End-to-end check of pam_idp.so with pamtester against examples/mock_idp.
#
# Usage (as root, on a scratch machine or container):
#   1. As any user:  cargo build --release
#                    cargo run --release --example mock_idp -- /tmp/pam-idp-mock
#   2. As root:      MOCK_DIR=/tmp/pam-idp-mock scripts/pamtester.sh
#
# The script writes /etc/pam.d/idp-test (and idp-test-enter, idp-test-down)
# with the plan's stack, pam_permit standing in for pam_sss, creates two
# throwaway local users, runs the cases below and prints a pass/fail
# summary. Everything it creates is removed on exit.
#
# Contract with examples/mock_idp (see its module doc):
#   MOCK_DIR (default: the current directory, where the mock writes when
#   started without an argument) holds the files the mock writes at start:
#       issuer         the issuer URL, https://127.0.0.1:8443/application/o/login/
#       client_id      the OAuth client id it accepts
#       client_secret  the matching client secret
#       ca.pem         the CA that signs its TLS certificate
#   These set how every pending and future device authorization resolves
#   when polled (GET on the issuer's origin):
#       /_test/approve?user=NAME  ID token with preferred_username=NAME
#       /_test/deny               access_denied
#       /_test/pending            authorization_pending (the start state)
#   The verification URI it hands out is <origin>/if/device/.
#   MODULE=<repo>/target/release/libpam_idp.so (falls back to target/debug)

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "pamtester.sh: must run as root (it writes /etc/pam.d and adds users)" >&2
    exit 2
fi

for tool in pamtester curl useradd userdel chpasswd install; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "pamtester.sh: missing ${tool}" >&2
        exit 2
    fi
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mock_dir="${MOCK_DIR:-${PWD}}"

module="${MODULE:-}"
if [[ -z ${module} ]]; then
    for candidate in "${repo}/target/release/libpam_idp.so" "${repo}/target/debug/libpam_idp.so"; do
        if [[ -f ${candidate} ]]; then
            module="${candidate}"
            break
        fi
    done
fi
if [[ -z ${module} || ! -f ${module} ]]; then
    echo "pamtester.sh: libpam_idp.so not found; run cargo build --release or set MODULE" >&2
    exit 2
fi

for f in issuer client_id client_secret ca.pem; do
    if [[ ! -s ${mock_dir}/${f} ]]; then
        echo "pamtester.sh: ${mock_dir}/${f} missing; start: cargo run --example mock_idp" >&2
        exit 2
    fi
done
issuer="$(<"${mock_dir}/issuer")"
client_id="$(<"${mock_dir}/client_id")"
if [[ ! ${issuer} =~ ^(https://[^/]+) ]]; then
    echo "pamtester.sh: ${mock_dir}/issuer is not an https URL" >&2
    exit 2
fi
origin="${BASH_REMATCH[1]}"
verify_uri="${origin}/if/device/"

# Root-owned copies: the module insists on a secret file owned by its euid
# with no group/other bits, and the mock runs as an ordinary user.
work="$(mktemp -d /tmp/pam-idp-test.XXXXXX)"
secret="${work}/client-secret"
ca="${work}/ca.pem"
install -m 0600 -o root -g root "${mock_dir}/client_secret" "${secret}"
install -m 0644 -o root -g root "${mock_dir}/ca.pem" "${ca}"

sso_user=idpalice
sso_uid=10042
local_user=idplocal
local_uid=1999
local_secret="local-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

services=(idp-test idp-test-enter idp-test-down)
created_users=()

cleanup() {
    local s u
    for s in "${services[@]}"; do
        rm -f "/etc/pam.d/${s}"
    done
    for u in "${created_users[@]}"; do
        userdel "${u}" >/dev/null 2>&1 || true
    done
    rm -rf "${work}"
}
trap cleanup EXIT

add_user() {
    local name=$1 uid=$2
    if id "${name}" >/dev/null 2>&1; then
        echo "pamtester.sh: user ${name} already exists; remove it first" >&2
        exit 2
    fi
    useradd --no-create-home --uid "${uid}" --shell /usr/sbin/nologin "${name}"
    created_users+=("${name}")
}

add_user "${sso_user}" "${sso_uid}"
add_user "${local_user}" "${local_uid}"
printf '%s:%s\n' "${local_user}" "${local_secret}" | chpasswd

# write_service NAME ISSUER EXTRA_ARGS
write_service() {
    local name=$1 iss=$2 extra=$3
    cat >"/etc/pam.d/${name}" <<EOF
# Written by scripts/pamtester.sh; removed when it exits.
auth [success=1 default=ignore]               pam_succeed_if.so uid >= 10000 uid <= 99999 quiet
auth [success=done default=die]               pam_unix.so
auth [success=done ignore=ignore default=die] ${module} methods=password,sso default=sso issuer=${iss} client_id=${client_id} secret_file=${secret} ca_file=${ca} connect_timeout=5 timeout=5 max_wait=20 ${extra}
auth [success=done default=die]               pam_permit.so
account required pam_unix.so
EOF
}

write_service idp-test "${issuer}" "wait=poll"
write_service idp-test-enter "${issuer}" "wait=enter qr=off"
# Nothing listens on port 1: discovery fails.
write_service idp-test-down "https://127.0.0.1:1" "wait=poll"

# decide approve NAME | deny | pending
decide() {
    local path
    case $1 in
    approve) path="approve?user=$2" ;;
    *) path=$1 ;;
    esac
    curl --silent --show-error --fail --noproxy '*' --cacert "${ca}" \
        "${origin}/_test/${path}" >/dev/null
}

if ! decide pending; then
    echo "pamtester.sh: mock IdP not reachable at ${issuer}" >&2
    exit 2
fi

# pamtester's messages (pam_strerror text).
ok_text='successfully authenticated'
maxtries_text='Have exhausted maximum number of retries'
autherr_text='Authentication failure'
unavail_text='Authentication service cannot retrieve authentication info'

passed=0
failed=0
results=()

# run_case NAME SERVICE USER STDIN WANT_EXIT WANT_TEXT [MUST_CONTAIN] [MUST_NOT_CONTAIN]
run_case() {
    local name=$1 service=$2 user=$3 input=$4 want_exit=$5 want_text=$6
    local must=${7:-} must_not=${8:-}
    local out rc=0
    out="$(printf '%b' "${input}" | pamtester -v -I rhost=192.0.2.7 "${service}" "${user}" authenticate 2>&1)" || rc=$?
    local why=()
    if [[ ${rc} -ne ${want_exit} ]]; then
        why+=("exit ${rc}, want ${want_exit}")
    fi
    if [[ ${out} != *"${want_text}"* ]]; then
        why+=("missing '${want_text}'")
    fi
    if [[ -n ${must} && ${out} != *"${must}"* ]]; then
        why+=("missing '${must}'")
    fi
    if [[ -n ${must_not} && ${out} == *"${must_not}"* ]]; then
        why+=("unexpected '${must_not}'")
    fi
    if [[ ${#why[@]} -eq 0 ]]; then
        passed=$((passed + 1))
        results+=("PASS  ${name}")
    else
        failed=$((failed + 1))
        results+=("FAIL  ${name}: ${why[*]}")
        printf -- '--- %s output ---\n%s\n---\n' "${name}" "${out}" >&2
    fi
}

# 1. SSO approved (empty answer picks default=sso; the mock approves as the PAM user).
decide approve "${sso_user}"
run_case "sso approved" idp-test "${sso_user}" '\n' 0 "${ok_text}" "${verify_uri}"

# 2. SSO denied at the IdP: PAM_MAXTRIES, pam_permit is not reached.
decide deny
run_case "sso denied" idp-test "${sso_user}" '2\n' 1 "${maxtries_text}"

# 3. ID token for another user: PAM_AUTH_ERR.
decide approve mallory
run_case "sso wrong user" idp-test "${sso_user}" '2\n' 1 "${autherr_text}"

# 4. Menu option 1 (password): PAM_IGNORE, then pam_permit (standing in for pam_sss).
decide pending
run_case "menu option 1" idp-test "${sso_user}" '1\n' 0 "${ok_text}" "Password" "${verify_uri}"

# 5. Bad menu input three times: PAM_MAXTRIES.
run_case "bad menu input" idp-test "${sso_user}" '9\nx\n7\n' 1 "${maxtries_text}"

# 6. Enter prompt answered q: cancelled, PAM_MAXTRIES, no approval needed.
run_case "enter prompt cancel" idp-test-enter "${sso_user}" '2\nq\n' 1 "${maxtries_text}" "Press Enter"

# 7. Enter prompt, then approved.
decide approve "${sso_user}"
run_case "enter prompt approve" idp-test-enter "${sso_user}" '2\n\n' 0 "${ok_text}" "Press Enter"

# 8. IdP unreachable: PAM_AUTHINFO_UNAVAIL.
run_case "idp unreachable" idp-test-down "${sso_user}" '2\n' 1 "${unavail_text}"

# 9. Local uid (< 10000): pam_unix decides, the menu is never shown.
run_case "local uid skips menu" idp-test "${local_user}" "${local_secret}\\n" 0 "${ok_text}" "" "Single sign-on"

# 10. Local uid with a wrong secret: pam_unix fails, default=die.
run_case "local uid wrong secret" idp-test "${local_user}" 'wrong\n' 1 "${autherr_text}" "" "Single sign-on"

decide pending || true

echo
echo "pam_idp pamtester results (${module}):"
printf '  %s\n' "${results[@]}"
echo "${passed} passed, ${failed} failed"
[[ ${failed} -eq 0 ]]
