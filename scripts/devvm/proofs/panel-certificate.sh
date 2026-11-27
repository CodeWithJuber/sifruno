#!/usr/bin/env bash
# The panel's own Let's Encrypt certificate on a real server. Against a
# panel installed with
#   install.sh --panel-host NAME --acme-email ADDR
# where NAME is in public DNS and points at the server, TCP 80 is open to
# the internet and 8443 to this machine, it shows that:
#   - https://NAME:8443/ has a Let's Encrypt certificate for NAME that this
#     machine's system trust store verifies (curl and openssl), got while
#     the panel ran, without a restart, in at most two requests;
#   - an IP address still gets the self-signed certificate;
#   - the chain and key are one 0600 file in the panel's state, and the
#     renewal loop has the certificate on record;
#   - a restart serves the saved certificate and asks for nothing;
#   - a website or account named NAME is refused through the panel's API.
# Like public-ca-wizard.sh it runs on the operator's own machine and
# reaches the panel over the internet; over SSH (SIFRUNO_DEVVM_DIR, see
# scripts/devvm/vm.sh) it reads what only the server can show and signs in
# on the server's loopback with the access key, which never leaves it.
#
#   panel-certificate.sh NAME
#
# It asks Let's Encrypt for nothing itself: the panel asked when it
# started. It restarts the panel once.
#
# Writes SIFRUNO_PROOF_OUT/panel-certificate-<time>.txt (default
# artifacts/devvm) with the server's address written SERVER_IP. Exit status
# is zero only when every check passed.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"
STATE=/var/lib/sifpanel/state
# The renewal loop's first check runs 2 minutes after the panel starts.
FIRST_CHECK_SECONDS=130

if [ $# -ne 1 ]; then
  sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 2
fi
name="$1"

die() {
  echo "panel-certificate.sh: $*" >&2
  exit 1
}
for tool in curl openssl jq getent; do
  command -v "$tool" >/dev/null 2>&1 || die "missing program: $tool"
done
[[ "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
  die "not a lowercase domain name: $name"
if [ -z "${SIFRUNO_DEVVM_DIR:-}" ] || [ ! -f "$SIFRUNO_DEVVM_DIR/ports" ]; then
  die "set SIFRUNO_DEVVM_DIR to the server's folder for scripts/devvm/vm.sh (with its ports file and SSH key)"
fi
addr="$(getent ahostsv4 "$name" | awk '{print $1; exit}')"
[ -n "$addr" ] || die "$name does not resolve"
panel="https://$name:8443"

mkdir -p "$OUT"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
transcript="$OUT/panel-certificate-$stamp.txt"
work="$(mktemp -d)"
chmod 700 "$work"
# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
# The transcript names the server SERVER_IP, in the sslip.io name too,
# where its dots are dashes.
exec > >(sed -u -e "s/${addr//./\\.}/SERVER_IP/g" -e "s/${addr//./-}/SERVER_IP/g" | tee "$transcript") 2>&1

fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
on_server() { "$REPO/scripts/devvm/vm.sh" ssh "$@" </dev/null; }
# served HOST [SNI]: the leaf the panel's HTTPS port serves to HOST, asked
# for SNI or for none, as PEM in $work/served.pem.
served() {
  local sni=(-noservername)
  [ $# -lt 2 ] || sni=(-servername "$2")
  openssl s_client -connect "$1:8443" "${sni[@]}" </dev/null 2>/dev/null | openssl x509 -out "$work/served.pem" 2>/dev/null
}
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//'; }
# panel_lines: the panel's log lines about its certificate, with their PIDs.
panel_lines() {
  on_server "journalctl -u sifruno --no-pager -o short-iso | grep -E 'Panel over HTTPS|TLS certificate|Panel certificate:|\\(account panel\\)'"
}

echo "# Panel certificate proof $(date -u +%FT%TZ)"
echo "# source $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown); runner: $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release), $(curl -V | head -n 1 | cut -d' ' -f1-2), $(openssl version | cut -d' ' -f1-2)"
echo "# panel $panel"

echo "## Before: the name, the units and port 80"
echo "  $name resolves to $addr"
check "$name resolves in public DNS to the server" test -n "$addr"
on_server "grep -h '^ExecStart=' /etc/systemd/system/sifruno-broker.service /etc/systemd/system/sifruno.service" | sed 's/^/  | /'
check "the installer passed --panel-host $name to the broker" on_server "grep -q -- '--panel-host $name\$' /etc/systemd/system/sifruno-broker.service"
check "and --panel-host $name and --acme-email to the panel" on_server "grep -q -- '--panel-host $name .*--acme-email ' /etc/systemd/system/sifruno.service"
root="$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' "http://$name/")"
echo "  http://$name/ from this machine: $root"
check "port 80 answers $name with 403 outside the challenge path: the panel's name serves nothing else there" test "$root" = 403

echo "## The certificate, checked from this machine with its system trust store"
curl -sv --max-time 30 -o /dev/null "$panel/" >"$work/curl.txt" 2>&1
curl_status=$?
grep -E '^\* +(SSL connection|Server certificate|subject:|start date|expire date|subjectAltName|issuer:|SSL certificate verify|CAfile|CApath)' "$work/curl.txt" | sed 's/^/  curl | /'
check "curl -sv $panel/ exits 0 with no CA but the system's" test "$curl_status" = 0
check "curl says: SSL certificate verify ok" grep -q 'SSL certificate verify ok' "$work/curl.txt"
openssl s_client -connect "$name:8443" -servername "$name" -verify_return_error </dev/null >"$work/openssl.txt" 2>&1
openssl_status=$?
grep -E '^ *[0-9]+ s:|^ +i:|^Verify return code|^Verification' "$work/openssl.txt" | sed 's/^/  openssl | /'
check "openssl s_client -verify_return_error exits 0" test "$openssl_status" = 0
check "openssl says: Verify return code: 0 (ok)" grep -q 'Verify return code: 0 (ok)' "$work/openssl.txt"
served "$name" "$name"
cp "$work/served.pem" "$work/letsencrypt.pem"
issuer="$(openssl x509 -in "$work/letsencrypt.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
san="$(openssl x509 -in "$work/letsencrypt.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
not_before="$(openssl x509 -in "$work/letsencrypt.pem" -noout -startdate 2>/dev/null | cut -d= -f2)"
not_after="$(openssl x509 -in "$work/letsencrypt.pem" -noout -enddate 2>/dev/null | cut -d= -f2)"
le_fp="$(fingerprint "$work/letsencrypt.pem")"
echo "  issuer:  $issuer"
echo "  SAN:     $san"
echo "  valid:   $not_before to $not_after"
echo "  SHA-256: $le_fp"
check "the issuer is Let's Encrypt" grep -q "O *= *Let's Encrypt" <<<"$issuer"
check "the certificate names exactly $name" test "$san" = "DNS:$name"
served "$addr"
echo "  to an IP address (no SNI): $(openssl x509 -in "$work/served.pem" -noout -subject -issuer 2>/dev/null | tr '\n' ' ')"
check "an IP address still gets the self-signed certificate" grep -q 'Sifruno self-signed' <(openssl x509 -in "$work/served.pem" -noout -issuer 2>/dev/null)

echo "## On the server: got while the panel ran, saved privately, on the renewal loop's record"
panel_lines | sed 's/^/  | /'
# The process that installed the certificate, and the last start before
# that: one PID means no restart between them.
installed_pid="$(panel_lines | grep '(account panel): certificate installed' | head -n 1 | sed -n 's/.*sifruno\[\([0-9]*\)\].*/\1/p')"
start_pid="$(panel_lines | sed -n '1,/(account panel): certificate installed/p' | grep 'until Let.s Encrypt.s is in place' | tail -n 1 | sed -n 's/.*sifruno\[\([0-9]*\)\].*/\1/p')"
echo "  the process that started with the self-signed certificate: ${start_pid:-none}; the one that installed Let's Encrypt's: ${installed_pid:-none}"
check "the panel installed Let's Encrypt's certificate in the process that started with the self-signed one: no restart in between" \
  test -n "$installed_pid" -a "$installed_pid" = "$start_pid"
check "the panel said so in plain words" bash -c "grep -q 'Panel certificate: from Let.s Encrypt for $name, valid until' <<<\"\$1\"" _ "$(panel_lines)"
requests="$(panel_lines | grep -c '(account panel): \(certificate installed\|no certificate\|certificate issued but not installed\)')"
echo "  attempts for the panel's certificate in the panel's whole log: $requests"
check "the panel asked Let's Encrypt at most twice" test "$requests" -ge 1 -a "$requests" -le 2
on_server "stat -c '%U:%G %a %n' $STATE/tls/letsencrypt.pem; grep -c 'BEGIN CERTIFICATE' $STATE/tls/letsencrypt.pem; grep -c 'PRIVATE KEY-----\$' $STATE/tls/letsencrypt.pem" >"$work/file.txt"
echo "  $(sed -n 1p "$work/file.txt"); $(sed -n 2p "$work/file.txt") certificates and $(($(sed -n 3p "$work/file.txt") / 2)) key in it"
check "the chain and its key are one file, the panel's own, mode 0600" test "$(sed -n 1p "$work/file.txt")" = "sifpanel:sifpanel 600 $STATE/tls/letsencrypt.pem"
on_server "openssl x509 -in $STATE/tls/letsencrypt.pem -noout -fingerprint -sha256" | sed 's/^.*=//' >"$work/saved-fp.txt"
check "the saved leaf is the one served" test "$(cat "$work/saved-fp.txt")" = "$le_fp"
on_server "jq -c '.sites[]' $STATE/tls/acme/certificates.json" >"$work/record.json"
sed 's/^/  certificates.json | /' "$work/record.json"
# shellcheck disable=SC2016 # a jq program, with $n its own variable
check "the renewal loop's record: the panel, installed, with the certificate's expiry" \
  jq -e --arg n "$name" '.account_id == "panel" and .domain == $n and .last_result == "installed" and (.not_after | startswith("20"))' "$work/record.json"
check "the panel says its renewal check renews it 30 days before it ends" bash -c "grep -q 'The renewal check, 2 minutes after start and then every 12 hours, renews it 30 days before then' <<<\"\$1\"" _ "$(panel_lines)"
# shellcheck disable=SC2016 # expanded on the server
started="$(on_server 'date -d "$(systemctl show -p ActiveEnterTimestamp --value sifruno)" +%s')"
while [ $(($(date +%s) - started)) -lt "$FIRST_CHECK_SECONDS" ]; do sleep 5; done
echo "  $(($(date +%s) - started)) s after the panel started, past the renewal loop's first check:"
# What the panel asked at its start is logged within seconds; the first
# check runs at 120 s.
on_server "journalctl -u sifruno --no-pager -o cat --since @$((started + 90)) | grep -c '(account panel)'" >"$work/after.txt"
echo "  lines about the panel's certificate from 90 s after the start on: $(cat "$work/after.txt")"
check "the panel still runs, and the first check asked for nothing (the certificate is not due)" \
  bash -c "test \"\$(cat '$work/after.txt')\" = 0 && test \"\$1\" = active" _ "$(on_server 'systemctl is-active sifruno')"

echo "## A restart serves the saved certificate and asks for nothing"
before_attempt="$(jq -r .last_attempt "$work/record.json")"
# shellcheck disable=SC2016 # expanded on the server
on_server 'systemctl restart sifruno; for i in $(seq 1 60); do curl -fs -o /dev/null http://127.0.0.1:8080/ && break; sleep 1; done'
# shellcheck disable=SC2016 # expanded on the server
restarted="$(on_server 'date -d "$(systemctl show -p ActiveEnterTimestamp --value sifruno)" +%s')"
sleep 3
on_server "journalctl -u sifruno --no-pager -o short-iso --since @$restarted | grep -E 'TLS certificate|Panel certificate:|\\(account panel\\)'" | sed 's/^/  | /'
check "after the restart it logs the saved certificate" on_server "journalctl -u sifruno --no-pager -o cat --since @$restarted | grep -q 'Panel certificate: from Let.s Encrypt for $name'"
check "and asks Let's Encrypt for nothing" on_server "! journalctl -u sifruno --no-pager -o cat --since @$restarted | grep -q '(account panel)'"
served "$name" "$name"
check "https://$name:8443/ serves the same certificate" test "$(fingerprint "$work/served.pem")" = "$le_fp"
check "the record's last attempt is unchanged" test "$(on_server "jq -r '.sites[0].last_attempt' $STATE/tls/acme/certificates.json")" = "$before_attempt"

echo "## A website or account named $name is refused through the panel's API"
# On the server's loopback with the access key, which stays in its file.
"$REPO/scripts/devvm/vm.sh" ssh 'bash -s' >"$work/api.txt" 2>&1 <<GUEST
set -u
api=http://127.0.0.1:8080
work="\$(mktemp -d)"
trap 'rm -rf -- "\$work"' EXIT
jq -n --rawfile k $STATE/operator/access.key '{access_key: (\$k | rtrimstr("\n"))}' |
  curl -s -c "\$work/cookies" -H "Origin: \$api" -H 'Content-Type: application/json' --data-binary @- -o "\$work/login.json" "\$api/api/v1/session/login"
jq -r '"X-CSRF-Token: " + .csrf_token' "\$work/login.json" > "\$work/csrf"
call() { # call PATH BODY
  code="\$(curl -s -b "\$work/cookies" -H @"\$work/csrf" -H "Origin: \$api" -H 'Content-Type: application/json' --data-binary "\$2" -o "\$work/answer.json" -w '%{http_code}' "\$api\$1")"
  echo "POST \$1 \$2 -> \$code \$(jq -r '.detail // empty' "\$work/answer.json")"
}
call /api/v1/websites/php '{"domain":"$name","php_version":"8.3","database":"none"}'
call /api/v1/websites/php '{"domain":"www.$name","php_version":"8.3","database":"none"}'
call /api/v1/accounts '{"username":"panelname","domain":"$name","reason":"panel certificate proof"}'
echo "websites listed: \$(curl -s -b "\$work/cookies" "\$api/api/v1/websites/sites" | jq -c '[.sites[].domain]')"
GUEST
sed 's/^/  | /' "$work/api.txt"
refused="This name is the panel's own address. Use a different domain for the website."
check "creating a PHP website named $name answers 422: $refused" grep -qF "/api/v1/websites/php {\"domain\":\"$name\",\"php_version\":\"8.3\",\"database\":\"none\"} -> 422 $refused" "$work/api.txt"
check "and for www.$name" grep -qF "{\"domain\":\"www.$name\",\"php_version\":\"8.3\",\"database\":\"none\"} -> 422 $refused" "$work/api.txt"
check "creating a hosting account for $name answers 422 the same" grep -qF "/api/v1/accounts {\"username\":\"panelname\",\"domain\":\"$name\",\"reason\":\"panel certificate proof\"} -> 422 $refused" "$work/api.txt"
check "no website named $name exists" bash -c "grep -q '^websites listed: ' '$work/api.txt' && ! grep '^websites listed: ' '$work/api.txt' | grep -qF '\"$name\"'"

echo
echo "# $fails check(s) failed"
echo "Transcript: $transcript"
exit "$fails"
