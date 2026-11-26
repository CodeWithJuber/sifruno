#!/usr/bin/env bash
# "Always use HTTPS" on a real server with a public certificate: plain http
# for a name the site's certificate covers answers 301 to the same address
# on https with the path and query kept, while https answers 200, the ACME
# challenge path and a name the certificate does not cover stay on http, and
# the switch turned off through the panel's API serves http again. Like
# public-ca-wizard.sh it runs on the operator's own machine and reaches the
# server over the internet, after that proof put a WordPress site with a
# Let's Encrypt certificate at DOMAIN:
#
#   always-https.sh LOGIN_FILE DOMAIN
#
# LOGIN_FILE is the one public-ca-wizard.sh reads (URL, Username, Password,
# TOTP key, Certificate SHA-256; mode 0600 or stricter). The admin signs in
# to the panel's API at its HTTPS address with password and authenticator
# code, and turns the switch off and on there as the site page does. The
# password and the key reach curl and python3 on stdin, never in a process's
# arguments, and the transcript holds none of them.
#
# SIFRUNO_DEVVM_DIR names the server's folder for scripts/devvm/vm.sh: over
# SSH the script shows the site's rules in OpenLiteSpeed's config and puts
# a file in the ACME challenge folder, as the panel does for a renewal,
# then removes it. The alias it adds is in .test, which resolves nowhere,
# so the panel leaves it out of the certificate and asks Let's Encrypt for
# nothing; the script removes it again and leaves the switch on.
#
# Writes SIFRUNO_PROOF_OUT/always-https-<time>.txt (default artifacts/devvm),
# with the server's address written SERVER_IP. Exit status is zero only
# when every check passed.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"
# How long a change may take to show: the broker has reloaded OpenLiteSpeed
# when the panel answers, and its workers finish their requests first.
SETTLE_SECONDS=60

if [ $# -ne 2 ]; then
  sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 2
fi
login="$1"
domain="$2"

die() {
  echo "always-https.sh: $*" >&2
  exit 1
}
for tool in curl openssl python3 jq getent; do
  command -v "$tool" >/dev/null 2>&1 || die "missing program: $tool"
done
if [ ! -f "$login" ] || [ ! -r "$login" ]; then die "cannot read the login file $login"; fi
case "$(stat -c %a "$login")" in
  600 | 400) ;;
  *) die "the login file $login holds a password; make it private first: chmod 600 $login" ;;
esac
[[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
  die "not a lowercase domain name: $domain"
if [ -z "${SIFRUNO_DEVVM_DIR:-}" ] || [ ! -f "$SIFRUNO_DEVVM_DIR/ports" ]; then
  die "set SIFRUNO_DEVVM_DIR to the server's folder for scripts/devvm/vm.sh (with its ports file and SSH key)"
fi

field() { sed -n "s/^$1: //p" "$login" | head -n 1; }
panel="$(field URL)"
panel="${panel%/}"
pinned="$(field 'Certificate SHA-256')"
[[ "$panel" =~ ^https://([a-z0-9.-]+):([0-9]+)$ ]] || die "URL in $login is not https://NAME:PORT/"
panel_host="${BASH_REMATCH[1]}"
panel_port="${BASH_REMATCH[2]}"
[ -n "$pinned" ] || die "$login has no Certificate SHA-256 line"
for name in Username Password 'TOTP key'; do
  [ -n "$(field "$name")" ] || die "$login has no $name line"
done
addr="$(getent ahostsv4 "$domain" | awk '{print $1; exit}')"
[ -n "$addr" ] || die "$domain does not resolve"

mkdir -p "$OUT"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
transcript="$OUT/always-https-$stamp.txt"
work="$(mktemp -d)"
chmod 700 "$work"
run="$(date +%s)"
alias_name="uncovered${run: -5}.sifruno-proof.test"
token="sifruno-proof-${run}"
# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
# The transcript names the server SERVER_IP, in the sslip.io names too, and
# in the config's rules, where its dots are escaped.
exec > >(sed -u -e "s/${addr//./\\.}/SERVER_IP/g" -e "s/${addr//./\\\\\\.}/SERVER_IP/g" | tee "$transcript") 2>&1

fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
on_server() { "$REPO/scripts/devvm/vm.sh" ssh "$@"; }

# answer URL [HOST]: the status and Location of one request, with this
# machine's system trust store; HOST, when given, is sent as the Host header
# to the server's address. Without a Location, the status alone.
answer() {
  if [ $# -eq 2 ]; then
    curl -s --max-time 20 -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $2" "http://$addr$1"
  else
    curl -s --max-time 20 -o /dev/null -w '%{http_code} %{redirect_url}' "$1"
  fi | sed 's/ $//'
}
# shellcheck disable=SC2317 # called through check
answers() { [ "$(answer "$1")" = "$2" ]; }
# shellcheck disable=SC2317 # called through check
settles() { # settles URL WANT: the answer is WANT within SETTLE_SECONDS
  local _
  for _ in $(seq 1 "$SETTLE_SECONDS"); do
    answers "$1" "$2" && return 0
    sleep 1
  done
  return 1
}
# headers URL: the status line and Location header as curl gets them.
headers() {
  curl -s --max-time 20 -o /dev/null -D - "$1" | tr -d '\r' | grep -iE '^(HTTP/|location:)' | sed 's/^/  < /'
}

# totp: the admin's current RFC 6238 code (SHA-1, 6 digits, 30 s), from the
# key on stdin, as public-ca-wizard.sh computes it.
totp() {
  field 'TOTP key' | python3 -I -c '
import base64, hmac, struct, sys, time
key = sys.stdin.readline().strip().replace(" ", "").upper()
key += "=" * (-len(key) % 8)
mac = hmac.new(base64.b32decode(key), struct.pack(">Q", int(time.time()) // 30), "sha1").digest()
o = mac[-1] & 15
print("%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))'
}

# api METHOD PATH [BODY]: one request to the panel's API in the signed-in
# session; prints the HTTP status and leaves the answer in $work/answer.json.
api() {
  local data=()
  [ $# -lt 3 ] || data=(--data-binary "$3")
  curl -sS --max-time 400 -k --pinnedpubkey "sha256//$spki" -b "$work/cookies" -c "$work/cookies" \
    -H "Origin: $panel" -H @"$work/csrf-header" -H 'Content-Type: application/json' \
    -X "$1" "${data[@]}" -o "$work/answer.json" -w '%{http_code}' "$panel$2"
}
site_json() { jq -c --arg d "$domain" '.sites[] | select(.domain == $d)' "$work/answer.json" 2>/dev/null; }
# why: the reason in the panel's last answer.
why() { jq -r '.detail // .message // empty' "$work/answer.json" 2>/dev/null; }

echo "# Always use HTTPS proof $(date -u +%FT%TZ)"
echo "# source $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown); runner: $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release), $(curl -V | head -n 1 | cut -d' ' -f1-2)"
echo "# panel $panel, website $domain, uncovered alias $alias_name"

echo "## The panel's API: the admin signs in over the internet"
openssl s_client -connect "$panel_host:$panel_port" -servername "$panel_host" </dev/null 2>/dev/null |
  openssl x509 -out "$work/panel.pem" 2>/dev/null
served_fp="$(openssl x509 -in "$work/panel.pem" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
if [ -z "$served_fp" ] || [ "$served_fp" != "$pinned" ]; then
  die "the panel's certificate is not the one in $login; stopping before any password is sent"
fi
pass "the panel serves the self-signed certificate the login file names"
spki="$(openssl x509 -in "$work/panel.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
: >"$work/csrf-header"
signed_in=no
for attempt in 1 2; do
  # A code works once, and public-ca-wizard.sh may have used this window's:
  # the second try waits for the next window.
  if [ "$attempt" = 2 ]; then
    window=$(($(date +%s) / 30))
    while [ $(($(date +%s) / 30)) = "$window" ]; do sleep 1; done
  fi
  while [ $(($(date +%s) % 30)) -gt 25 ]; do sleep 1; done
  code="$(totp)"
  # The body is built from the login file inside python3 and goes to curl
  # on stdin.
  status="$(CODE="$code" python3 -I -c '
import json, os, sys
f = {}
for line in open(sys.argv[1], encoding="utf-8"):
    name, sep, value = line.rstrip("\n").partition(": ")
    if sep and name not in f:
        f[name] = value
print(json.dumps({"username": f["Username"], "password": f["Password"], "totp_code": os.environ["CODE"]}))' "$login" |
    curl -sS --max-time 30 -k --pinnedpubkey "sha256//$spki" -c "$work/cookies" -H "Origin: $panel" \
      -H 'Content-Type: application/json' --data-binary @- -o "$work/answer.json" -w '%{http_code}' "$panel/api/v1/session/login")"
  if [ "$status" = 200 ] && jq -e '.authenticated == true and (.csrf_token | length > 0)' "$work/answer.json" >/dev/null 2>&1; then
    jq -r '"X-CSRF-Token: " + .csrf_token' "$work/answer.json" >"$work/csrf-header"
    signed_in=yes
    break
  fi
  echo "  sign-in attempt $attempt answered HTTP $status: $(why)"
done
check "the admin $(field Username) signs in at $panel with password and authenticator code" test "$signed_in" = yes
[ "$signed_in" = yes ] || die "not signed in; nothing was changed"
status="$(api GET /api/v1/websites/sites)"
site="$(site_json)"
id="$(jq -r '.account_id // empty' <<<"$site")"
rev="$(jq -r '.revision // empty' <<<"$site")"
echo "  GET /api/v1/websites/sites: HTTP $status; $domain: $(jq -c '{state, https, always_https, revision, aliases}' <<<"$site" 2>/dev/null)"
check "the panel lists $domain, live, with a certificate" jq -e '.state == "active" and .https.on == true' <<<"$site"
check "Always use HTTPS is on by default" test "$(jq -r .always_https <<<"$site")" = true
[[ "$id" =~ ^[a-f0-9]{32}$ ]] || die "the panel does not list $domain; run public-ca-wizard.sh for it first"
vhost="/usr/local/lsws/conf/vhosts/sifruno-u${id:0:31}/vhconf.conf"
https_rules() { on_server "grep -A3 -F 'RewriteCond %{HTTPS} !on' $vhost" | sed 's/^/  vhconf | /'; }

echo "## 1. On: plain http for the certificate's name answers 301 to https, path and query kept"
echo "  the certificate names: $(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null |
  openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
fingerprint="$(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
echo "  the site's rules in OpenLiteSpeed's config, over SSH:"
https_rules
echo "  curl -sD - http://$domain/some/path?x=1"
headers "http://$domain/some/path?x=1"
check "http://$domain/some/path?x=1 answers 301 to https://$domain/some/path?x=1" answers "http://$domain/some/path?x=1" "301 https://$domain/some/path?x=1"
check "http://$domain/ answers 301 to https://$domain/" answers "http://$domain/" "301 https://$domain/"
check "http://$domain/license.txt?a=b&c=d answers 301 to https://$domain/license.txt?a=b&c=d" answers "http://$domain/license.txt?a=b&c=d" "301 https://$domain/license.txt?a=b&c=d"
https_status="$(curl -sS --max-time 20 -o "$work/page.html" -w '%{http_code}' "https://$domain/" 2>&1)"
echo "  https://$domain/ with this machine's system trust store: $https_status"
check "https://$domain/ answers 200 with a certificate this machine trusts" test "$https_status" = 200
title="$(sed -n 's:.*<title>\(.*\)</title>.*:\1:p' "$work/page.html" | head -n 1)"
echo "  its title: ${title:-none}"
followed="$(curl -sSL --max-time 30 --max-redirs 5 -o /dev/null -w '%{http_code} %{num_redirects} %{url_effective}' "http://$domain/" 2>&1)"
echo "  curl -L http://$domain/ ends: $followed (status, redirects followed, last address)"
check "following it from http ends at https://$domain/ with 200 after one redirect: WordPress's own address is https, so no loop" test "$followed" = "200 1 https://$domain/"

echo "## 2. On: the ACME challenge path stays on http"
on_server "runuser -u sifpanel -- sh -c 'umask 022; printf \"%s\\n\" \"challenge $run\" > /var/lib/sifruno-acme/$token'"
got="$(curl -s --max-time 20 -o "$work/challenge" -w '%{http_code} %{redirect_url}' "http://$domain/.well-known/acme-challenge/$token" | sed 's/ $//')"
echo "  a file the panel's certificate manager would write, /var/lib/sifruno-acme/$token, over http: $got, \"$(cat "$work/challenge")\""
check "http://$domain/.well-known/acme-challenge/$token answers 200 with the file, not a redirect" \
  test "$got|$(cat "$work/challenge")" = "200|challenge $run"
on_server "rm -f -- /var/lib/sifruno-acme/$token"
got="$(answer "http://$domain/.well-known/acme-challenge/test")"
echo "  http://$domain/.well-known/acme-challenge/test: $got"
check "http://$domain/.well-known/acme-challenge/test is not redirected (404: there is no such file)" test "$got" = "404"

echo "## 3. On: an alias the certificate does not cover stays on http"
status="$(api POST "/api/v1/websites/sites/$id/domain-add" "{\"domain\":\"$alias_name\",\"expected_revision\":$rev}")"
rev="$(jq -r '.revision // empty' "$work/answer.json")"
echo "  POST domain-add $alias_name: HTTP $status; aliases $(jq -c .aliases "$work/answer.json" 2>/dev/null)"
check "the panel adds the alias $alias_name" test "$status" = 200
echo "  the site's rules in OpenLiteSpeed's config, over SSH (one name only):"
https_rules
check "the alias is mapped to the site, and has no https rule" on_server \
  "grep -qF '$alias_name' /usr/local/lsws/conf/sifruno.conf && ! grep -F 'RewriteCond %{HTTP_HOST}' $vhost | grep -qF '${alias_name%%.*}'"
got="$(answer "/license.txt?x=1" "$alias_name")"
echo "  http://$alias_name/license.txt?x=1 (Host header to the server): $got"
check "http://$alias_name/license.txt?x=1 answers 200, not a redirect" test "$got" = "200"
got="$(answer "/" "$alias_name")"
echo "  http://$alias_name/: $got"
check "http://$alias_name/ answers 200, not a redirect" test "$got" = "200"
check "the name the certificate covers still answers 301" answers "http://$domain/some/path?x=1" "301 https://$domain/some/path?x=1"
sleep 5
status="$(api GET "/api/v1/websites/sites/$id")"
echo "  the alias's HTTPS on the site page: $(jq -r --arg a "$alias_name" '.aliases[] | select(.name == $a) | .https' "$work/answer.json" 2>/dev/null)"
now_fp="$(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
check "no new certificate was asked for: the served one is the same" test -n "$now_fp" -a "$now_fp" = "$fingerprint"

echo "## 4. The API refuses a switch that is not true or false, and a stale revision"
status="$(api POST "/api/v1/websites/sites/$id/always-https" "{\"always_https\":\"no\",\"expected_revision\":$rev}")"
echo "  always_https \"no\": HTTP $status: $(why)"
check "\"no\" is refused with 422" test "$status" = 422
status="$(api POST "/api/v1/websites/sites/$id/always-https" "{\"always_https\":false,\"expected_revision\":$((rev - 1))}")"
echo "  an old revision: HTTP $status: $(why)"
check "an old revision is refused with 409" test "$status" = 409
check "after both, http still answers 301" answers "http://$domain/some/path?x=1" "301 https://$domain/some/path?x=1"

echo "## 5. Off through the panel's API: plain http serves the site"
status="$(api POST "/api/v1/websites/sites/$id/always-https" "{\"always_https\":false,\"expected_revision\":$rev}")"
rev="$(jq -r '.revision // empty' "$work/answer.json")"
echo "  POST always-https false: HTTP $status; always_https $(jq -r .always_https "$work/answer.json" 2>/dev/null), revision $rev"
check "the panel turns it off" test "$status" = 200 -a "$(jq -r .always_https "$work/answer.json" 2>/dev/null)" = false
check "http://$domain/ answers 200" settles "http://$domain/" "200"
echo "  curl -sD - http://$domain/"
headers "http://$domain/"
check "http://$domain/license.txt?x=1 answers 200" answers "http://$domain/license.txt?x=1" "200"
got="$(answer "http://$domain/some/path?x=1")"
echo "  http://$domain/some/path?x=1: $got (WordPress has no such page)"
check "http://$domain/some/path?x=1 is not redirected" test "$got" = "404"
check "https://$domain/ still answers 200" answers "https://$domain/" "200"
check "the site's config in OpenLiteSpeed has no https rule" on_server "! grep -qF '%{HTTPS}' $vhost"
status="$(api GET /api/v1/websites/sites)"
check "the website list says always_https false" test "$(site_json | jq -r .always_https)" = false

echo "## 6. On again: 301 again"
status="$(api POST "/api/v1/websites/sites/$id/always-https" "{\"always_https\":true,\"expected_revision\":$rev}")"
rev="$(jq -r '.revision // empty' "$work/answer.json")"
echo "  POST always-https true: HTTP $status; always_https $(jq -r .always_https "$work/answer.json" 2>/dev/null), revision $rev"
check "the panel turns it on" test "$status" = 200 -a "$(jq -r .always_https "$work/answer.json" 2>/dev/null)" = true
check "http://$domain/some/path?x=1 answers 301 to https://$domain/some/path?x=1" settles "http://$domain/some/path?x=1" "301 https://$domain/some/path?x=1"
echo "  curl -sD - http://$domain/some/path?x=1"
headers "http://$domain/some/path?x=1"
# The page was served over http while the switch was off, so the site's
# cache may hold it: the redirect must still answer first.
check "http://$domain/ answers 301 again, not a cached page" answers "http://$domain/" "301 https://$domain/"
check "the ACME challenge path is still not redirected" answers "http://$domain/.well-known/acme-challenge/test" "404"
check "the uncovered alias still answers 200" test "$(answer "/license.txt?x=1" "$alias_name")" = "200"

echo "## 7. Clean up: the alias goes, the switch stays on"
status="$(api POST "/api/v1/websites/sites/$id/domain-remove" "{\"domain\":\"$alias_name\",\"expected_revision\":$rev}")"
echo "  POST domain-remove $alias_name: HTTP $status"
check "the panel removes the alias" test "$status" = 200
check "http still answers 301" settles "http://$domain/some/path?x=1" "301 https://$domain/some/path?x=1"
api POST /api/v1/session/logout '{}' >/dev/null

echo
echo "# $fails check(s) failed"
exit "$fails"
