#!/usr/bin/env bash
# The Phase 1 gate on a real server with a public certificate authority: a
# new admin's New website wizard puts a WordPress site live over https in
# under two minutes, with a certificate from Let's Encrypt's production
# directory for a name in public DNS. Unlike the other proofs it runs on the
# operator's own machine, against a panel installed with
#   install.sh --panel-host NAME --acme-email ADDR
# whose admin already exists, and reaches it over the internet:
#
#   public-ca-wizard.sh LOGIN_FILE DOMAIN
#
# LOGIN_FILE is private (mode 0600 or stricter) and holds one "Name: value"
# line for each of:
#   URL                       the panel, https://NAME:8443/
#   Username                  the admin
#   Password                  the admin's password
#   TOTP key                  the admin's authenticator key (base32)
#   Certificate SHA-256       the panel's self-signed certificate, as
#                             openssl x509 -fingerprint -sha256 prints it
#   WordPress admin password  for the new site's admin, wpadmin
# DOMAIN must resolve in public DNS to the server, with TCP 80 and 443 open
# to the internet, and have no website yet. The wizard asks Let's Encrypt
# for one certificate, so run this once per domain: Let's Encrypt limits
# how often it issues for a name.
#
# agent-browser (Chrome) signs in and runs the wizard. Passwords and the
# authenticator key reach it on stdin, never in a process's arguments, and
# the transcript holds none of them. curl and openssl then check the site
# with this machine's system trust store and no other CA, and a second
# browser that ignores no certificate error opens it.
#
# Writes SIFRUNO_PROOF_OUT/public-ca-wizard-<time>.txt (default
# artifacts/devvm) and the screenshots in a folder of the same name. Exit
# status is zero only when every check passed.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"
# The gate: two minutes from pressing Create.
LIMIT_SECONDS=120
# How long to follow a job that is slower than the gate, to see how it ends.
FOLLOW_SECONDS=900
TITLE="Sifruno public CA proof"

if [ $# -ne 2 ]; then
  sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 2
fi
login="$1"
domain="$2"

die() {
  echo "public-ca-wizard.sh: $*" >&2
  exit 1
}
for tool in agent-browser curl openssl python3 jq getent; do
  command -v "$tool" >/dev/null 2>&1 || die "missing program: $tool"
done
if [ ! -f "$login" ] || [ ! -r "$login" ]; then die "cannot read the login file $login"; fi
case "$(stat -c %a "$login")" in
  600 | 400) ;;
  *) die "the login file $login holds a password; make it private first: chmod 600 $login" ;;
esac
[[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] ||
  die "not a lowercase domain name: $domain"

# field NAME: the value of the login file's "NAME: value" line.
field() { sed -n "s/^$1: //p" "$login" | head -n 1; }
panel="$(field URL)"
panel="${panel%/}"
username="$(field Username)"
pinned="$(field 'Certificate SHA-256')"
[[ "$panel" =~ ^https://([a-z0-9.-]+):([0-9]+)$ ]] || die "URL in $login is not https://NAME:PORT/"
panel_host="${BASH_REMATCH[1]}"
panel_port="${BASH_REMATCH[2]}"
if [ -z "$username" ] || [ -z "$pinned" ]; then die "$login has no Username or Certificate SHA-256 line"; fi
for name in Password 'TOTP key' 'WordPress admin password'; do
  [ -n "$(field "$name")" ] || die "$login has no $name line"
done

mkdir -p "$OUT"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
transcript="$OUT/public-ca-wizard-$stamp.txt"
shots="$OUT/public-ca-wizard-$stamp"
mkdir -p "$shots"
work="$(mktemp -d)"
chmod 700 "$work"
SESSION="pubca$$"
SITE_SESSION="pubcasite$$"
poller=""
# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
  [ -z "$poller" ] || kill "$poller" 2>/dev/null
  agent-browser --session "$SESSION" close >/dev/null 2>&1
  agent-browser --session "$SITE_SESSION" close >/dev/null 2>&1
  rm -rf -- "$work"
}
trap cleanup EXIT
exec > >(tee "$transcript") 2>&1

fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
ab() { agent-browser --session "$SESSION" "$@"; }
# js EXPRESSION: its value in the panel's page, as plain text.
js() { ab eval "$1" 2>/dev/null | jq -r 'if type == "string" then . else tojson end' 2>/dev/null; }
# since START: seconds from START (an EPOCHREALTIME) to now, one decimal.
since() { awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.1f", b - a }'; }
# shellcheck disable=SC2317 # called through check
within() { awk -v s="$1" -v l="$LIMIT_SECONDS" 'BEGIN { exit !(s != "" && s <= l) }'; }

# fill_secret SELECTOR FIELD: puts the login file's FIELD into the input at
# SELECTOR the way typing does, so the page's state sees it. The value goes
# to the browser on stdin.
fill_secret() {
  {
    printf '(() => {\nconst sel = %s;\n' "$(printf '%s' "$1" | jq -Rs .)"
    printf 'const v = %s;\n' "$(field "$2" | tr -d '\n' | jq -Rs .)"
    cat <<'JS'
const el = document.querySelector(sel);
Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, v);
el.dispatchEvent(new Event("input", { bubbles: true }));
return "filled";
})();
JS
  } | ab eval --stdin >/dev/null 2>&1
}

# totp: the admin's current RFC 6238 code (SHA-1, 6 digits, 30 s), from the
# key on stdin.
totp() {
  field 'TOTP key' | python3 -I -c '
import base64, hmac, struct, sys, time
key = sys.stdin.readline().strip().replace(" ", "").upper()
key += "=" * (-len(key) % 8)
mac = hmac.new(base64.b32decode(key), struct.pack(">Q", int(time.time()) // 30), "sha1").digest()
o = mac[-1] & 15
print("%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))'
}

echo "# Public-CA wizard proof $(date -u +%FT%TZ)"
echo "# source $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown); runner: $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release), $(curl -V | head -n 1 | cut -d' ' -f1-2), $(openssl version | cut -d' ' -f1-2), agent-browser $(agent-browser --version | awk '{print $2}')"
echo "# panel $panel, website $domain, limit $LIMIT_SECONDS s from Create"

echo "## Before the wizard"
addr="$(getent ahostsv4 "$domain" | awk '{print $1; exit}')"
panel_addr="$(getent ahostsv4 "$panel_host" | awk '{print $1; exit}')"
echo "  $domain resolves to ${addr:-nothing}; the panel's name to ${panel_addr:-nothing}"
check "the domain resolves in public DNS to the panel's server" test -n "$addr" -a "$addr" = "$panel_addr"
# The panel's certificate is self-signed: it is taken once, compared with
# the login file's fingerprint, and from then on trusted by its key alone.
openssl s_client -connect "$panel_host:$panel_port" -servername "$panel_host" </dev/null 2>/dev/null |
  openssl x509 -out "$work/panel.pem" 2>/dev/null
served_fp="$(openssl x509 -in "$work/panel.pem" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
check "the panel serves the self-signed certificate the login file names" test -n "$served_fp" -a "$served_fp" = "$pinned"
[ "$served_fp" = "$pinned" ] || die "the panel's certificate is not the one in $login; stopping before any password is sent"
spki="$(openssl x509 -in "$work/panel.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -k --pinnedpubkey "sha256//$spki" \
  -H 'Sec-Fetch-Site: cross-site' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Dest: document' "$panel/")"
echo "  a top-level link from another site to $panel/ answers HTTP $code"
check "a link from another site opens the panel (cross-site navigation answers 200)" test "$code" = 200
before="$(curl -sS --max-time 10 -o /dev/null "https://$domain/" 2>&1)"
echo "  https://$domain/ before the wizard: ${before:-answered}"
check "before the wizard, https://$domain/ has no certificate this machine trusts" test -n "$before"

echo "## Browser: sign in over the internet and open the wizard"
# Chrome takes the panel's self-signed certificate by its key alone.
ab --args "--ignore-certificate-errors-spki-list=$spki" open "$panel/websites" >/dev/null 2>&1
ab wait '#sign-in-username' >/dev/null 2>&1
check "the panel's sign-in form opens at $panel/websites" test "$(js "document.querySelectorAll('#sign-in-username').length")" = 1
signed_in=no
for attempt in 1 2; do
  ab fill '#sign-in-username' "$username" >/dev/null 2>&1
  fill_secret '#sign-in-password' Password
  # A code read in the last seconds of its window may be old on arrival,
  # and a code works once: a second try waits for the next window.
  if [ "$attempt" = 2 ]; then
    window=$(($(date +%s) / 30))
    while [ $(($(date +%s) / 30)) = "$window" ]; do sleep 1; done
  fi
  while [ $(($(date +%s) % 30)) -gt 25 ]; do sleep 1; done
  ab fill '#sign-in-code' "$(totp)" >/dev/null 2>&1
  ab click 'button[type=submit]' >/dev/null 2>&1
  if ab wait '[data-testid="signed-in-as"]' >/dev/null 2>&1; then
    signed_in=yes
    break
  fi
  echo "  sign-in attempt $attempt did not finish: $(js "document.querySelector('[role=alert]')?.innerText ?? 'no message'" | tr '\n' ' ')"
done
check "the admin $username signs in with password and authenticator code" test "$signed_in" = yes
# Websites shows its New website button once its list has loaded.
ab wait '[data-testid="new-website-link"]' >/dev/null 2>&1
ab click '[data-testid="new-website-link"]' >/dev/null 2>&1
ab wait '[data-testid="new-website-form"]' >/dev/null 2>&1
check "Websites, New website opens the wizard at /websites/new" test "$(js 'location.pathname')" = /websites/new
# The radio itself has no text: the label around it names it.
check "WordPress is the chosen website type" test "$(js "document.querySelector('[role=radio][aria-checked=true]')?.closest('label')?.htmlFor ?? ''")" = nw-kind-wordpress

ab fill '#nw-domain' "$domain" >/dev/null 2>&1
ab fill '#nw-title' "$TITLE" >/dev/null 2>&1
ab fill '#nw-admin-user' wpadmin >/dev/null 2>&1
ab fill '#nw-admin-email' "admin@$domain" >/dev/null 2>&1
fill_secret '#nw-admin-password' 'WordPress admin password'
ab screenshot "$shots/1-new-website.png" >/dev/null 2>&1
# Create asks Let's Encrypt for a certificate, which it limits: press it
# only on a form that holds what this run typed.
filled="$(js "[document.querySelector('#nw-domain')?.value, document.querySelector('#nw-title')?.value, document.querySelector('#nw-admin-password')?.value.length > 0].join(' | ')")"
if [ "$filled" != "$domain | $TITLE | true" ]; then
  fail "the wizard's form holds the domain, the title and a password (it holds: ${filled:-nothing})"
  echo
  echo "# Stopped before Create: nothing was made and no certificate was asked for."
  echo "# $fails check(s) failed"
  exit 1
fi

echo "## Browser: Create, then follow the job"
# From Create, this machine asks for https://DOMAIN/ every half second with
# its system trust store and notes the first 200.
start="$EPOCHREALTIME"
(
  deadline=$((SECONDS + FOLLOW_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(curl -s --max-time 5 -o "$work/first-200.html" -w '%{http_code}' "https://$domain/")" = 200 ]; then
      printf '%s\n' "$EPOCHREALTIME" >"$work/first-200-at"
      exit 0
    fi
    sleep 0.5
  done
) &
poller=$!
ab click '[data-testid="create-website"]' >/dev/null 2>&1
echo "  pressed Create at $(date -u +%FT%TZ)"
state=running
seen=""
while :; do
  state="$(js "document.querySelector('[data-testid=job-succeeded]') ? 'succeeded' : document.querySelector('[data-testid=job-failed]') ? 'failed' : 'running'")"
  # No answer while the page changes counts as still running.
  case "$state" in succeeded | failed) break ;; esac
  steps="$(js "[...document.querySelectorAll('[data-testid=job-steps] li')].map(li => li.getAttribute('data-state')).join(' ')")"
  if [ -n "$steps" ] && [ "$steps" != "$seen" ]; then
    echo "  $(since "$start") s: steps $steps"
    seen="$steps"
  fi
  if awk -v s="$(since "$start")" -v l="$FOLLOW_SECONDS" 'BEGIN { exit !(s > l) }'; then
    state=timeout
    break
  fi
  sleep 1
done
last_screen="$(since "$start")"
echo "  the job page shows its last screen ($state) $last_screen s after Create"
ab screenshot "$shots/2-job-done.png" >/dev/null 2>&1
check "the job succeeds" test "$state" = succeeded
check "Create to the job's last screen: $last_screen s, within $LIMIT_SECONDS s" within "$last_screen"
# A failed job may leave the site on http for good: then give the poller
# half a minute more, not its whole time.
if [ "$state" != succeeded ]; then
  for _ in $(seq 1 30); do kill -0 "$poller" 2>/dev/null || break; sleep 1; done
  kill "$poller" 2>/dev/null
fi
wait "$poller" 2>/dev/null
poller=""
first_200=""
[ -s "$work/first-200-at" ] && first_200="$(awk -v a="$start" '{ printf "%.1f", $1 - a }' "$work/first-200-at")"
echo "  first HTTPS 200 from https://$domain/, system trust store: ${first_200:-none} s after Create"
check "Create to the site's first HTTPS 200: ${first_200:-none} s, within $LIMIT_SECONDS s" within "$first_200"
check "that first 200 is the new WordPress site" grep -q "$TITLE" "$work/first-200.html"

job="$(js "fetch('/api/v1/websites/jobs/' + location.pathname.split('/').pop()).then(r => r.json()).then(j => JSON.stringify(j.job))")"
printf '%s\n' "$job" | jq -r '.steps[] | "  step \(.name): \(.state)\(if .message then " (" + .message + ")" else "" end)"' 2>/dev/null
check "the job's HTTPS step is done" test "$(jq -r '.steps[] | select(.name == "ssl") | .state' <<<"$job" 2>/dev/null)" = "done"
protocol="$(js "document.querySelector('[data-testid=site-protocol]')?.innerText ?? ''")"
echo "  last screen: $(js "document.querySelector('[data-testid=job-succeeded] h2')?.innerText ?? ''"). $protocol"
check "the last screen says the site uses https" grep -q 'uses https' <<<"$protocol"
check "Open site on the last screen is https://$domain/" test "$(js "document.querySelector('[data-testid=open-site]')?.getAttribute('href') ?? ''")" = "https://$domain/"

echo "## The certificate, checked with this machine's system trust store"
curl -sv --max-time 20 -o "$work/page.html" "https://$domain/" 2>"$work/curl.txt"
curl_status=$?
grep -E '^\* +(CAfile|CApath|SSL connection|ALPN|Server certificate|subject|start date|expire date|subjectAltName|issuer|SSL certificate verify)|^< HTTP/' "$work/curl.txt" |
  sed -e 's/[[:space:]]*$//' -e 's/^/  curl | /'
check "curl -sv https://$domain/ exits 0 with no CA but the system's" test "$curl_status" = 0
check "curl says: SSL certificate verify ok" grep -q 'SSL certificate verify ok' "$work/curl.txt"
check "the page is the WordPress site" grep -q "$TITLE" "$work/page.html"
openssl s_client -connect "$domain:443" -servername "$domain" -verify_return_error </dev/null >"$work/s_client.txt" 2>&1
s_status=$?
sed -n -e '/^Certificate chain/,/^---/p' -e '/Verify return code/p' -e '/^verify return/p' "$work/s_client.txt" | sed 's/^/  openssl | /'
check "openssl s_client -verify_return_error exits 0" test "$s_status" = 0
check "openssl says: Verify return code: 0 (ok)" grep -q 'Verify return code: 0 (ok)' "$work/s_client.txt"
openssl x509 -in "$work/s_client.txt" -out "$work/leaf.pem" 2>/dev/null
issuer="$(openssl x509 -in "$work/leaf.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
san="$(openssl x509 -in "$work/leaf.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
not_after="$(openssl x509 -in "$work/leaf.pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
not_before="$(openssl x509 -in "$work/leaf.pem" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')"
echo "  issuer:  ${issuer:-none}"
echo "  SAN:     ${san:-none}"
echo "  valid:   $not_before to $not_after"
echo "  SHA-256: $(openssl x509 -in "$work/leaf.pem" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
# Staging's issuers are "(STAGING) Let's Encrypt", Pebble's "Pebble ...".
# shellcheck disable=SC2016 # expanded by the inner bash
check "the issuer is Let's Encrypt's production CA (not staging, not Pebble)" bash -c \
  'grep -Eq "(^|, )O ?= ?Let.s Encrypt(,|$)" <<<"$1" && ! grep -Eqi "staging|pebble" <<<"$1"' _ "$issuer"
check "the certificate names exactly $domain" test "$san" = "DNS:$domain"
# shellcheck disable=SC2016 # expanded by the inner bash
check "it was issued during this run and is valid for at least 30 more days" bash -c \
  'now=$(date +%s); b=$(date -d "$1" +%s) && e=$(date -d "$2" +%s) && [ $((now - b)) -lt 7200 ] && [ $((e - now)) -gt 2592000 ]' _ "$not_before" "$not_after"

echo "## A browser that ignores no certificate error opens the site"
agent-browser --session "$SITE_SESSION" open "https://$domain/" >/dev/null 2>&1
site_title="$(agent-browser --session "$SITE_SESSION" eval 'document.title' 2>/dev/null | jq -r . 2>/dev/null)"
echo "  Chrome shows: ${site_title:-nothing}"
agent-browser --session "$SITE_SESSION" screenshot "$shots/3-site-over-https.png" >/dev/null 2>&1
check "Chrome opens https://$domain/ without a certificate warning and shows the site" grep -q "$TITLE" <<<"$site_title"

echo "## The new site in Websites"
ab click '[data-testid="go-to-websites"]' >/dev/null 2>&1
ab wait '[data-testid="websites-table"]' >/dev/null 2>&1
row="[data-testid=website-row][data-domain='$domain']"
echo "  row: $(js "document.querySelector(\"$row\")?.innerText.replace(/\\s+/g, ' ') ?? 'none'")"
check "Websites lists $domain as Live" test "$(js "document.querySelector(\"$row [data-testid=website-status]\")?.innerText.trim() ?? ''")" = Live
# shellcheck disable=SC2016 # expanded by the inner bash
check "its https badge is on, with the certificate's expiry" bash -c '[ "$1" = on ] && [[ "$2" == until* ]]' _ \
  "$(js "document.querySelector(\"$row [data-testid=website-https]\")?.getAttribute('data-https') ?? ''")" \
  "$(js "document.querySelector(\"$row [data-testid=website-https-until]\")?.innerText ?? ''")"
ab screenshot "$shots/4-websites.png" >/dev/null 2>&1

echo
echo "# $fails check(s) failed"
echo "# Times from pressing Create: last screen $last_screen s, first HTTPS 200 ${first_200:-none} s (limit $LIMIT_SECONDS s)"
echo "# Screenshots: $shots"
exit "$fails"
