#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh broker-site-actions copies it in).
# Proves the site page's three changes at the broker: a PHP version change,
# suspend (the public gets 403 from a vhost that names no tenant path, served
# from the broker's own empty folder), a second suspend that re-applies it,
# resume, and delete. Prints PASS/FAIL per check.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
SUSPENDED=/var/lib/sifruno-suspended
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="act${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
# A change answers either the account or {"account": ...}.
revision() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('account', d)['revision'])"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1$1"; }
# The first request after a change starts lsphp cold; under emulation that
# can take minutes, so wait for the answer the change should give.
wait_for() { # wait_for PATH CODE [TEXT]
  local _
  for _ in $(seq 1 150); do
    if [ "$(code "$1")" = "$2" ] && { [ -z "${3:-}" ] || curl -s -H "Host: $DOMAIN" "http://127.0.0.1$1" | grep -q "$3"; }; then
      return 0
    fi
    sleep 2
  done
  return 1
}
listed() { # listed PYTHON-CONDITION-ON-a
  drive list | python3 -c "import json,sys; a=[x for x in json.load(sys.stdin) if x['id']=='$id']; sys.exit(0 if a and ($1) else 1)"
}

echo "# Site actions at the broker: PHP version, suspend, a second suspend, resume, delete"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 | paste -sd ' ')  SELinux $(getenforce)"
echo "# site user $SITE_USER, domain $DOMAIN"

echo
echo "## 1. The broker runs with the web operation on"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
# A second PHP version for the change; the installer puts in 8.3 only.
if [ ! -x "$LSWS/lsphp84/bin/lsphp" ]; then
  dnf -y -q install lsphp84 lsphp84-common >/dev/null 2>&1
fi
check "LSPHP 8.4 is installed for the version change" test -x "$LSWS/lsphp84/bin/lsphp"

echo
echo "## 2. A live site on PHP 8.3"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Site actions proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
rev="$(printf '%s' "$created" | revision)"
runuser -u "$SITE_USER" -- sh -c "printf '%s\n' '<?php echo \"site on php \", PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;' > /home/$SITE_USER/public_html/index.php"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | revision)"
check "the site serves on PHP 8.3" wait_for / 200 'site on php 8.3'
check "the account list shows PHP 8.3 and the 200 MiB quota" listed "a[0].get('web', {}).get('php_version') == '8.3' and a[0]['web'].get('quota_mib') == 200"

echo
echo "## 3. The PHP version changes to 8.4"
changed="$(drive web --id "$id" --revision "$rev" --php 8.4 --quota-mib 200 --reason 'PHP 8.4')" || fail "the broker changes the PHP version"
rev="$(printf '%s' "$changed" | revision)"
check "the site serves on PHP 8.4" wait_for / 200 'site on php 8.4'
check "the account list shows PHP 8.4" listed "a[0].get('web', {}).get('php_version') == '8.4'"

echo
echo "## 4. Suspend: the public gets 403 from the broker's own empty folder"
vhost="$LSWS/conf/vhosts/sifruno-u${id:0:31}"
suspended="$(drive state --id "$id" --revision "$rev" --state suspended --reason 'Unpaid invoice')" || fail "the broker suspends the account"
rev="$(printf '%s' "$suspended" | revision)"
check "the home page answers 403" wait_for / 403
check "a PHP file answers 403" test "$(code /index.php)" = 403
# The challenge path maps to the panel's own folder, not the site's. Show what
# it answers while suspended, and that nothing of the site's own is served
# there: a file the tenant puts in its .well-known folder stays unreachable.
challenge="proof-${RUNID}"
printf 'challenge %s\n' "$RUNID" > "/var/lib/sifruno-acme/$challenge"
chmod 0644 "/var/lib/sifruno-acme/$challenge"
echo "  the ACME challenge path answers $(code "/.well-known/acme-challenge/$challenge") for a challenge in the panel's folder while suspended"
rm -f "/var/lib/sifruno-acme/$challenge"
runuser -u "$SITE_USER" -- sh -c "mkdir -p /home/$SITE_USER/public_html/.well-known/acme-challenge && printf 'tenant decoy\n' > /home/$SITE_USER/public_html/.well-known/acme-challenge/decoy"
check "a file the tenant put under .well-known is not served" bash -c "! curl -s -H 'Host: $DOMAIN' http://127.0.0.1/.well-known/acme-challenge/decoy | grep -q 'tenant decoy'"
check "the account list shows it suspended" listed "a[0]['state'] == 'suspended'"
echo "  $SUSPENDED: $(stat -c '%U:%G %a' "$SUSPENDED" 2>&1), SELinux $(stat -c %C "$SUSPENDED" 2>&1), entries: $(find "$SUSPENDED" -mindepth 1 | wc -l)"
check "$SUSPENDED is root's, mode 0755, and empty" bash -c "[ \"\$(stat -c '%U:%G %a' $SUSPENDED)\" = 'root:root 755' ] && [ -z \"\$(find $SUSPENDED -mindepth 1 -print -quit)\" ]"
check "the suspended vhost names no path in /home" bash -c "! grep -q '/home' $vhost/vhconf.conf"
check "the server fragment points the vhost at $SUSPENDED" bash -c "grep -A3 'sifruno-u${id:0:31}' $LSWS/conf/sifruno.conf | grep -q '$SUSPENDED'"
check "the site's files are untouched in its home" test -f "/home/$SITE_USER/public_html/index.php"
check "OpenLiteSpeed is running" systemctl is-active --quiet lsws

echo
echo "## 5. A second suspend applies the suspension again"
again="$(drive state --id "$id" --revision "$rev" --state suspended --reason 'Enforce the suspension')" || fail "the broker accepts a second suspend"
new_rev="$(printf '%s' "$again" | revision)"
check "it is a recorded change (the revision moved from $rev)" test "${new_rev:-0}" -gt "$rev"
rev="${new_rev:-$rev}"
check "the site still answers 403" test "$(code /)" = 403

echo
echo "## 6. Resume serves the site again, as it was"
resumed="$(drive state --id "$id" --revision "$rev" --state active --reason 'Paid')" || fail "the broker resumes the account"
rev="$(printf '%s' "$resumed" | revision)"
check "the site serves on PHP 8.4 again" wait_for / 200 'site on php 8.4'
check "the vhost names its home again" grep -q "/home/$SITE_USER" "$vhost/vhconf.conf"

echo
echo "## 7. Delete"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
check "the vhost config is gone" test ! -e "$vhost/vhconf.conf"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
