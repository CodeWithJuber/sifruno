#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh broker-web copies it in). Proves the
# broker's web operation: web server access, quota and the OpenLiteSpeed vhost,
# tested and reloaded, then removed again on delete. Prints PASS/FAIL per check.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="web${RUNID}"
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
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1$1"; }

echo "# Broker web operation: access, quota and an OpenLiteSpeed vhost from a typed request"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 | paste -sd ' ')"
echo "# site user $SITE_USER, domain $DOMAIN"

echo
echo "## 1. The broker runs with the web operation on"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
ols_uid="$(id -u "$ols_user")"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"

echo
echo "## 2. An account and a page in its public_html"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Web operation proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | field '["id"]')"
rev="$(printf '%s' "$created" | field '["revision"]')"
runuser -u "$SITE_USER" -- sh -c "printf '%s\n' '<?php echo \"php \", 6 * 7, \" as \", posix_getpwuid(posix_geteuid())[\"name\"] ?? \"?\";' > /home/$SITE_USER/public_html/index.php"
runuser -u "$SITE_USER" -- sh -c "printf 'deny me\n' > /home/$SITE_USER/public_html/.htaccess"
check "the site user wrote index.php" test -f "/home/$SITE_USER/public_html/index.php"

echo
echo "## 3. The web operation puts the site live"
start=$(date +%s)
applied="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the broker applies the web operation"
echo "  took $(( $(date +%s) - start )) s"
check "the result records PHP 8.3 and a 200 MiB quota" bash -c "printf '%s' '$applied' | python3 -c 'import json,sys; w=json.load(sys.stdin)[\"web\"]; sys.exit(0 if w==dict(php_version=\"8.3\", quota_mib=200) else 1)'"
rev="$(printf '%s' "$applied" | field '["account"]["revision"]')"
check "OpenLiteSpeed's user may traverse the home (ACL u:$ols_uid:--x)" bash -c "getfacl -n --omit-header /home/$SITE_USER | grep -qx 'user:$ols_uid:--x'"
check "OpenLiteSpeed's user may read public_html (ACL u:$ols_uid:r-x)" bash -c "getfacl -n --omit-header /home/$SITE_USER/public_html | grep -qx 'user:$ols_uid:r-x'"
check "the home and public_html keep mode 0750" bash -c "[ \"\$(stat -c %a /home/$SITE_USER /home/$SITE_USER/public_html | paste -sd ' ')\" = '750 750' ]"
check "a 200 MiB hard quota is set" bash -c "xfs_quota -x -c 'quota -v -u -N -b $SITE_USER' /home | awk '{print \$4}' | grep -qx 204800"
# The vhost name is "u" plus the first 31 characters of the account ID.
vhost="$LSWS/conf/vhosts/sifruno-u${id:0:31}"
check "the broker wrote the vhost config (0600)" bash -c "[ \"\$(stat -c %a $vhost/vhconf.conf)\" = 600 ]"
check "the server fragment names the vhost" grep -q "$(basename "$vhost")" "$LSWS/conf/sifruno.conf"
ok=no
for _ in $(seq 1 120); do
  if curl -s -H "Host: $DOMAIN" http://127.0.0.1/ | grep -q "php 42 as $SITE_USER"; then ok=yes; break; fi
  sleep 2
done
check "the page is served for $DOMAIN, PHP running as $SITE_USER" test "$ok" = yes
check "/.htaccess is denied (403)" test "$(code /.htaccess)" = 403
check "/.git/config is denied (403)" test "$(code /.git/config)" = 403
check "OpenLiteSpeed is still running after the graceful reload" systemctl is-active --quiet lsws

echo
echo "## 4. A config OpenLiteSpeed would reject changes nothing"
before="$(sha256sum "$LSWS/conf/sifruno.conf" "$vhost/vhconf.conf")"
if drive web --id "$id" --revision "$rev" --php 8.4 --quota-mib 200 --reason 'PHP 8.4 is not installed' >/dev/null 2>&1; then
  if [ -x "$LSWS/lsphp84/bin/lsphp" ]; then pass "PHP 8.4 is installed here, so the rejection case does not apply"; else fail "the broker refused a site for a PHP that is not installed"; fi
else
  pass "the broker refused a site for a PHP that is not installed"
fi
check "the config files are byte for byte unchanged" bash -c "[ \"\$(sha256sum $LSWS/conf/sifruno.conf $vhost/vhconf.conf)\" = '$before' ]"
check "the account revision did not move" bash -c "runuser -u sifpanel -- $BIN/brokerdrive --socket $SOCKET list | python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin) if x[\"id\"]==\"$id\"]; sys.exit(0 if a and a[0][\"revision\"]==$rev and a[0][\"state\"]==\"active\" else 1)'"
check "the site still serves" bash -c "curl -s -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -q 'php 42'"

echo
echo "## 5. A tenant's symlink cannot redirect the access grant"
# The grant itself, as root on this host, against a throwaway fixture. A swap
# made before a broker request is caught first by the broker's per-request
# identity check, which records the account for an operator to inspect.
grant_log="$("$BIN/hostaccounts.test" -test.run '^TestRootOnlyWebAccessFollowsNoLink$' -test.v 2>&1)"
printf '%s\n' "$grant_log" | grep -E '^(=== RUN|--- |    )' | sed 's/^/  /'
check "the grant writes the ACLs, then refuses a symlinked or replaced public_html and leaves the target without an ACL" \
  grep -q -- '--- PASS: TestRootOnlyWebAccessFollowsNoLink' <<<"$grant_log"

echo
echo "## 6. What OpenLiteSpeed reports when a tenant breaks its own site"
# The broker skips, for other accounts' changes, what OpenLiteSpeed reports
# under a broker vhost the change did not rewrite. This shows what a tenant's
# broken docroot looks like in the real test output. No broker request runs
# while it is broken: the broker would mark that account as changed outside it.
BROKEN_USER="brk${RUNID}"
broken="$(drive create --username "$BROKEN_USER" --domain "${BROKEN_USER}.proof.test" --reason 'Broken site proof')" || fail "broker creates the third account"
bid="$(printf '%s' "$broken" | field '["id"]')"
brev="$(printf '%s' "$broken" | field '["revision"]')"
drive web --id "$bid" --revision "$brev" --php 8.3 --quota-mib 100 --reason 'Go live' >/dev/null || fail "the third site goes live"
bvhost="sifruno-u${bid:0:31}"
if [ -z "$bid" ] || [ ! -f "$LSWS/conf/vhosts/$bvhost/vhconf.conf" ]; then
  fail "the third site is live, so its broken docroot can be observed"
else
norm() { sed -E 's/^[0-9-]+ [0-9:.]+ //; s/\[[0-9]+\] //' | grep -E '^\[(ERROR|WARN)\]' | sort -u; }
baseline="$("$LSWS/bin/openlitespeed" -t 2>&1 | norm)"
runuser -u "$BROKEN_USER" -- sh -c "cd /home/$BROKEN_USER && mv public_html public_gone"
after_break="$("$LSWS/bin/openlitespeed" -t 2>&1 | norm)"
runuser -u "$BROKEN_USER" -- sh -c "cd /home/$BROKEN_USER && mv public_gone public_html"
new_lines="$(comm -13 <(printf '%s\n' "$baseline") <(printf '%s\n' "$after_break") | grep -v '^$')"
if [ -z "$new_lines" ]; then
  pass "openlitespeed -t reports nothing new for the broken site, so it cannot fail another account's change"
else
  echo "  new lines from openlitespeed -t after the tenant moved public_html:"
  printf '%s\n' "$new_lines" | sed 's/^/    /'
  # shellcheck disable=SC2016 # $1 and $2 expand in the inner shell
  check "every new line carries the broken site's vhost context, which other accounts' changes skip" \
    bash -c '! printf "%s\n" "$1" | grep -vE "^\[(ERROR|WARN)\] \[[^]]*:vhost:$2[]:]" | grep -q .' _ "$new_lines" "$bvhost"
fi
fi

echo
echo "## 7. Deleting the account takes the site out first"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
check "the vhost config is gone" test ! -e "$vhost/vhconf.conf"
check "the server fragment no longer names it" bash -c "! grep -q '$(basename "$vhost")' $LSWS/conf/sifruno.conf"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws
check "the domain no longer serves the page" bash -c "! curl -s -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -q 'php 42'"
config_status=0
"$LSWS/bin/openlitespeed" -t >/dev/null 2>&1 || config_status=$?
check "openlitespeed -t reports no error afterwards" test "$config_status" -ne 2

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
