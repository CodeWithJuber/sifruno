#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh htaccess-reload copies it in).
# Proves the broker's .htaccess watcher on a live site: a rewrite rule the
# site's user writes into public_html/.htaccess takes effect within the
# window with no panel action; 1000 writes to other names restart nothing;
# a flood of 1000 .htaccess writes restarts OpenLiteSpeed at most once per
# window, and its last rule is the one served; the broker's lines name
# counts only. Then the root-only Go test marks a filesystem the same way.
# Prints PASS/FAIL per check; the exit status is the number of FAILs.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
UNIT=sifruno-broker-proof
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="hta${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
DOCROOT="/home/$SITE_USER/public_html"
# The watcher's timing (internal/hostaccounts/htaccess_watch.go).
QUIET=5
WINDOW=30
RESTARTED='sifruno broker: htaccess: OpenLiteSpeed restarted gracefully'
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
as_site() { runuser -u "$SITE_USER" -- "$@"; }
# The broker's journal since an epoch second, with epoch timestamps.
journal_since() { journalctl -u "$UNIT" --since "@$1" -o short-unix --no-pager 2>/dev/null; }
restart_lines() { journal_since "$1" | grep -F "$RESTARTED"; }
restarts_since() { restart_lines "$1" | wc -l; }
last_restart() { restart_lines "$1" | tail -n 1 | awk '{print int($1)}'; }
# wait_body PATH TEXT SECONDS: the site answers PATH with TEXT in time.
wait_body() {
  local deadline=$(($(date +%s) + $3))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -s -H "Host: $DOMAIN" "http://127.0.0.1$1" | grep -qF "$2"; then return 0; fi
    sleep 1
  done
  return 1
}
# settle SINCE: sleep until one window and a quiet period have passed since
# the last restart after SINCE, so the next change is not held by the window.
settle() {
  local last now wait
  last="$(last_restart "$1")"
  [ -n "$last" ] || return 0
  now="$(date +%s)"
  wait=$((last + WINDOW + QUIET - now))
  [ "$wait" -gt 0 ] && sleep "$wait"
  return 0
}
# Consecutive restart lines are at least a window apart: each restart
# starts a window after the one before ended, and logs when it ends.
spaced() { restart_lines "$1" | awk -v w="$WINDOW" '{t=int($1)} NR>1 && t-p<w {bad=1} {p=t} END {exit bad}'; }

echo "# The .htaccess watcher: a tenant's rewrite rule takes effect with no panel action, and a flood is bounded"
echo "# $(date -u +%FT%TZ)  kernel $(uname -r)  $(rpm -q openlitespeed | paste -sd ' ')  SELinux $(getenforce)"
echo "# /home is $(stat -f -c %T /home); site user $SITE_USER, domain $DOMAIN; quiet ${QUIET} s, window ${WINDOW} s"

echo
echo "## 1. The broker runs with the web operation on, and its watcher starts"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop "$UNIT" 2>/dev/null
systemctl reset-failed "$UNIT" 2>/dev/null
start="$(date +%s)"
systemd-run --quiet --unit "$UNIT" --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
for _ in $(seq 1 90); do [ "$(restarts_since "$start")" -ge 1 ] && break; sleep 1; done
restart_lines "$start" | sed 's/^/  /'
check "the watcher restarted OpenLiteSpeed once after the broker started" test "$(restarts_since "$start")" -eq 1
check "the watcher did not log that it could not start" bash -c "! journalctl -u $UNIT --since @$start --no-pager | grep -q 'watcher could not start'"

echo
echo "## 2. A live site, with no rewrite rule yet"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'htaccess reload proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
rev="$(printf '%s' "$created" | revision)"
as_site sh -c "printf 'rule target %s\n' $RUNID > $DOCROOT/rule-target.txt; printf 'flood final %s\n' $RUNID > $DOCROOT/flood-final.txt"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | revision)"
check "the site serves its files" wait_body /rule-target.txt "rule target $RUNID" 120
echo "  /proof-rule answers $(code /proof-rule) before any .htaccess"
check "/proof-rule is not found before any .htaccess" test "$(code /proof-rule)" = 404
settle "$start"

echo
echo "## 3. A rewrite rule the site's user writes takes effect, with no panel action"
before="$(date +%s)"
as_site sh -c "printf 'RewriteEngine On\nRewriteRule ^proof-rule\$ /rule-target.txt [L]\n' > $DOCROOT/.htaccess"
if wait_body /proof-rule "rule target $RUNID" 120; then
  took=$(($(date +%s) - before))
  pass "/proof-rule serves the rule's target ($took s after the write)"
  check "it took at most 60 s (quiet period ${QUIET} s and one restart)" test "$took" -le 60
else
  fail "/proof-rule serves the rule's target within 120 s"
fi
sleep $((WINDOW + QUIET))
restart_lines "$before" | sed 's/^/  /'
check "one write made exactly one restart" test "$(restarts_since "$before")" -eq 1
settle "$before"

echo
echo "## 4. Writes to other names restart nothing"
mark="$(date +%s)"
as_site sh -c "for i in \$(seq 1 1000); do printf 'x %s\n' \$i > $DOCROOT/notes.txt; printf 'x\n' > $DOCROOT/.htaccess.bak; printf 'x\n' > $DOCROOT/x.htaccess; done"
sleep $((WINDOW + QUIET + 5))
check "1000 writes each to notes.txt, .htaccess.bak and x.htaccess restarted nothing" test "$(restarts_since "$mark")" -eq 0

echo
echo "## 5. A flood of 1000 .htaccess writes restarts at most once per window"
flood="$(date +%s)"
as_site sh -c "for i in \$(seq 1 1000); do printf 'RewriteEngine On\nRewriteRule ^proof-flood\$ /rule-target.txt?n=%s [L]\n' \$i > $DOCROOT/.htaccess; sleep 0.06; done; printf 'RewriteEngine On\nRewriteRule ^proof-flood\$ /flood-final.txt [L]\n' > $DOCROOT/.htaccess"
flood_end="$(date +%s)"
check "the last write's rule is the one served" wait_body /proof-flood "flood final $RUNID" 120
sleep $((WINDOW + QUIET + 10))
done_at="$(date +%s)"
n="$(restarts_since "$flood")"
bound=$((1 + (done_at - flood) / WINDOW))
echo "  1001 writes over $((flood_end - flood)) s; $n restarts in the $((done_at - flood)) s since the flood began (at most $bound)"
restart_lines "$flood" | sed 's/^/  /'
check "the flood restarted OpenLiteSpeed at least once" test "$n" -ge 1
check "the flood restarted it at most once per window ($n <= $bound)" test "$n" -le "$bound"
check "consecutive restarts ended at least $WINDOW s apart" spaced "$flood"

echo
echo "## 6. The broker's lines name counts only, and nothing failed"
journal_since "$start" | grep -F 'htaccess' | sed 's/^/  /'
check "no htaccess line names the site's user, domain or home" bash -c "! journalctl -u $UNIT --since @$start --no-pager | grep -F htaccess | grep -q -e '$SITE_USER' -e '$DOMAIN' -e '/home/'"
check "no restart failed (no recovery line for operation=htaccess)" bash -c "! journalctl -u $UNIT --since @$start --no-pager | grep -q 'operation=htaccess'"
check "OpenLiteSpeed is running" systemctl is-active --quiet lsws

echo
echo "## 7. Delete"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"
systemctl stop "$UNIT" 2>/dev/null

echo
echo "## 8. The root-only Go tests of the watcher on this kernel"
echo "  TMPDIR's filesystem: $(stat -f -c %T "${TMPDIR:-/tmp}")"
go_log="$("$BIN/hostaccounts.test" -test.run '^(TestRootOnlyHtaccessWatchRestartsOnceForAWrite|TestHtaccessEventsFromTheKernel)$' -test.v -test.count=1 2>&1)"
printf '%s\n' "$go_log" | grep -E -- '^(=== RUN|--- |    |ok|FAIL|PASS)' | sed 's/^/  /'
check "a filesystem mark sees one .htaccess write as one restart" grep -q -- '--- PASS: TestRootOnlyHtaccessWatchRestartsOnceForAWrite' <<<"$go_log"
check "the kernel's events are read and counted the watcher's way" grep -q -- '--- PASS: TestHtaccessEventsFromTheKernel' <<<"$go_log"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
