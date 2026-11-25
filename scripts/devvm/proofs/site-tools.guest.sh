#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh site-tools copies it in). Proves a
# site's scheduled jobs, logs and usage at the broker: a job the broker
# writes runs as the site's user, in its user slice, under the limits.d
# nproc, within two minutes; a refused job changes nothing; the access log
# tail shows a request just made; disk use grows after the user writes a
# file; traffic grows after requests; delete takes the crontab and the
# traffic counter away. Prints PASS/FAIL per check.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
SPOOL=/var/spool/cron
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="cron${RUNID}"
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
revision() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('account', d)['revision'])"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1$1"; }
wait_for() { # wait_for SECONDS COMMAND...
  local limit="$1" _
  shift
  for _ in $(seq 1 "$limit"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

echo "# Scheduled jobs, logs and usage at the broker"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed cronie | paste -sd ' ')  SELinux $(getenforce)"
echo "# site user $SITE_USER, domain $DOMAIN"

echo
echo "## 1. crond and the broker with the web operation"
rpm -q cronie >/dev/null 2>&1 || dnf -y -q install cronie >/dev/null 2>&1
systemctl enable --now crond >/dev/null 2>&1
check "crond is running (the installer installs cronie and starts it)" systemctl is-active --quiet crond
echo "  $SPOOL: $(stat -c '%U:%G %a' "$SPOOL"), SELinux $(stat -c %C "$SPOOL")"
echo "  /etc/pam.d/crond: $(grep -v '^#' /etc/pam.d/crond | grep -v '^$' | paste -sd ';')"
echo "  authselect: $(authselect current 2>/dev/null | head -1)"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
wait_for 60 test -S "$SOCKET"
check "the broker started with --web-user $ols_user" test -S "$SOCKET"

echo
echo "## 2. A live site"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Site tools proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | field "['id']")"
uid="$(id -u "$SITE_USER")"
rev="$(printf '%s' "$created" | revision)"
runuser -u "$SITE_USER" -- sh -c "printf '%s\n' '<?php echo \"site tools proof\";' > /home/$SITE_USER/public_html/index.php && head -c 102400 /dev/urandom > /home/$SITE_USER/public_html/blob.bin"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | revision)"
serves() { curl -s -H "Host: $DOMAIN" http://127.0.0.1/ | grep -q 'site tools proof'; }
check "the site serves" wait_for 300 serves

echo
echo "## 3. A scheduled job runs as the site's user, in its slice"
job='* * * * * id -u > ~/cron-ran.txt; cat /proc/self/cgroup >> ~/cron-ran.txt; ulimit -u >> ~/cron-ran.txt'
set="$(drive set-cron --id "$id" --revision "$rev" --job "$job" --reason 'Proof job')" || fail "the broker writes the job"
rev="$(printf '%s' "$set" | revision)"
echo "  $SPOOL/$SITE_USER: $(stat -c '%U:%G %a links %h' "$SPOOL/$SITE_USER" 2>&1), SELinux $(stat -c %C "$SPOOL/$SITE_USER" 2>&1)"
sed 's/^/    /' "$SPOOL/$SITE_USER"
check "the crontab is root's, 0600, one link" test "$(stat -c '%U:%G %a %h' "$SPOOL/$SITE_USER")" = "root:root 600 1"
job_listed() { drive cron --id "$id" | python3 -c "import json,sys; j=json.load(sys.stdin)['jobs']; sys.exit(0 if len(j) == 1 and j[0]['next_run'] else 1)"; }
check "the job list shows the job with its next run" job_listed
check "the job ran within two minutes" wait_for 130 test -s "/home/$SITE_USER/cron-ran.txt"
echo "  the job wrote: $(paste -sd ' ' "/home/$SITE_USER/cron-ran.txt" 2>&1)"
check "it ran as the site's user (UID $uid)" test "$(head -1 "/home/$SITE_USER/cron-ran.txt")" = "$uid"
check "its file belongs to the site's user" test "$(stat -c %u "/home/$SITE_USER/cron-ran.txt")" = "$uid"
check "it ran in user-$uid.slice" grep -q "user.slice/user-$uid.slice/" "/home/$SITE_USER/cron-ran.txt"
check "its process limit is the limits.d nproc (4096)" test "$(tail -1 "/home/$SITE_USER/cron-ran.txt")" = 4096
echo "  user-$uid.slice TasksMax: $(systemctl show -p TasksMax "user-$uid.slice" 2>&1)"
echo "  crond's log: $(grep -h "($SITE_USER) CMD" /var/log/cron 2>/dev/null | tail -1)"
before="$(sha256sum "$SPOOL/$SITE_USER" | cut -d' ' -f1)"
refuses_percent() { ! drive set-cron --id "$id" --revision "$rev" --job '* * * * * date +%s' --reason 'Refused'; }
check "a job with % is refused" refuses_percent
check "the refusal changed nothing" test "$(sha256sum "$SPOOL/$SITE_USER" | cut -d' ' -f1)" = "$before"

echo
echo "## 4. The access log tail shows a request just made"
probe="/proof-tail-${RUNID}"
echo "  GET $probe answered $(code "$probe")"
tail_has() { drive log --id "$id" --kind access | grep -q "$probe"; }
check "the tail holds the request" wait_for 60 tail_has
check "the error log tail reads" drive log --id "$id" --kind error

echo
echo "## 5. Disk use grows after the user writes a file"
used() { drive usage --id "$id" | field "['disk_used_kib']"; }
disk_before="$(used)"
runuser -u "$SITE_USER" -- dd if=/dev/zero of="/home/$SITE_USER/fill.bin" bs=1M count=20 conv=fsync status=none
disk_after="$(used)"
echo "  disk used: $disk_before KiB, then $disk_after KiB; limit $(drive usage --id "$id" | field "['disk_limit_kib']") KiB"
check "it grew by at least 20 MiB" test "$((disk_after - disk_before))" -ge 20480
check "the limit is the 200 MiB quota" test "$(drive usage --id "$id" | field "['disk_limit_kib']")" = 204800

echo
echo "## 6. Traffic grows after requests"
traffic() { drive usage --id "$id" | field "['traffic_bytes']"; }
traffic_before="$(traffic)"
for _ in 1 2 3 4 5; do code /blob.bin >/dev/null; done
grown() { test "$(( $(traffic) - traffic_before ))" -ge 512000; }
check "five 100 KiB responses were counted" wait_for 60 grown
echo "  traffic this month: $traffic_before, then $(traffic) bytes ($(drive usage --id "$id" | field "['traffic_month']"))"
counter="$(find "$STATE" -path '*usage*' -name "$id.json" 2>/dev/null | head -1)"
echo "  counter: $counter $(stat -c '%U:%G %a' "$counter" 2>&1)"
check "the counter file is root's and 0600" test "$(stat -c '%U:%G %a' "$counter")" = "root:root 600"

echo
echo "## 7. Delete takes the crontab and the counter"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
check "the crontab is gone" test ! -e "$SPOOL/$SITE_USER"
check "the counter is gone" test ! -e "$counter"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
