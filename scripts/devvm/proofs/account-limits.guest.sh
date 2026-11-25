#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh account-limits copies it in).
# Proves the per-account process, memory and CPU limits: the installer's
# pam_limits file and OpenLiteSpeed cgroups setting, the broker's slice
# drop-in at create and plan change, a login session (pam_systemd, as for
# SFTP and cron) in the user slice, a tenant's fork loop stopping at the
# limit, the site's lsphp process held by the slice, the delete of an
# active site while a fork loop runs, and a WordPress install step whose tenant wp-cli.yml starts a
# fork loop: held in its own unit in the account's slice, the broker still
# answering, nothing left after the step. Prints PASS/FAIL per check, and
# what it read.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
# Each site's LSCache store is in this root-owned folder (olsweb.CacheRoot).
LSCACHE=/var/lib/sifruno-lscache
UNITS=/etc/systemd/system
LIMITS_FILE=/etc/security/limits.d/90-sifruno-accounts.conf
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
# Files the tenant copies into its public_html, readable by it.
WORK="/tmp/account-limits-proof-$RUNID"
# What the panel holds lives in its own home, where brokerdrive (as sifpanel)
# can read it.
PANEL="/var/lib/sifpanel/limits-proof-$RUNID"
A_USER="lma${RUNID}"
B_USER="lmb${RUNID}"
A_DOMAIN="${A_USER}.proof.test"
B_DOMAIN="${B_USER}.proof.test"
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
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1$2"; }
wait_for() { # wait_for DOMAIN PATH CODE [TEXT]
  local _
  for _ in $(seq 1 150); do
    if [ "$(code "$1" "$2")" = "$3" ] && { [ -z "${4:-}" ] || curl -s -H "Host: $1" "http://127.0.0.1$2" | grep -q "$4"; }; then
      return 0
    fi
    sleep 2
  done
  return 1
}
# The tenant's own file writes, as its user without PAM.
as_tenant() { # as_tenant USER COMMAND
  local uid
  uid="$(id -u "$1")"
  setpriv --reuid="$uid" --regid="$uid" --clear-groups -- sh -c "cd /home/$1 && $2"
}
# A login session of the tenant, as sshd (SFTP) and crond start one: their
# PAM stacks include password-auth, whose pam_systemd registers the session
# under user-<uid>.slice, and pam_limits applies limits.d (section 3 checks
# both stacks). runuser -l uses the runuser-l stack, which has pam_systemd
# too; plain runuser -u has not, and its process stays in the unit that
# started it. Started from a transient system service so it is not inside
# this script's own (root's) login session; --shell because the tenant's
# shell is nologin.
tenant_session() { # tenant_session USER COMMAND...
  systemd-run --quiet --wait --pipe --collect -- \
    /usr/sbin/runuser -l "$1" --shell=/bin/bash --command="$(printf '%q ' "${@:2}")"
}
# The same, left running in the background as unit NAME.
tenant_session_bg() { # tenant_session_bg NAME USER COMMAND...
  systemd-run --quiet --collect --unit "$1" -- \
    /usr/sbin/runuser -l "$2" --shell=/bin/bash --command="$(printf '%q ' "${@:3}")"
}
# pam_systemd is in a PAM service's session stack, directly or through an
# include or substack of password-auth or system-auth.
pam_has_systemd() { # pam_has_systemd SERVICE
  grep -qE '^-?session\s+\S+\s+pam_systemd\.so' "/etc/pam.d/$1" && return 0
  local inc
  while read -r inc; do
    grep -qE '^-?session\s+\S+\s+pam_systemd\.so' "/etc/pam.d/$inc" && return 0
  done < <(awk '$1 ~ /^-?session$/ && ($2 == "include" || $2 == "substack") {print $3}' "/etc/pam.d/$1")
  return 1
}
slice_dir() { printf '/sys/fs/cgroup/user.slice/user-%s.slice' "$1"; }
show() { systemctl show -P "$2" "user-$1.slice"; }
slice_has() { # slice_has UID TASKSMAX MEMORYMAX_BYTES CPUQUOTA_PER_SEC
  [ "$(show "$1" TasksMax)" = "$2" ] && [ "$(show "$1" MemoryMax)" = "$3" ] && [ "$(show "$1" CPUQuotaPerSecUSec)" = "$4" ]
}
has_limits() { # has_limits JSON PROCESSES MEMORY_MIB CPU_PERCENT
  printf '%s' "$1" | python3 -c "import json,sys; d=json.load(sys.stdin); l=d.get('account', d).get('limits'); sys.exit(0 if l == {'processes': $2, 'memory_mib': $3, 'cpu_percent': $4} else 1)"
}
between() { [ "${1:-0}" -ge "$2" ] && [ "${1:-0}" -le "$3" ]; }
ols_cgroups() { awk '/^CGIRLimit/{b=1} b&&$1=="cgroups"{print $2; exit}' "$LSWS/conf/httpd_config.conf"; }

# A loop that forks sleeping children until fork() fails or 150 are running,
# then prints how many it made and the error, and ends them.
FORK_COUNT='
import os, signal, time
kids, err = [], "none"
for _ in range(150):
    try:
        pid = os.fork()
    except OSError as e:
        err = e.strerror
        break
    if pid == 0:
        time.sleep(120)
        os._exit(0)
    kids.append(pid)
print(len(kids), err)
for k in kids:
    os.kill(k, signal.SIGKILL)
for k in kids:
    os.waitpid(k, 0)
'
# A fork loop that never stops: every process keeps forking, and waits a
# moment when fork() fails, so it refills whatever the broker ends.
FORK_LOOP='
import os, time
while True:
    try:
        os.fork()
    except OSError:
        time.sleep(0.01)
'

echo "# Per-account process, memory and CPU limits"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 systemd pam | paste -sd ' ')  SELinux $(getenforce)  cgroup fs $(stat -fc %T /sys/fs/cgroup)"
echo "# account A $A_USER ($A_DOMAIN), account B $B_USER ($B_DOMAIN)"

echo
echo "## 1. The installer's three steps"
# The VM was provisioned by an older installer: run the three new steps from
# this release's install.sh, as an upgrade would. In a subshell, because
# install.sh turns on errexit, which this script does not use.
# shellcheck disable=SC1091
(SIFRUNO_INSTALL_FUNCTIONS_ONLY=1 . "$BIN/install.sh" && step_limits && step_ols_cgroups && step_lscache && printf '  changed: %s\n' "${CHANGES[@]}") || fail "the installer's limits, cgroups and LSCache stores steps run"
check "the limits file is root's, 0644" test "$(stat -c '%U:%G %a' "$LIMITS_FILE")" = "root:root 644"
check "it sets the backstop nproc 4096, soft and hard, for UIDs 20000:60000" grep -qxE '20000:60000 +hard +nproc +4096' "$LIMITS_FILE"
check "and the soft limit too" grep -qxE '20000:60000 +soft +nproc +4096' "$LIMITS_FILE"
echo "  CGIRLimit cgroups: $(ols_cgroups)"
check "OpenLiteSpeed's CGIRLimit has cgroups 1" test "$(ols_cgroups)" = 1
check "the LSCache stores folder is root's, mode 0711" test "$(stat -c '%U:%G %a' "$LSCACHE" 2>/dev/null)" = "root:root 711"
# shellcheck disable=SC2016 # expands in the inner shell
check "the installer's steps change nothing the second time" bash -c 'SIFRUNO_INSTALL_FUNCTIONS_ONLY=1 . "$0" && step_limits && step_ols_cgroups && step_lscache && [ "${#CHANGES[@]}" -eq 0 ]' "$BIN/install.sh"
check "OpenLiteSpeed is running" systemctl is-active --quiet lsws

echo
echo "## 2. The broker writes each account's slice limits"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
a="$(drive create --username "$A_USER" --domain "$A_DOMAIN" --reason 'Limits proof, account A')" || fail "broker creates account A"
b="$(drive create --username "$B_USER" --domain "$B_DOMAIN" --reason 'Limits proof, account B')" || fail "broker creates account B"
a_id="$(printf '%s' "$a" | field '["id"]')"
b_id="$(printf '%s' "$b" | field '["id"]')"
a_rev="$(printf '%s' "$a" | revision)"
b_rev="$(printf '%s' "$b" | revision)"
a_uid="$(id -u "$A_USER")"
dropin="$UNITS/user-$a_uid.slice.d/50-sifruno-limits.conf"
echo "  $dropin:"
sed 's/^/    /' "$dropin"
check "A's answer carries the default limits" has_limits "$a" 100 1024 100
check "A's drop-in is root's, 0644" test "$(stat -c '%U:%G %a' "$dropin")" = "root:root 644"
check "systemd loaded it: TasksMax 100, MemoryMax 1 GiB, CPUQuota 100%" slice_has "$a_uid" 100 1073741824 1s

echo
echo "## 3. A login session lands in the user slice with TasksMax set"
for svc in sshd crond runuser-l; do
  check "the $svc PAM stack registers a session with pam_systemd" pam_has_systemd "$svc"
done
session="$(tenant_session "$A_USER" /usr/bin/cat /proc/self/cgroup /proc/self/limits)"
printf '%s\n' "$session" | grep -E '^0::|Max processes|Max address space' | sed 's/^/  /'
check "the session runs in user-$a_uid.slice" grep -q "^0::/user.slice/user-$a_uid.slice/" <<<"$session"
check "the session's RLIMIT_NPROC is the backstop 4096 (limits.d)" grep -qE '^Max processes +4096 +4096 ' <<<"$session"
tenant_session_bg "limits-proof-hold-$RUNID" "$A_USER" /usr/bin/sleep 600
# pam_systemd starts the user manager before the session runs; on a
# slow machine that takes a while.
for _ in $(seq 1 90); do [ -e "$(slice_dir "$a_uid")/pids.max" ] && pgrep -u "$a_uid" -x sleep >/dev/null && break; sleep 1; done
echo "  pids.max $(cat "$(slice_dir "$a_uid")/pids.max" 2>&1), memory.max $(cat "$(slice_dir "$a_uid")/memory.max" 2>&1), cpu.max $(cat "$(slice_dir "$a_uid")/cpu.max" 2>&1)"
check "the active slice's pids.max is 100" test "$(cat "$(slice_dir "$a_uid")/pids.max")" = 100

echo
echo "## 4. A plan change moves the limits, also of the active slice"
planned="$(drive plan --id "$a_id" --revision "$a_rev" --plan larger --processes 120 --memory-mib 2048 --cpu-percent 200 --reason 'Larger plan')" || fail "A's plan changes to 120 tasks, 2 GiB, two CPUs"
a_rev="$(printf '%s' "$planned" | revision)"
check "the answer carries the new limits" has_limits "$planned" 120 2048 200
check "the drop-in says TasksMax=120" grep -qx 'TasksMax=120' "$dropin"
check "systemd loaded it: TasksMax 120, MemoryMax 2 GiB, CPUQuota 200%" slice_has "$a_uid" 120 2147483648 2s
echo "  after the change: pids.max $(cat "$(slice_dir "$a_uid")/pids.max" 2>&1), memory.max $(cat "$(slice_dir "$a_uid")/memory.max" 2>&1), cpu.max $(cat "$(slice_dir "$a_uid")/cpu.max" 2>&1)"
check "daemon-reload applied it to the active slice: pids.max 120" test "$(cat "$(slice_dir "$a_uid")/pids.max")" = 120
check "and memory.max 2 GiB" test "$(cat "$(slice_dir "$a_uid")/memory.max")" = 2147483648
back="$(drive plan --id "$a_id" --revision "$a_rev" --plan default --processes 100 --memory-mib 1024 --cpu-percent 100 --reason 'Back to the default plan')" || fail "A's plan changes back to the defaults"
a_rev="$(printf '%s' "$back" | revision)"
check "the active slice's pids.max is 100 again" test "$(cat "$(slice_dir "$a_uid")/pids.max")" = 100
answer="$(drive plan --id "$a_id" --revision "$a_rev" --plan default --processes 5 --memory-mib 1024 --cpu-percent 100 --reason 'Too small' 2>&1 >/dev/null)"
echo "  5 tasks: $answer"
check "limits out of bounds are refused" grep -q 'invalid' <<<"$answer"
systemctl stop "limits-proof-hold-$RUNID" 2>/dev/null

echo
echo "## 5. A tenant's fork loop stops at the limit"
counted="$(tenant_session "$A_USER" /usr/bin/python3 -c "$FORK_COUNT")"
echo "  children made, and fork's error: $counted"
check "the loop made fewer than 100 children, not 150" between "${counted%% *}" 1 99
check "fork() failed with EAGAIN" grep -q 'Resource temporarily unavailable' <<<"$counted"

echo
echo "## 6. The site's lsphp and its limits"
as_tenant "$A_USER" "printf '%s\n' '<?php echo \"site A on php \", PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;' > public_html/index.php"
as_tenant "$B_USER" "printf '%s\n' '<?php echo \"site B on php \", PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;' > public_html/index.php"
a_live="$(drive web --id "$a_id" --revision "$a_rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "A goes live"
b_live="$(drive web --id "$b_id" --revision "$b_rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "B goes live"
a_rev="$(printf '%s' "$a_live" | revision)"
b_rev="$(printf '%s' "$b_live" | revision)"
vhconf="$LSWS/conf/vhosts/sifruno-u${a_id:0:31}/vhconf.conf"
grep -E '^(namespace|cgroups) |memHardLimit|procHardLimit' "$vhconf" | sed 's/^/  /'
check "A's vhost asks for cgroups" grep -qE '^cgroups +2$' "$vhconf"
check "and renders memHardLimit 1024M, procHardLimit 496" bash -c "grep -qE '^ +memHardLimit +1024M$' '$vhconf' && grep -qE '^ +procHardLimit +496$' '$vhconf'"
check "A serves PHP" wait_for "$A_DOMAIN" / 200 'site A on php 8.3'
check "B serves PHP" wait_for "$B_DOMAIN" / 200 'site B on php 8.3'
lsphp="$(pgrep -u "$a_uid" -f lsphp | head -1)"
if [ -n "$lsphp" ]; then
  echo "  lsphp $lsphp: $(cat "/proc/$lsphp/cgroup")"
  grep -E 'Max processes|Max address space' "/proc/$lsphp/limits" | sed 's/^/  /'
  check "lsphp runs in user-$a_uid.slice/litespeed-exec.scope (OpenLiteSpeed cgroups)" grep -q "^0::/user.slice/user-$a_uid.slice/litespeed-exec.scope" "/proc/$lsphp/cgroup"
  # OpenLiteSpeed sets the vhost's procHardLimit and memHardLimit as
  # rlimits only outside its namespace container (ns.c in 1.9.4; the
  # rlimits printed above are the system defaults), so with namespace on
  # the account's slice is lsphp's bound.
  echo "  slice: pids.max $(cat "$(slice_dir "$a_uid")/pids.max" 2>&1), memory.max $(cat "$(slice_dir "$a_uid")/memory.max" 2>&1)"
  check "lsphp's slice holds it to A's plan: pids.max 100" test "$(cat "$(slice_dir "$a_uid")/pids.max")" = 100
  check "and memory.max 1 GiB" test "$(cat "$(slice_dir "$a_uid")/memory.max")" = 1073741824
else
  fail "an lsphp process runs as A"
fi

echo
echo "## 7. Delete of the active site while a fork loop runs"
tenant_session_bg "limits-proof-loop-$RUNID" "$A_USER" /usr/bin/python3 -c "$FORK_LOOP"
for _ in $(seq 1 90); do [ "$(pgrep -u "$a_uid" -c)" -ge 20 ] && break; sleep 1; done
sleep 3
running="$(pgrep -u "$a_uid" -c)"
echo "  A's processes with the loop running: $running; slice pids.current $(cat "$(slice_dir "$a_uid")/pids.current" 2>&1)"
check "the loop runs, held at or under the limit" between "$running" 20 100
check "B still serves while A's loop runs" wait_for "$B_DOMAIN" / 200 'site B on php 8.3'
started="$(date +%s)"
if drive delete --id "$a_id" --revision "$a_rev" --reason 'Remove A with its fork loop' >/dev/null; then
  pass "the delete of active A succeeds with its fork loop running ($(($(date +%s) - started)) s)"
else
  fail "the delete of active A succeeds with its fork loop running"
fi
check "A's Linux user is gone" bash -c "! getent passwd $A_USER"
check "no process runs as A's UID" bash -c "! pgrep -u $a_uid"
check "A's drop-in is gone" test ! -e "$dropin"
check "B still serves" test "$(code "$B_DOMAIN" /)" = 200
systemctl stop "limits-proof-loop-$RUNID" 2>/dev/null

echo
echo "## 8. Tenant code in a WordPress install step stays in the account's slice"
# B's wp-cli.yml makes WP-CLI load fork.php before every command the broker
# runs in public_html. fork.php starts a fork loop that never stops in a new
# session (setsid), then waits, so the step is still running while this
# section looks. B has no database, so the install stops at a step; what
# matters is where the loop runs, that it stays bounded, that the broker
# answers meanwhile, and that nothing of it is left after the step.
b_uid="$(id -u "$B_USER")"
install -d -m 0755 "$WORK"
printf 'require:\n  - fork.php\n' > "$WORK/wp-cli.yml"
printf '%s\n' "$FORK_LOOP" > "$WORK/loop.py"
cat > "$WORK/fork.php" <<'PHP'
<?php
// Tenant code that WP-CLI loads through wp-cli.yml.
exec('/usr/bin/setsid /usr/bin/python3 ' . __DIR__ . '/loop.py > /dev/null 2>&1 &');
sleep(20);
PHP
chmod 0644 "$WORK/wp-cli.yml" "$WORK/loop.py" "$WORK/fork.php"
as_tenant "$B_USER" "cp $WORK/wp-cli.yml $WORK/loop.py $WORK/fork.php public_html/"
install -d -o sifpanel -g sifpanel -m 0700 "$PANEL"
for f in admin-password db-password; do
  head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20 > "$PANEL/$f"
  chown sifpanel:sifpanel "$PANEL/$f"
  chmod 0600 "$PANEL/$f"
done
drive wordpress --id "$b_id" --revision "$b_rev" --title 'Limits proof' --admin-user proofadmin \
  --admin-email "admin@$B_DOMAIN" --admin-password-file "$PANEL/admin-password" \
  --db-name "${B_USER}_wp" --db-user "${B_USER}_wp" --db-password-file "$PANEL/db-password" \
  >"$WORK/install.out" 2>"$WORK/install.err" &
install_pid=$!
# WP-CLI loads fork.php only once its own start-up is done, which takes a
# while under emulation; fork.php then holds the step for 20 s, so look for
# the loop until it shows, then give it a moment to fill the unit.
loop_pid=""
for _ in $(seq 1 150); do
  loop_pid="$(pgrep -u "$b_uid" -f loop.py | head -1)"
  [ -n "$loop_pid" ] || ! kill -0 "$install_pid" 2>/dev/null && break
  sleep 1
done
sleep 3
loop_pid="$(pgrep -u "$b_uid" -f loop.py | head -1)"
loop_cgroup="$(cat "/proc/${loop_pid:-0}/cgroup" 2>/dev/null)"
unit="$(sed -nE 's|^0::/user.slice/user-[0-9]+.slice/(sifruno-site-[0-9]+-[0-9a-f]{16}\.scope)$|\1|p' <<<"$loop_cgroup")"
echo "  loop process ${loop_pid:-none}: $loop_cgroup"
check "the loop runs in a sifruno-site scope in user-$b_uid.slice" grep -qE "^0::/user.slice/user-$b_uid.slice/sifruno-site-$b_uid-[0-9a-f]{16}\.scope$" <<<"$loop_cgroup"
php_pid="$(pgrep -u "$b_uid" -f wp-cli.phar | head -1)"
check "the loop runs in a session of its own (setsid), not WP-CLI's" bash -c "[ -n '$loop_pid' ] && [ -n '$php_pid' ] && [ \"\$(ps -o sid= -p $loop_pid)\" != \"\$(ps -o sid= -p $php_pid)\" ]"
unit_dir="$(slice_dir "$b_uid")/$unit"
echo "  $unit: pids.current $(cat "$unit_dir/pids.current" 2>&1), pids.max $(cat "$unit_dir/pids.max" 2>&1); slice pids.current $(cat "$(slice_dir "$b_uid")/pids.current" 2>&1)"
echo "  unit: TasksMax $(systemctl show -P TasksMax "$unit" 2>&1), RuntimeMaxUSec $(systemctl show -P RuntimeMaxUSec "$unit" 2>&1), KillMode $(systemctl show -P KillMode "$unit" 2>&1), KillSignal $(systemctl show -P KillSignal "$unit" 2>&1)"
echo "  WP-CLI ${php_pid:-none}: user $(ps -o user= -p "${php_pid:-0}" 2>&1), cwd $(readlink "/proc/${php_pid:-0}/cwd" 2>&1), $(awk '/^(NoNewPrivs|Cap[A-Za-z]+):/{printf "%s %s  ", $1, $2}' "/proc/${php_pid:-0}/status" 2>&1)"
check "the unit's task limit is B's plan, 100" test "$(systemctl show -P TasksMax "$unit")" = 100
check "the loop is held at or under it" between "$(cat "$unit_dir/pids.current")" 20 100
echo "  the broker's own tasks: $(systemctl show -P TasksCurrent sifruno-broker-proof)"
check "the broker's own cgroup holds few tasks" between "$(systemctl show -P TasksCurrent sifruno-broker-proof)" 1 60
started="$(date +%s)"
drive list >/dev/null
listed=$?
echo "  the broker answered a list in $(($(date +%s) - started)) s while the loop ran"
check "the broker answers while the loop runs" bash -c "[ $listed -eq 0 ] && [ $(($(date +%s) - started)) -le 10 ]"
check "WP-CLI's HOME is the broker's empty root-owned folder" bash -c "tr '\\0' '\\n' < /proc/${php_pid:-0}/environ | grep -qx HOME=/var/lib/sifruno-site-home"
# The step runs with the account's own group only, and its unit's
# description, which any local user can read, holds no site details.
groups_line="$(grep '^Groups:' "/proc/${php_pid:-0}/status" 2>/dev/null)"
echo "  WP-CLI's supplementary groups: ${groups_line:-none read}"
check "WP-CLI has no supplementary group but the account's own" bash -c "[ -n '$groups_line' ] && for g in \$(cut -f2- <<<'$groups_line'); do [ \"\$g\" = $b_uid ] || exit 1; done"
check "the unit's description is the fixed 'sifruno site step'" test "$(systemctl show -P Description "$unit" 2>/dev/null)" = "sifruno site step"
# setpriv sets no_new_privs and empties the capability sets before the step
# runs, so WP-CLI and everything it starts can gain no privilege.
check "WP-CLI cannot gain privileges (NoNewPrivs)" grep -qE '^NoNewPrivs:[[:space:]]*1$' "/proc/${php_pid:-0}/status"
check "WP-CLI holds no capability, not even in its bounding set" bash -c "for c in CapInh CapPrm CapEff CapBnd CapAmb; do grep -qE \"^\$c:[[:space:]]*0{16}\$\" /proc/${php_pid:-0}/status || exit 1; done"
wait "$install_pid"
echo "  install answer: $(cat "$WORK/install.err" "$WORK/install.out" | tr '\n' ' ')"
sleep 2
check "no loop process of B is left after the steps" bash -c "! pgrep -u $b_uid -f loop.py"
check "no sifruno-site unit is left" bash -c "[ -z \"\$(systemctl list-units --all --plain --no-legend 'sifruno-site-*')\" ]"
# The download step may have put WordPress's files in place, which redirect
# to its setup page while there is no wp-config.php.
check "B's site answers again" bash -c "for _ in \$(seq 1 30); do case \$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: $B_DOMAIN' http://127.0.0.1/) in 200|302) exit 0;; esac; sleep 2; done; exit 1"
b_store="$LSCACHE/sifruno-u${b_id:0:31}"
echo "  B's cache store before the delete: $(stat -c '%U %a %n' "$b_store" 2>&1)"
check "B's cache store is in $LSCACHE" test -d "$b_store"
drive delete --id "$b_id" --revision "$b_rev" --reason 'Remove B' >/dev/null || fail "the operator deletes B"
check "B's Linux user is gone" bash -c "! getent passwd $B_USER"
check "B's cache store is gone" test ! -e "$b_store"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws
rm -rf "$WORK" "$PANEL"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
