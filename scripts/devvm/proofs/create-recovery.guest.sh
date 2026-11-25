#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh create-recovery copies it in).
# Proves the create recovery slice at the real broker: a create whose
# groupadd waits on shadow-utils' lock is not killed and its reason is
# logged; the state a useradd stopped after making the home leaves (passwd
# and group written, an empty root:root mode-0 home) is finished when the
# broker starts again; a create the broker cannot finish holds up every
# account until the operator abandons it, which is refused for an active
# account and for a home the create did not make. Then the root-only Go
# tests of the same native code run. Prints PASS/FAIL per check; the exit
# status is the number of FAILs.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
UNIT=sifruno-broker-proof
WORK=/root/sifruno-create-recovery
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
A_USER="cra${RUNID}"
B_USER="crb${RUNID}"
C_USER="crc${RUNID}"
D_USER="crd${RUNID}"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
# account USER: the listed account with this username, as JSON, or nothing.
account() {
  drive list | python3 -c "import json,sys; a=[x for x in json.load(sys.stdin) if x['username']=='$1']; print(json.dumps(a[0]) if a else '')"
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
state_of() { account "$1" | field "['state']" 2>/dev/null; }
is_state() { test "$(state_of "$1")" = "$2"; }
gone_from_list() { test -z "$(account "$1")"; }
start_broker() {
  systemctl stop "$UNIT" 2>/dev/null
  systemctl reset-failed "$UNIT" 2>/dev/null
  systemd-run --quiet --unit "$UNIT" --collect \
    "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)"
  for _ in $(seq 1 90); do [ -S "$SOCKET" ] && return 0; sleep 1; done
  return 1
}
# recovery_lines SINCE: the broker's recovery log since a journal time.
recovery_lines() { journalctl -u "$UNIT" --since "$1" -o cat --no-pager | grep 'sifruno broker: recovery:'; }
logged() { recovery_lines "$1" | grep -qF -- "$2"; }
not_logged() { ! logged "$@"; }
# hold_pwd_lock SECONDS: holds /etc/.pwd.lock with a POSIX write lock, as
# glibc's lckpwdf takes it for shadow-utils, so groupadd waits for it (15 s
# at most) and then gives up by itself. The caller ends it earlier.
hold_pwd_lock() {
  : >"$WORK/lock.out"
  python3 -I -c 'import fcntl, sys, time
f = open("/etc/.pwd.lock", "a")
fcntl.lockf(f, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(float(sys.argv[1]))' "$1" >"$WORK/lock.out" 2>&1 &
  LOCK_PID=$!
  for _ in $(seq 1 50); do grep -q held "$WORK/lock.out" && return 0; sleep 0.1; done
  return 1
}
# interrupted_create USER: a create whose groupadd cannot take its lock:
# the broker journals the create, groupadd gives up, and the create ends
# recovery_required with only the ownership marker and the slice drop-in
# made. The lock is held until the create answers.
interrupted_create() {
  local started answer
  hold_pwd_lock 300 || return 1
  started=$SECONDS
  answer="$(drive create --username "$1" --domain "$1.proof.test" --reason 'Create recovery proof' 2>&1 >/dev/null)"
  kill "$LOCK_PID" 2>/dev/null
  wait "$LOCK_PID" 2>/dev/null
  echo "  create of $1 while the lock was held answered after $((SECONDS - started)) s: $answer"
  grep -q 'recovery' <<<"$answer"
}
# step_ok WHAT STATUS: one check from a status already taken.
step_ok() { if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1"; fi; }
journal_time() { date '+%Y-%m-%d %H:%M:%S'; }

install -d -m 0700 "$WORK"
echo "# Create recovery: no killed shadow-utils, a stopped useradd finished, an unfinishable create abandoned"
echo "# $(date -u +%FT%TZ)  $(cat /etc/almalinux-release)  $(rpm -q shadow-utils glibc | paste -sd ' ')  SELinux $(getenforce)"
echo "# accounts A $A_USER, B $B_USER, C $C_USER, D $D_USER"

echo
echo "## 1. The broker starts; nothing is unfinished"
t="$(journal_time)"
check "the broker started" start_broker
pending="$(drive list | python3 -c "import json,sys; print(' '.join(a['username'] for a in json.load(sys.stdin) if a['state']=='recovery_required'))")"
if [ -n "$pending" ]; then
  echo "  recovery_required before this proof: $pending"
  recovery_lines "$t" | sed 's/^/    /'
  fail "no account was left recovery_required by an earlier run (clear it first)"
  exit "$fails"
fi
pass "no account is recovery_required"

echo
echo "## 2. groupadd waits on its lock: the broker lets it finish and logs why the create stopped"
t="$(journal_time)"
interrupted_create "$A_USER"
step_ok "A's create ends recovery_required (groupadd could not take its lock)" $?
a="$(account "$A_USER")"
a_id="$(printf '%s' "$a" | field "['id']")"
a_uid="$(printf '%s' "$a" | field "['uid']")"
echo "  broker log since the create:"
recovery_lines "$t" | sed 's/^/    /'
check "the log names A's create, step groupadd, and that groupadd exited by itself" logged "$t" "operation=create account=$a_id user=$A_USER step=\"groupadd\" error=\"groupadd exited with status"
check "groupadd was not stopped at a time limit" not_logged "$t" "groupadd was stopped at its time limit"
check "groupadd made no group" bash -c "! getent group $A_USER"
t="$(journal_time)"
answer="$(drive create --username "$B_USER" --domain "$B_USER.proof.test" --reason 'Held up' 2>&1 >/dev/null)"
echo "  another create meanwhile: $answer"
check "another account's create is refused (recovery)" grep -q recovery <<<"$answer"
check "the log names the account that holds it up" logged "$t" "operation=create account=$a_id user=$A_USER step=\"unfinished, so this change is refused\""

echo
echo "## 3. useradd stopped after it made the home: the next start finishes the create"
# What the killed useradd left on this VM: passwd and group written by the
# create's own arguments, and the home made by mkdir(path, 0) as root.
groupadd --gid "$a_uid" -- "$A_USER"
useradd --uid "$a_uid" --gid "$a_uid" --no-user-group --groups '' --no-create-home --home-dir "/home/$A_USER" \
  --shell /usr/sbin/nologin --comment "sifruno-managed-$a_id" --password '!' --expiredate '' -- "$A_USER"
mkdir -m 0 "/home/$A_USER"
echo "  left: $(getent passwd "$A_USER")"
echo "  left: $(ls -ld "/home/$A_USER")"
check "the home is root:root, mode 0, empty" test "$(stat -c '%U:%G %a' "/home/$A_USER")-$(find "/home/$A_USER" -mindepth 1 | wc -l)" = "root:root 0-0"
t="$(journal_time)"
check "the broker starts again" start_broker
check "A is active" is_state "$A_USER" active
check "A's home is A's own with mode 0750" test "$(stat -c '%U:%G %a' "/home/$A_USER")" = "$A_USER:$A_USER 750"
check "A's public_html is A's own with mode 0750" test "$(stat -c '%U:%G %a' "/home/$A_USER/public_html")" = "$A_USER:$A_USER 750"
check "the start logged no recovery for A" not_logged "$t" "account=$a_id"
b="$(drive create --username "$B_USER" --domain "$B_USER.proof.test" --reason 'Free again')" || fail "B is created now"
b_id="$(printf '%s' "$b" | field "['id']")"
check "B is active" is_state "$B_USER" active

echo
echo "## 4. A create the broker cannot finish holds up every account until the operator abandons it"
interrupted_create "$C_USER"
step_ok "C's create ends recovery_required" $?
c="$(account "$C_USER")"
c_id="$(printf '%s' "$c" | field "['id']")"
c_uid="$(printf '%s' "$c" | field "['uid']")"
# What a groupadd that ran before a useradd that never ran leaves.
groupadd --gid "$c_uid" -- "$C_USER"
t="$(journal_time)"
check "the broker starts again" start_broker
check "C stays recovery_required: a group alone is not a finished create" is_state "$C_USER" recovery_required
echo "  broker log since the start:"
recovery_lines "$t" | sed 's/^/    /'
check "the log says why the start could not finish C" logged "$t" "operation=create account=$c_id user=$C_USER step=\"finish at start / passwd and group\""
answer="$(drive create --username "$D_USER" --domain "$D_USER.proof.test" --reason 'Held up' 2>&1 >/dev/null)"
check "another account's create is refused (recovery)" grep -q recovery <<<"$answer"
answer="$(drive abandon-create --id "$b_id" --reason 'Not a create' 2>&1 >/dev/null)"
echo "  abandon of B, an active account: $answer"
check "is refused: no_unfinished_create" grep -q no_unfinished_create <<<"$answer"
check "and B is still active" is_state "$B_USER" active
install -d -m 0700 "/home/$C_USER"
touch "/home/$C_USER/planted"
answer="$(drive abandon-create --id "$c_id" --reason 'Remove the leftovers' 2>&1 >/dev/null)"
echo "  abandon of C with a home the create did not make: $answer"
check "is refused: home" grep -q 'refused: home$' <<<"$answer"
check "and removed nothing: C's group and the planted file are there" bash -c "getent group $C_USER && test -e /home/$C_USER/planted"
rm -rf -- "/home/${C_USER:?}"
t="$(journal_time)"
abandoned="$(drive abandon-create --id "$c_id" --reason 'Leftover of an interrupted create')" || fail "the operator abandons C"
echo "  abandon of C: $(printf '%s' "$abandoned" | field "['state']")"
check "C is gone from the list" gone_from_list "$C_USER"
check "C's group is gone" bash -c "! getent group $C_USER"
check "C's ownership marker is gone" test ! -e "$STATE/owners/$c_id"
check "C's slice drop-in is gone" test ! -e "/etc/systemd/system/user-$c_uid.slice.d/50-sifruno-limits.conf"
check "the abandon logged no recovery" not_logged "$t" "account=$c_id"
drive create --username "$D_USER" --domain "$D_USER.proof.test" --reason 'Every account unblocked' >/dev/null || fail "D is created after the abandon"
check "D is active" is_state "$D_USER" active

echo
echo "## 5. The root-only Go tests of the same native code"
if "$BIN/hostaccounts.test" -test.run 'RootOnly(RecoverCreateAdoptsUseraddHome|AbandonCreate)' -test.v 2>&1 | sed 's/^/  /' | tee "$WORK/root-tests.log" | grep -E -- '^  (--- |ok|FAIL|PASS)'; then :; fi
check "TestRootOnlyRecoverCreateAdoptsUseraddHome passed" grep -q -- '--- PASS: TestRootOnlyRecoverCreateAdoptsUseraddHome' "$WORK/root-tests.log"
check "TestRootOnlyAbandonCreate passed" grep -q -- '--- PASS: TestRootOnlyAbandonCreate ' "$WORK/root-tests.log"
check "no root-only test failed" bash -c "! grep -q -- '--- FAIL' $WORK/root-tests.log"

echo
echo "## 6. Clean up"
for user in "$A_USER" "$B_USER" "$D_USER"; do
  acct="$(account "$user")"
  [ -n "$acct" ] || continue
  drive delete --id "$(printf '%s' "$acct" | field "['id']")" --revision "$(printf '%s' "$acct" | field "['revision']")" --reason 'Create recovery proof done' >/dev/null || fail "delete $user"
done
check "no account of this run is left" bash -c "! getent passwd $A_USER && ! getent passwd $B_USER && ! getent passwd $D_USER"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
