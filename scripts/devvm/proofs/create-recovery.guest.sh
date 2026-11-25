#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh create-recovery copies it in).
# Proves the create recovery slice at the real broker: a create whose
# groupadd waits on shadow-utils' lock is not killed and its reason is
# logged; the state a useradd stopped after making the home leaves (passwd
# and group written, an empty root:root mode-0 home) is finished when the
# broker starts again; a create the broker cannot finish holds up every
# account until the operator abandons it, which is refused for an active
# account and for a home the create did not make. The delete side: a delete
# whose userdel cannot take shadow-utils' lock stays pending and the next
# start finishes it, other accounts unblocked; a delete the broker cannot
# finish (a trash that is not its own) holds every account until the
# operator finishes it; a 200,000-file home is deleted at once, the trash
# drains in the background and its UID is not given out meanwhile. Then the
# root-only Go tests of the same native code run. Prints PASS/FAIL per
# check; the exit status is the number of FAILs.
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
E_USER="cre${RUNID}"
F_USER="crf${RUNID}"
G_USER="crg${RUNID}"
H_USER="crh${RUNID}"
I_USER="cri${RUNID}"
J_USER="crj${RUNID}"
TRASH=/home/.sifruno-trash
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
# journalctl --since has whole-second precision: wait for the next second,
# so a line logged before this mark is never counted as after it.
journal_time() {
  sleep 1
  date '+%Y-%m-%d %H:%M:%S'
}
# cleanup_lines SINCE: the broker's cleanup log (the trash remover's) since then.
cleanup_lines() { journalctl -u "$UNIT" --since "$1" -o cat --no-pager | grep 'sifruno broker: cleanup:'; }
cleanup_logged() { cleanup_lines "$1" | grep -qF -- "$2"; }
# wait_until SECONDS COMMAND...: runs COMMAND every second until it succeeds
# or the time is up.
wait_until() {
  local limit="$1"
  shift
  for _ in $(seq 1 "$limit"); do "$@" && return 0; sleep 1; done
  "$@"
}
# lowest_free_id: the ID a create would get if no trash entry held one back:
# the lowest in the account range that no user or group has and that is not
# the controller's.
lowest_free_id() {
  python3 -I -c 'import grp, pwd, sys
used = {p.pw_uid for p in pwd.getpwall()} | {g.gr_gid for g in grp.getgrall()} | {int(sys.argv[1])}
print(next(i for i in range(20000, 60001) if i not in used))' "$(id -u sifpanel)"
}
trash_empty() { [ ! -d "$TRASH" ] || [ -z "$(ls -A "$TRASH")" ]; }
files_in() { find "$1" -xdev -type f 2>/dev/null | wc -l; }
no_files_in() { test "$(files_in "$1")" -eq 0; }

install -d -m 0700 "$WORK"
echo "# Create recovery: no killed shadow-utils, a stopped useradd finished, an unfinishable create abandoned"
echo "# $(date -u +%FT%TZ)  $(cat /etc/almalinux-release)  $(rpm -q shadow-utils glibc | paste -sd ' ')  SELinux $(getenforce)"
echo "# accounts A $A_USER, B $B_USER, C $C_USER, D $D_USER, E $E_USER, F $F_USER, G $G_USER, H $H_USER, I $I_USER, J $J_USER"

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
echo "## 5. A delete whose userdel cannot take its lock stays pending; the next start finishes it"
e="$(drive create --username "$E_USER" --domain "$E_USER.proof.test" --reason 'Delete recovery proof')" || fail "E is created"
e_id="$(printf '%s' "$e" | field "['id']")"
e_uid="$(printf '%s' "$e" | field "['uid']")"
# A suspended account skips the delete's own lock step (usermod), so the
# first writer to wait on shadow-utils' lock is userdel itself.
drive state --id "$e_id" --revision "$(printf '%s' "$e" | field "['revision']")" --state suspended --reason 'Suspend before the delete' >/dev/null || fail "E is suspended"
e_rev="$(account "$E_USER" | field "['revision']")"
t="$(journal_time)"
if hold_pwd_lock 300; then
  started=$SECONDS
  answer="$(drive delete --id "$e_id" --revision "$e_rev" --reason 'Delete recovery proof' 2>&1 >/dev/null)"
  kill "$LOCK_PID" 2>/dev/null
  wait "$LOCK_PID" 2>/dev/null
  echo "  delete of E while the lock was held answered after $((SECONDS - started)) s: $answer"
else
  answer="the lock could not be held"
fi
check "E's delete ends recovery_required (userdel could not take its lock)" grep -q recovery <<<"$answer"
check "E is recovery_required" is_state "$E_USER" recovery_required
echo "  broker log since the delete:"
recovery_lines "$t" | sed 's/^/    /'
check "the log names E's delete, step remove user, and that userdel exited by itself" logged "$t" "operation=delete account=$e_id user=$E_USER step=\"remove / remove user\" error=\"userdel exited with status"
check "userdel changed nothing: E's user is still there" getent passwd "$E_USER"
answer="$(drive create --username "$F_USER" --domain "$F_USER.proof.test" --reason 'Held up' 2>&1 >/dev/null)"
check "another account's create is refused (recovery)" grep -q recovery <<<"$answer"
t="$(journal_time)"
check "the broker starts again" start_broker
check "E is gone from the list" gone_from_list "$E_USER"
check "E's user and group are gone" bash -c "! getent passwd $E_USER && ! getent group $E_USER"
check "E's home left the homes folder" test ! -e "/home/$E_USER"
check "E's ownership marker is gone" test ! -e "$STATE/owners/$e_id"
check "E's slice drop-in is gone" test ! -e "/etc/systemd/system/user-$e_uid.slice.d/50-sifruno-limits.conf"
check "the trash remover empties E's home from the trash" wait_until 120 test ! -e "$TRASH/$e_id"
check "the start logged no recovery for E" not_logged "$t" "account=$e_id"
drive create --username "$F_USER" --domain "$F_USER.proof.test" --reason 'Every account unblocked' >/dev/null || fail "F is created after the start"
check "F is active" is_state "$F_USER" active

echo
echo "## 6. A delete the broker cannot finish holds up every account until the operator finishes it"
g="$(drive create --username "$G_USER" --domain "$G_USER.proof.test" --reason 'Finish delete proof')" || fail "G is created"
g_id="$(printf '%s' "$g" | field "['id']")"
g_uid="$(printf '%s' "$g" | field "['uid']")"
# A trash that is not the broker's own: the delete refuses it before it
# removes anything, and no start can finish the delete until it is fixed.
mkdir -p "$TRASH"
chmod 0755 "$TRASH"
t="$(journal_time)"
answer="$(drive delete --id "$g_id" --revision "$(printf '%s' "$g" | field "['revision']")" --reason 'Finish delete proof' 2>&1 >/dev/null)"
echo "  delete of G with a trash of mode 0755: $answer"
check "G's delete ends recovery_required" grep -q recovery <<<"$answer"
check "the log names G's delete and the trash refusal" logged "$t" "operation=delete account=$g_id user=$G_USER step=\"remove / trash\" error=\"refused: trash\""
t="$(journal_time)"
check "the broker starts again" start_broker
check "G stays recovery_required: the start cannot finish it" is_state "$G_USER" recovery_required
check "the log says why the start could not finish G" logged "$t" "operation=delete account=$g_id user=$G_USER step=\"finish at start / trash\" error=\"refused: trash\""
answer="$(drive create --username "$H_USER" --domain "$H_USER.proof.test" --reason 'Held up' 2>&1 >/dev/null)"
check "another account's create is refused (recovery)" grep -q recovery <<<"$answer"
answer="$(drive finish-delete --id "$(account "$F_USER" | field "['id']")" --reason 'Not a delete' 2>&1 >/dev/null)"
echo "  finish-delete of F, an active account: $answer"
check "is refused: no_unfinished_delete" grep -q no_unfinished_delete <<<"$answer"
answer="$(drive finish-delete --id "$g_id" --reason 'Try before the fix' 2>&1 >/dev/null)"
echo "  finish-delete of G with the trash as it is: $answer"
check "is refused: trash" grep -q 'refused: trash$' <<<"$answer"
check "and removed nothing: G's user and home are there" bash -c "getent passwd $G_USER && test -d /home/$G_USER/public_html"
chmod 0700 "$TRASH"
t="$(journal_time)"
finished="$(drive finish-delete --id "$g_id" --reason 'The trash was fixed by hand')" || fail "the operator finishes G's delete"
echo "  finish-delete of G: $(printf '%s' "$finished" | field "['id']")"
check "G is gone from the list" gone_from_list "$G_USER"
check "G's user and group are gone" bash -c "! getent passwd $G_USER && ! getent group $G_USER"
check "G's home left the homes folder" test ! -e "/home/$G_USER"
check "G's ownership marker is gone" test ! -e "$STATE/owners/$g_id"
check "G's slice drop-in is gone" test ! -e "/etc/systemd/system/user-$g_uid.slice.d/50-sifruno-limits.conf"
check "the finish logged no recovery" not_logged "$t" "account=$g_id"
check "the trash remover empties G's home from the trash" wait_until 120 test ! -e "$TRASH/$g_id"
drive create --username "$H_USER" --domain "$H_USER.proof.test" --reason 'Every account unblocked' >/dev/null || fail "H is created after the finish"
check "H is active" is_state "$H_USER" active

echo
echo "## 7. A 200,000-file home: the delete answers at once, the trash drains, its UID is held back meanwhile"
# With the trash empty, I gets the lowest free ID, which a create would get
# again once I is deleted if the trash did not hold it back.
check "the trash is empty before I is created" wait_until 120 trash_empty
i="$(drive create --username "$I_USER" --domain "$I_USER.proof.test" --reason 'Large delete proof')" || fail "I is created"
i_id="$(printf '%s' "$i" | field "['id']")"
i_uid="$(printf '%s' "$i" | field "['uid']")"
python3 -I -c 'import os, sys
for d in range(200):
    folder = os.path.join(sys.argv[1], "bulk", str(d))
    os.makedirs(folder)
    for f in range(1000):
        open(os.path.join(folder, str(f)), "w").close()' "/home/$I_USER"
chown -R "$I_USER:$I_USER" "/home/$I_USER/bulk"
# A folder on another filesystem in the home: the remover never enters it,
# so I's entry stays in the trash (and holds I's UID) until it is unmounted.
install -d -o "$I_USER" -g "$I_USER" -m 0750 "/home/$I_USER/held"
mount -t tmpfs -o size=1m,mode=0750 tmpfs "/home/$I_USER/held"
check "I's home holds 200,000 files" test "$(files_in "/home/$I_USER")" -eq 200000
t="$(journal_time)"
started=$SECONDS
drive delete --id "$i_id" --revision "$(printf '%s' "$i" | field "['revision']")" --reason 'Large delete proof' >/dev/null || fail "I is deleted"
took=$((SECONDS - started))
left="$(files_in "$TRASH/$i_id")"
echo "  the delete of 200,000 files answered after $took s; $left of them were still in the trash then"
check "the delete answered within 30 s" test "$took" -le 30
check "I is gone from the list" gone_from_list "$I_USER"
check "I's home is in the trash, not in the homes folder" bash -c "test -d $TRASH/$i_id && test ! -e /home/$I_USER"
check "I's UID is the one a create would get without the trash" test "$(lowest_free_id)" = "$i_uid"
j="$(drive create --username "$J_USER" --domain "$J_USER.proof.test" --reason 'Created while the trash drains')" || fail "J is created while I's home is in the trash"
j_uid="$(printf '%s' "$j" | field "['uid']")"
echo "  I had UID $i_uid; J, created while I's home was in the trash, got $j_uid"
check "J did not get I's UID" test "$j_uid" != "$i_uid"
check "the trash drains I's 200,000 files" wait_until 300 no_files_in "$TRASH/$i_id"
check "the folder on another filesystem is left, logged by I's account ID" wait_until 30 cleanup_logged "$t" "account=$i_id step=\"empty the trash: a folder on another device or mount is left in it\""
check "no cleanup line names a file of I's home" bash -c "! journalctl -u $UNIT --since '$t' -o cat --no-pager | grep 'sifruno broker: cleanup:' | grep -qE 'bulk|held'"
umount "$TRASH/$i_id/held"
check "the broker starts again" start_broker
check "the trash remover empties I's home from the trash" wait_until 120 test ! -e "$TRASH/$i_id"

echo
echo "## 8. The root-only Go tests of the same native code"
if "$BIN/hostaccounts.test" -test.run 'RootOnly(RecoverCreateAdoptsUseraddHome|AbandonCreate|DeleteFinishesAfterUserdel|FinishDelete|PlanSkipsATrashedUID)' -test.v 2>&1 | sed 's/^/  /' | tee "$WORK/root-tests.log" | grep -E -- '^  (--- |ok|FAIL|PASS)'; then :; fi
for test in RecoverCreateAdoptsUseraddHome AbandonCreate DeleteFinishesAfterUserdel FinishDelete PlanSkipsATrashedUID; do
  check "TestRootOnly$test passed" grep -q -- "--- PASS: TestRootOnly$test " "$WORK/root-tests.log"
done
check "no root-only test failed" bash -c "! grep -q -- '--- FAIL' $WORK/root-tests.log"

echo
echo "## 9. Clean up"
# The tmpfs of section 7, wherever a failed check left it.
umount "/home/$I_USER/held" 2>/dev/null
umount "$TRASH/$i_id/held" 2>/dev/null
for user in "$A_USER" "$B_USER" "$D_USER" "$F_USER" "$H_USER" "$J_USER"; do
  acct="$(account "$user")"
  [ -n "$acct" ] || continue
  drive delete --id "$(printf '%s' "$acct" | field "['id']")" --revision "$(printf '%s' "$acct" | field "['revision']")" --reason 'Create recovery proof done' >/dev/null || fail "delete $user"
done
check "no account of this run is left" bash -c "! getent passwd $A_USER && ! getent passwd $B_USER && ! getent passwd $D_USER && ! getent passwd $F_USER && ! getent passwd $H_USER && ! getent passwd $J_USER"
check "the trash empties" wait_until 120 trash_empty

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
