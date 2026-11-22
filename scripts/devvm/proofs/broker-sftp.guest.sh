#!/usr/bin/env bash
# Proof 2 (docs/PRODUCT-PLAN.md, Phase 0 item 8), guest side. Runs as root in
# the dev VM after provision.sh. It starts the real root broker, drives it as
# the controller user, and checks the result from outside the broker with
# ordinary tools: getent, stat, sftp, ssh.
#
# Every check prints PASS or FAIL. The exit status is the number of FAILs.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
WORK=/root/sifruno-proof2
EXTRA_ACCOUNTS="${EXTRA_ACCOUNTS:-0}"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { # check "description" command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
refuse() { # refuse "description" command...   passes when the command fails
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi
}
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'; }
sftp_as() { # sftp_as user keyfile batchfile
  sftp -q -b "$3" -i "$2" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=20 "$1@127.0.0.1"
}

echo "# Proof 2: broker creates a real Linux user that can sign in over SFTP"
echo "# $(date -u +%FT%TZ)  $(cat /etc/redhat-release)  kernel $(uname -r)  SELinux $(getenforce)"
echo "# $(rpm -q openssh-server shadow-utils | tr '\n' ' ')"

mkdir -p "$WORK"
chmod 700 "$WORK"
for name in one two rogue; do
  [ -f "$WORK/key_$name" ] || ssh-keygen -q -t ed25519 -N '' -C "proof-$name" -f "$WORK/key_$name"
done
chmod 644 "$WORK"/key_*.pub
# The controller reads the public keys it submits.
install -d -o sifpanel -g sifpanel -m 0700 /var/lib/sifpanel/keys
install -o sifpanel -g sifpanel -m 0600 "$WORK"/key_one.pub "$WORK"/key_two.pub /var/lib/sifpanel/keys/

echo
echo "## Host policy and broker start"
check "broker host policy report says supported" "$BIN/hostbroker" --check-host
controller_uid="$(id -u sifpanel)"
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$controller_uid"
for _ in $(seq 1 30); do [ -S "$SOCKET" ] && break; sleep 1; done
check "broker is running and its socket exists" test -S "$SOCKET"
check "socket is owned by the controller with mode 0600" test "$(stat -c '%U %a' "$SOCKET")" = "sifpanel 600"
refuse "root itself is not admitted on the socket" "$BIN/brokerdrive" --socket "$SOCKET" list
check "controller sees an available broker" bash -c "runuser -u sifpanel -- $BIN/brokerdrive --socket $SOCKET capability | grep -q '\"available\": true'"

echo
echo "## Create a real user"
created="$(drive create --username proofone --domain proofone.test --reason 'Proof 2 first account')" || fail "create proofone"
id1="$(printf '%s' "$created" | field '["id"]')"
uid1="$(printf '%s' "$created" | field '["uid"]')"
echo "account id $id1, uid $uid1"
check "passwd entry exists with the nologin shell" bash -c "getent passwd proofone | grep -q ':/home/proofone:/usr/sbin/nologin\$'"
check "UID is a regular user ID in 20000-60000" test "$uid1" -ge 20000 -a "$uid1" -le 60000
check "private primary group exists and has no members" bash -c "getent group proofone | grep -q '^proofone:x:$uid1:\$'"
check "password is locked" bash -c "passwd --status proofone | awk '{print \$2}' | grep -Eq '^(L|LK)\$'"
check "subordinate UID range was allocated" grep -q '^proofone:[0-9]*:65536$' /etc/subuid
check "subordinate GID range was allocated" grep -q '^proofone:[0-9]*:65536$' /etc/subgid
check "home is owned by the account with mode 0750" test "$(stat -c '%U:%G %a' /home/proofone)" = "proofone:proofone 750"
check "public_html is owned by the account with mode 0750" test "$(stat -c '%U:%G %a' /home/proofone/public_html)" = "proofone:proofone 750"
grep '^proofone:' /etc/subuid /etc/subgid | sed 's/^/  /'

echo
echo "## SFTP key through the broker"
refuse "no key yet: SFTP sign-in is refused" sftp_as proofone "$WORK/key_one" /dev/null
keys="$(drive ssh-keys --id "$id1" --revision 1 --key-file /var/lib/sifpanel/keys/key_one.pub --reason 'Proof 2 add key')" || fail "set ssh key"
check "broker reports one key and revision 2" bash -c "printf '%s' '$keys' | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"account\"][\"revision\"]==2 and len(d[\"keys\"])==1 else 1)'"
keyfile=/etc/sifruno/ssh/authorized_keys/proofone
check "key file is root-owned, group = account, mode 0640" test "$(stat -c '%U:%G %a' "$keyfile")" = "root:proofone 640"
check "every key line carries the SFTP-only options" bash -c "grep -v '^#' $keyfile | grep -vq '^restrict,command=\"internal-sftp\" ssh-' && exit 1 || exit 0"
check "fingerprint reported by the broker matches ssh-keygen" bash -c "printf '%s' '$keys' | grep -q \"\$(ssh-keygen -lf $WORK/key_one.pub | awk '{print \$2}')\""
echo "proof file $(date -u +%s)" > "$WORK/upload.txt"
printf 'put %s public_html/proof.txt\nls -l public_html\n' "$WORK/upload.txt" > "$WORK/batch_put"
check "SFTP sign-in with the key works and can upload into public_html" sftp_as proofone "$WORK/key_one" "$WORK/batch_put"
check "uploaded file is owned by the account" test "$(stat -c '%U' /home/proofone/public_html/proof.txt 2>/dev/null)" = "proofone"
refuse "a different key is refused" sftp_as proofone "$WORK/key_two" /dev/null

echo
echo "## What the account must not be able to do"
refuse "no shell: a remote command does not run" bash -c "ssh_out=\$(ssh -i $WORK/key_one -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$WORK/known_hosts proofone@127.0.0.1 'id; echo SHELL-RAN' 2>&1); printf '%s' \"\$ssh_out\" | grep -q 'SHELL-RAN\|uid='"
refuse "no port forwarding to the local database port" bash -c "
  ssh -i $WORK/key_one -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$WORK/known_hosts -o ExitOnForwardFailure=yes -N -L 127.0.0.1:13306:127.0.0.1:3306 proofone@127.0.0.1 &
  pid=\$!; sleep 6; ok=1
  timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/13306 && head -c 5 <&3 | grep -q .' && ok=0
  kill \$pid 2>/dev/null; exit \$ok"
# The account plants its own authorized_keys in its home; sshd must ignore it.
mkdir -p "$WORK/plant" && cp "$WORK/key_rogue.pub" "$WORK/plant/authorized_keys"
printf 'mkdir .ssh\nchmod 700 .ssh\nput %s .ssh/authorized_keys\nchmod 600 .ssh/authorized_keys\n' "$WORK/plant/authorized_keys" > "$WORK/batch_plant"
sftp_as proofone "$WORK/key_one" "$WORK/batch_plant" >/dev/null 2>&1
check "the account did write its own ~/.ssh/authorized_keys" test -s /home/proofone/.ssh/authorized_keys
refuse "a key the account added itself does not grant sign-in" sftp_as proofone "$WORK/key_rogue" /dev/null

echo
echo "## A second account is separate"
created2="$(drive create --username prooftwo --domain prooftwo.test --reason 'Proof 2 second account')" || fail "create prooftwo"
id2="$(printf '%s' "$created2" | field '["id"]')"
drive ssh-keys --id "$id2" --revision 1 --key-file /var/lib/sifpanel/keys/key_two.pub --reason 'Proof 2 add key' >/dev/null || fail "set prooftwo key"
printf 'ls /home/proofone\n' > "$WORK/batch_peek"
printf 'get /home/proofone/public_html/proof.txt %s/stolen.txt\n' "$WORK" > "$WORK/batch_steal"
printf 'get /etc/sifruno/ssh/authorized_keys/proofone %s/stolen_keys\n' "$WORK" > "$WORK/batch_keys"
check "second account signs in with its own key" sftp_as prooftwo "$WORK/key_two" /dev/null
refuse "second account cannot list the first account's home" sftp_as prooftwo "$WORK/key_two" "$WORK/batch_peek"
refuse "second account cannot read the first account's file" sftp_as prooftwo "$WORK/key_two" "$WORK/batch_steal"
refuse "second account cannot read the first account's key file" sftp_as prooftwo "$WORK/key_two" "$WORK/batch_keys"
refuse "first account's key does not open the second account" sftp_as prooftwo "$WORK/key_one" /dev/null

echo
echo "## Suspend, resume, remove keys"
drive state --id "$id1" --revision 2 --state suspended --reason 'Proof 2 suspend' >/dev/null || fail "suspend"
refuse "suspended account cannot sign in" sftp_as proofone "$WORK/key_one" /dev/null
drive state --id "$id1" --revision 3 --state active --reason 'Proof 2 resume' >/dev/null || fail "resume"
check "resumed account signs in again" sftp_as proofone "$WORK/key_one" /dev/null
drive ssh-keys --id "$id1" --revision 4 --reason 'Proof 2 remove keys' >/dev/null || fail "remove keys"
check "key file is gone after removing all keys" test ! -e "$keyfile"
refuse "sign-in is refused after removing all keys" sftp_as proofone "$WORK/key_one" /dev/null

if [ "$EXTRA_ACCOUNTS" -gt 0 ]; then
  echo
  echo "## More than 100 accounts"
  started=$(date +%s)
  made=0
  for i in $(seq 1 "$EXTRA_ACCOUNTS"); do
    name=$(printf 'bulk%04d' "$i")
    drive create --username "$name" --domain "$name.test" --reason 'Proof 2 bulk' >/dev/null 2>&1 && made=$((made + 1))
  done
  elapsed=$(( $(date +%s) - started ))
  echo "created $made of $EXTRA_ACCOUNTS accounts in ${elapsed}s"
  check "all bulk accounts were created" test "$made" -eq "$EXTRA_ACCOUNTS"
  t0=$(date +%s%N)
  total="$(drive list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
  t1=$(date +%s%N)
  echo "list returned $total accounts in $(( (t1 - t0) / 1000000 )) ms"
  check "inventory holds more than 100 accounts" test "$total" -gt 100
  check "every listed account is active" bash -c "runuser -u sifpanel -- $BIN/brokerdrive --socket $SOCKET list | python3 -c 'import json,sys; sys.exit(0 if all(a[\"state\"]==\"active\" for a in json.load(sys.stdin)) else 1)'"
fi

echo
echo "## Delete"
drive delete --id "$id2" --revision 2 --reason 'Proof 2 delete' >/dev/null || fail "delete prooftwo"
refuse "deleted account has no passwd entry" getent passwd prooftwo
check "deleted account's home is gone" test ! -e /home/prooftwo
check "deleted account's key file is gone" test ! -e /etc/sifruno/ssh/authorized_keys/prooftwo
check "deleted account's mail spool is gone" test ! -e /var/spool/mail/prooftwo
refuse "deleted account's subordinate ranges are gone" grep -q '^prooftwo:' /etc/subuid /etc/subgid
refuse "deleted account cannot sign in" sftp_as prooftwo "$WORK/key_two" /dev/null

echo
echo "## Root-only Go tests of the key file code"
if "$BIN/hostaccounts.test" -test.run 'RootOnly' -test.v 2>&1 | sed 's/^/  /' | tee "$WORK/root-tests.log" | grep -q -- '--- PASS: TestRootOnlySSHKeyFileLifecycle'; then
  pass "TestRootOnlySSHKeyFileLifecycle passed as root"
else
  fail "TestRootOnlySSHKeyFileLifecycle passed as root"
fi

echo
echo "## SELinux"
denials="$(ausearch -m avc -ts recent 2>/dev/null | grep -c 'denied' || true)"
echo "AVC denials in the last 10 minutes: ${denials:-0}"
ausearch -m avc -ts recent 2>/dev/null | grep denied | sed 's/^/  /' | head -5

systemctl stop sifruno-broker-proof 2>/dev/null
echo
echo "# Result: $fails failed"
exit "$fails"
