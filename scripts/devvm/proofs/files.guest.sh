#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh files copies it in).
# Proves the file manager at the broker: the helper runs as the site's user
# in its slice, an upload lands owned by that user and counts against its
# quota, a link to /etc/shadow in the home cannot be read through it, an
# edit of index.php changes what the site serves, and a delete of a folder
# with links inside leaves the links' targets alone. Prints PASS/FAIL per
# check.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
HELPER=/usr/local/lib/sifruno/bin/sifruno-files
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="fil${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
HOME_DIR="/home/$SITE_USER"
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
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }
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
# refused CODE COMMAND...: the broker refused with this file error code.
refused() {
  local want="$1" out
  shift
  out="$("$@" 2>&1)" && return 1
  printf '%s\n' "$out" | grep -q "file operation failed: $want"
}
# not COMMAND...: the command failed.
not() { ! "$@"; }
# Used blocks (KiB) of the site user on the homes filesystem.
used_kib() { xfs_quota -x -c "quota -u -N -b $uid" /home 2>/dev/null | awk 'NR==1{print $2}'; }

work="$(mktemp -d /tmp/files-proof.XXXXXX)"
chown sifpanel "$work"
chmod 0700 "$work"
trap 'rm -rf -- "$work"' EXIT
as_panel() { install -o sifpanel -m 0600 /dev/stdin "$work/$1"; }

echo "# File manager at the broker: the helper as the site's user"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 systemd | paste -sd ' ')  SELinux $(getenforce)"
echo "# site user $SITE_USER, domain $DOMAIN"

echo
echo "## 1. The helper is where the release installs it, and the broker runs with the web operation"
install -d -o root -g root -m 0755 /usr/local/lib/sifruno /usr/local/lib/sifruno/bin
install -o root -g root -m 0755 "$BIN/sifruno-files" "$HELPER"
restorecon "$HELPER" 2>/dev/null
echo "  $(stat -c '%U:%G %a, %h link(s)' "$HELPER") $HELPER, SELinux $(stat -c %C "$HELPER" 2>&1)"
check "the helper is root's, 0755, one link" bash -c "[ \"\$(stat -c '%U:%G %a %h' $HELPER)\" = 'root:root 755 1' ]"
check "the helper refuses to run as root" bash -c "! echo '{\"op\":\"list\",\"path\":\"\"}' | (cd /tmp && $HELPER)"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"

echo
echo "## 2. A live site with the smallest quota, 64 MiB"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Files proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | field "['id']")"
uid="$(printf '%s' "$created" | field "['uid']")"
rev="$(printf '%s' "$created" | revision)"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 64 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | revision)"
check "the account is live with UID $uid" test -n "$uid"

echo
echo "## 3. The helper runs as the site's user, in its slice, with no new privileges"
mkfifo "$work/slow"
chown sifpanel "$work/slow"
# The upload's bytes arrive after a pause, so the helper waits for them and
# can be looked at while it runs.
(sleep 8; head -c 1048576 /dev/urandom) > "$work/slow" &
writer=$!
drive files-upload --id "$id" --file-path slow.bin --from "$work/slow" --size 1048576 > "$work/slow.json" 2>&1 &
upload=$!
pid=""
for _ in $(seq 1 60); do
  pid="$(pgrep -u "$SITE_USER" -x sifruno-files | head -n 1)"
  [ -n "$pid" ] && break
  sleep 0.2
done
if [ -n "$pid" ]; then
  cgroup="$(cut -d: -f3- "/proc/$pid/cgroup")"
  unit="${cgroup##*/}"
  echo "  pid $pid: user $(ps -o user= -p "$pid"), uid $(ps -o uid= -p "$pid" | tr -d ' '), groups $(ps -o supgrp= -p "$pid")"
  echo "  exe $(readlink "/proc/$pid/exe"), cwd $(readlink "/proc/$pid/cwd")"
  echo "  cgroup $cgroup"
  echo "  $(awk '/^(NoNewPrivs|CapEff|Seccomp):/{printf "%s %s  ", $1, $2}' "/proc/$pid/status")"
  echo "  unit: $(systemctl show "$unit" -p User -p Slice -p NoNewPrivileges -p TasksMax -p RuntimeMaxUSec -p Description 2>&1 | paste -sd ' ')"
  check "it runs as $SITE_USER" test "$(ps -o user= -p "$pid" | tr -d ' ')" = "$SITE_USER"
  check "it runs from the release path" test "$(readlink "/proc/$pid/exe")" = "$HELPER"
  check "it starts in the home, $HOME_DIR" test "$(readlink "/proc/$pid/cwd")" = "$HOME_DIR"
  check "it is in user-$uid.slice, in its own sifruno-site unit" bash -c "printf '%s' '$cgroup' | grep -Eq '/user.slice/user-$uid.slice/sifruno-site-$uid-[0-9a-f]{16}.service$'"
  check "NoNewPrivs is set and it holds no capability" bash -c "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/$pid/status && grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/$pid/status"
else
  fail "the helper was seen running"
fi
wait "$writer"
wait "$upload"
check "the paused upload finished" bash -c "grep -q '\"name\": \"slow.bin\"' $work/slow.json"
check "no helper is left running" bash -c "! pgrep -u $SITE_USER -x sifruno-files"

echo
echo "## 4. An upload lands owned by the site's user and counts against its quota"
before="$(used_kib)"
head -c $((20 * 1024 * 1024)) /dev/urandom | as_panel big.bin
drive files-upload --id "$id" --file-path public_html/big.bin --from "$work/big.bin" >/dev/null || fail "the broker uploads 20 MiB"
after="$(used_kib)"
echo "  $(stat -c '%U:%G %a %s bytes' "$HOME_DIR/public_html/big.bin" 2>&1) public_html/big.bin; quota use ${before:-?} KiB -> ${after:-?} KiB"
check "the file is the site user's, 0644" bash -c "[ \"\$(stat -c '%U:%G %a' $HOME_DIR/public_html/big.bin)\" = '$SITE_USER:$SITE_USER 644' ]"
check "the bytes arrived whole" cmp -s "$work/big.bin" "$HOME_DIR/public_html/big.bin"
check "the account's quota use grew by at least 20 MiB" test "$(( ${after:-0} - ${before:-0} ))" -ge 20480
head -c $((50 * 1024 * 1024)) /dev/urandom | as_panel huge.bin
check "50 MiB more is refused at the quota" refused quota drive files-upload --id "$id" --file-path public_html/huge.bin --from "$work/huge.bin"
check "the refused upload left nothing behind" bash -c "[ ! -e $HOME_DIR/public_html/huge.bin ] && [ -z \"\$(find $HOME_DIR -name '.sifruno-*.tmp' -print -quit)\" ]"
echo "  quota use after the refusal: $(used_kib) KiB"
drive files-delete --id "$id" --file-path public_html/big.bin >/dev/null || fail "the big file is deleted"
rm -f -- "$work/big.bin" "$work/huge.bin"

echo
echo "## 5. A link to /etc/shadow cannot be read through the file manager"
runuser -u "$SITE_USER" -- ln -s /etc/shadow "$HOME_DIR/public_html/shadow.txt"
runuser -u "$SITE_USER" -- ln -s /etc "$HOME_DIR/public_html/etc"
links_listed() {
  drive files-list --id "$id" --file-path public_html |
    python3 -c "import json,sys; e={x['name']:x['type'] for x in json.load(sys.stdin)['entries']}; sys.exit(0 if e.get('shadow.txt')=='link' and e.get('etc')=='link' else 1)"
}
check "the links are listed as links" links_listed
check "reading the link is refused" refused is_link drive files-read --id "$id" --file-path public_html/shadow.txt
check "downloading the link is refused" refused is_link drive files-download --id "$id" --file-path public_html/shadow.txt --to "$work/shadow.out"
check "reading through a linked folder is refused" refused is_link drive files-read --id "$id" --file-path public_html/etc/shadow
printf x | as_panel x.txt
check "writing through the link is refused" refused is_link drive files-write --id "$id" --file-path public_html/shadow.txt --content-file "$work/x.txt"
check "a path out of the home is refused before it is sent" not drive files-read --id "$id" --file-path ../../etc/shadow
check "nothing of /etc/shadow reached the proof" bash -c "[ ! -e $work/shadow.out ] && ! grep -rqs '^root:' $work"
check "the link is still a link to /etc/shadow" test "$(readlink "$HOME_DIR/public_html/shadow.txt")" = /etc/shadow

echo
echo "## 6. An edit of index.php changes what the site serves"
printf '<?php echo "files proof one %s";\n' "$RUNID" | as_panel one.php
drive files-write --id "$id" --file-path public_html/index.php --content-file "$work/one.php" >/dev/null || fail "the broker writes index.php"
check "the site serves the first text" wait_for / 200 "files proof one $RUNID"
version="$(drive files-read --id "$id" --file-path public_html/index.php | field "['file']['version']")"
printf '<?php echo "files proof two %s";\n' "$RUNID" | as_panel two.php
drive files-write --id "$id" --file-path public_html/index.php --content-file "$work/two.php" --file-version "$version" >/dev/null || fail "the broker saves the edit at its version"
check "the site serves the edited text" wait_for / 200 "files proof two $RUNID"
check "a save at the old version is refused as changed" refused changed drive files-write --id "$id" --file-path public_html/index.php --content-file "$work/one.php" --file-version "$version"
check "the site still serves the edited text" wait_for / 200 "files proof two $RUNID"
echo "  $(stat -c '%U:%G %a' "$HOME_DIR/public_html/index.php") public_html/index.php"

echo
echo "## 7. Deleting a folder with links inside leaves the links' targets alone"
runuser -u "$SITE_USER" -- mkdir -p "$HOME_DIR/keep" "$HOME_DIR/public_html/old/sub"
runuser -u "$SITE_USER" -- sh -c "printf 'keep me\n' > '$HOME_DIR/keep/data.txt' && printf x > '$HOME_DIR/public_html/old/sub/a.txt'"
runuser -u "$SITE_USER" -- ln -s "$HOME_DIR/keep" "$HOME_DIR/public_html/old/keep-folder"
runuser -u "$SITE_USER" -- ln -s "$HOME_DIR/keep/data.txt" "$HOME_DIR/public_html/old/sub/keep-file"
runuser -u "$SITE_USER" -- ln -s /etc "$HOME_DIR/public_html/old/etc"
hostname_sum="$(sha256sum /etc/hostname)"
drive files-delete --id "$id" --file-path public_html/old >/dev/null || fail "the broker deletes the folder"
check "the folder is gone" test ! -e "$HOME_DIR/public_html/old"
check "the linked folder and its file are untouched" bash -c "[ \"\$(cat $HOME_DIR/keep/data.txt)\" = 'keep me' ]"
check "/etc is untouched" bash -c "[ \"\$(sha256sum /etc/hostname)\" = '$hostname_sum' ]"

echo
echo "## 8. A suspended site's files can be read, not changed"
suspended="$(drive state --id "$id" --revision "$rev" --state suspended --reason 'Files proof suspend')" || fail "the broker suspends the account"
rev="$(printf '%s' "$suspended" | revision)"
check "the files list while suspended" drive files-list --id "$id" --file-path public_html
check "a new folder is refused while suspended" not drive files-mkdir --id "$id" --file-path public_html/new
resumed="$(drive state --id "$id" --revision "$rev" --state active --reason 'Files proof resume')" || fail "the broker resumes the account"
rev="$(printf '%s' "$resumed" | revision)"
check "a new folder is made once resumed" drive files-mkdir --id "$id" --file-path public_html/new
check "the new folder is the site user's, 0755" bash -c "[ \"\$(stat -c '%U %a' $HOME_DIR/public_html/new)\" = '$SITE_USER 755' ]"

echo
echo "## 9. Nothing of this is in the account's journal, and the delete still works"
at_revision() {
  drive list | python3 -c "import json,sys; a=[x for x in json.load(sys.stdin) if x['id']=='$id']; sys.exit(0 if a and a[0]['revision']==$rev else 1)"
}
check "the account's revision moved only for the state changes" at_revision
drive delete --id "$id" --revision "$rev" --reason 'Remove the files proof site' >/dev/null || fail "the broker deletes the account"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
