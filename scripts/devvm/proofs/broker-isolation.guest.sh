#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh broker-isolation copies it in).
# Proves that a tenant who renames its own public_html affects only its own
# account: another account still changes PHP, is suspended and resumed; the
# operator can suspend the tenant (403), use the tenant's new public_html,
# resume it, and delete it. A tenant's running processes end when it is
# suspended or deleted, another account's do not, and a delete with a
# process running succeeds. Prints PASS/FAIL per check.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
A_USER="tna${RUNID}"
B_USER="tnb${RUNID}"
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
# A change answers either the account or {"account": ...}.
revision() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('account', d)['revision'])"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1$2"; }
# The first request after a change starts lsphp cold; under emulation that
# can take minutes, so wait for the answer the change should give.
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
listed() { # listed ID PYTHON-CONDITION-ON-a
  drive list | python3 -c "import json,sys; a=[x for x in json.load(sys.stdin) if x['id']=='$1']; sys.exit(0 if a and ($2) else 1)"
}
# The tenant's own actions, as its user without PAM: a suspended account's
# expiry would refuse a PAM login, and the tenant's files do not care.
as_tenant() { # as_tenant USER COMMAND
  local uid
  uid="$(id -u "$1")"
  setpriv --reuid="$uid" --regid="$uid" --clear-groups -- sh -c "cd /home/$1 && $2"
}
ols_lines() { "$LSWS/bin/openlitespeed" -t 2>&1 | sed -E 's/^[0-9-]+ [0-9:.]+ //; s/\[[0-9]+\] //' | grep -E "^\[(ERROR|WARN)\].*$1" | sort -u; }
SFTP_SERVER=/usr/libexec/openssh/sftp-server
# Long-running processes of a tenant: a sleep, and an SFTP server reading a
# pipe as an open SFTP session runs it. Started without PAM, as as_tenant,
# and handed to init (setsid -f) as a login's or a worker's would be, so an
# ended one is reaped at once and not left as a zombie of this script.
tenant_processes() { # tenant_processes USER
  local uid
  uid="$(id -u "$1")"
  setsid -f setpriv --reuid="$uid" --regid="$uid" --clear-groups -- sleep 3600 </dev/null >/dev/null 2>&1
  if [ -x "$SFTP_SERVER" ]; then
    setsid -f setpriv --reuid="$uid" --regid="$uid" --clear-groups -- sh -c "sleep 3600 | $SFTP_SERVER" </dev/null >/dev/null 2>&1
  fi
  sleep 1
}
# tenant_running UID: a sleep runs as UID, and an SFTP server when installed.
tenant_running() { pgrep -u "$1" -x sleep >/dev/null && { [ ! -x "$SFTP_SERVER" ] || pgrep -u "$1" -x sftp-server >/dev/null; }; }

echo "# A tenant's own folder change stays with its own account"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 | paste -sd ' ')  SELinux $(getenforce)"
echo "# tenant A $A_USER ($A_DOMAIN), account B $B_USER ($B_DOMAIN)"

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
# B changes to a second PHP version; the installer puts in 8.3 only.
if [ ! -x "$LSWS/lsphp84/bin/lsphp" ]; then
  dnf -y -q install lsphp84 lsphp84-common >/dev/null 2>&1
fi
check "LSPHP 8.4 is installed for B's version change" test -x "$LSWS/lsphp84/bin/lsphp"

echo
echo "## 2. Two accounts, both live on PHP 8.3"
a="$(drive create --username "$A_USER" --domain "$A_DOMAIN" --reason 'Isolation proof, tenant A')" || fail "broker creates account A"
b="$(drive create --username "$B_USER" --domain "$B_DOMAIN" --reason 'Isolation proof, account B')" || fail "broker creates account B"
a_id="$(printf '%s' "$a" | field '["id"]')"
b_id="$(printf '%s' "$b" | field '["id"]')"
a_rev="$(printf '%s' "$a" | revision)"
b_rev="$(printf '%s' "$b" | revision)"
as_tenant "$A_USER" "printf '%s\n' '<?php echo \"site A on php \", PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;' > public_html/index.php"
as_tenant "$B_USER" "printf '%s\n' '<?php echo \"site B on php \", PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;' > public_html/index.php"
a_live="$(drive web --id "$a_id" --revision "$a_rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "A goes live"
b_live="$(drive web --id "$b_id" --revision "$b_rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "B goes live"
a_rev="$(printf '%s' "$a_live" | revision)"
b_rev="$(printf '%s' "$b_live" | revision)"
check "A serves on PHP 8.3" wait_for "$A_DOMAIN" / 200 'site A on php 8.3'
check "B serves on PHP 8.3" wait_for "$B_DOMAIN" / 200 'site B on php 8.3'
a_vhost="$LSWS/conf/vhosts/sifruno-u${a_id:0:31}"

echo
echo "## 3. Tenant A renames its public_html"
as_tenant "$A_USER" "mv public_html public_gone"
check "public_html is gone from A's home" test ! -e "/home/$A_USER/public_html"
check "the list marks A's site folder changed, and A stays active" listed "$a_id" "a[0]['state'] == 'active' and a[0].get('site_folder_changed') is True and a[0]['revision'] == $a_rev"
check "the list does not mark B" listed "$b_id" "a[0]['state'] == 'active' and not a[0].get('site_folder_changed')"
check "the account service stays available" bash -c "runuser -u sifpanel -- $BIN/brokerdrive --socket $SOCKET capability | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)[\"available\"] else 1)'"
echo "  openlitespeed -t on A's vhost now:"
ols_lines "sifruno-u${a_id:0:31}" | sed 's/^/    /'
answer="$(drive web --id "$a_id" --revision "$a_rev" --php 8.4 --quota-mib 200 --reason 'PHP 8.4' 2>&1 >/dev/null)"
echo "  A's own PHP change: $answer"
check "A's own PHP change is refused as a conflict" grep -q 'conflict' <<<"$answer"
check "and A's revision did not move" listed "$a_id" "a[0]['revision'] == $a_rev"

echo
echo "## 4. B carries on"
changed="$(drive web --id "$b_id" --revision "$b_rev" --php 8.4 --quota-mib 200 --reason 'PHP 8.4')" || fail "B changes PHP while A's folder is changed"
b_rev="$(printf '%s' "$changed" | revision)"
check "B serves on PHP 8.4" wait_for "$B_DOMAIN" / 200 'site B on php 8.4'
# A render that rewrites A's vhost, as the first one after an upgrade that
# changes the rendered form does: OpenLiteSpeed warns for A, and B's change
# must still pass.
printf '# written by an older render\n' >>"$a_vhost/vhconf.conf"
suspended="$(drive state --id "$b_id" --revision "$b_rev" --state suspended --reason 'Unpaid')" || fail "B is suspended while A's folder is changed"
b_rev="$(printf '%s' "$suspended" | revision)"
check "B's suspend rewrote A's vhost (the older render is gone)" bash -c "! grep -q 'older render' $a_vhost/vhconf.conf"
check "B answers 403" wait_for "$B_DOMAIN" / 403
resumed="$(drive state --id "$b_id" --revision "$b_rev" --state active --reason 'Paid')" || fail "B is resumed while A's folder is changed"
b_rev="$(printf '%s' "$resumed" | revision)"
check "B serves on PHP 8.4 again" wait_for "$B_DOMAIN" / 200 'site B on php 8.4'
c_user="tnc${RUNID}"
c="$(drive create --username "$c_user" --domain "${c_user}.proof.test" --reason 'Isolation proof, account C')" || fail "a new account can be created"
c_id="$(printf '%s' "$c" | field '["id"]')"
drive delete --id "$c_id" --revision "$(printf '%s' "$c" | revision)" --reason 'Remove C' >/dev/null || fail "the new account can be deleted"
check "account C is gone" bash -c "! getent passwd $c_user"
check "A is still active and marked, never recovery_required" listed "$a_id" "a[0]['state'] == 'active' and a[0].get('site_folder_changed') is True"

echo
echo "## 5. The operator suspends A"
a_uid="$(id -u "$A_USER")"
b_uid="$(id -u "$B_USER")"
tenant_processes "$A_USER"
tenant_processes "$B_USER"
check "A has a sleep and an SFTP server running" tenant_running "$a_uid"
check "B has a sleep and an SFTP server running" tenant_running "$b_uid"
held="$(drive state --id "$a_id" --revision "$a_rev" --state suspended --reason 'Site folder changed')" || fail "the operator suspends A"
a_rev="$(printf '%s' "$held" | revision)"
echo "  processes of A after the suspend: $(pgrep -u "$a_uid" -l | paste -sd ' ')"
check "the suspend ended every process of A" bash -c "! pgrep -u $a_uid"
check "B's processes still run" tenant_running "$b_uid"
check "A answers 403" wait_for "$A_DOMAIN" / 403
check "A's suspended vhost names no path in /home" bash -c "! grep -q '/home' $a_vhost/vhconf.conf"
again="$(drive state --id "$a_id" --revision "$a_rev" --state suspended --reason 'Apply again')" || fail "the operator applies A's suspension again"
new_rev="$(printf '%s' "$again" | revision)"
check "applying it again is a recorded change (revision moved from $a_rev)" test "${new_rev:-0}" -gt "$a_rev"
a_rev="${new_rev:-$a_rev}"
answer="$(drive state --id "$a_id" --revision "$a_rev" --state active --reason 'Resume' 2>&1 >/dev/null)"
echo "  resume while public_html is gone: $answer"
check "a resume while A's public_html is gone ends rejected" grep -q 'rejected' <<<"$answer"
check "and A still answers 403" test "$(code "$A_DOMAIN" /)" = 403

echo
echo "## 6. Recovery: the operator uses A's new public_html"
as_tenant "$A_USER" "ln -s /etc public_html"
answer="$(drive public-html --id "$a_id" --revision "$a_rev" --reason 'Use the new folder' 2>&1 >/dev/null)"
echo "  with public_html a link to /etc: $answer"
check "a public_html that is a link is refused" grep -q 'conflict' <<<"$answer"
check "the link's target gained no ACL for the web server" bash -c "! getfacl -n --omit-header /etc 2>/dev/null | grep -q 'user:$ols_uid:'"
as_tenant "$A_USER" "rm public_html && mkdir -m 0755 public_html && printf 'new folder for A\n' > public_html/index.html"
adopted="$(drive public-html --id "$a_id" --revision "$a_rev" --reason 'Use the new folder')" || fail "the operator uses A's new public_html"
new_rev="$(printf '%s' "$adopted" | revision)"
check "it is a recorded change (revision moved from $a_rev)" test "${new_rev:-0}" -gt "$a_rev"
a_rev="${new_rev:-$a_rev}"
check "the list no longer marks A, still suspended" listed "$a_id" "a[0]['state'] == 'suspended' and not a[0].get('site_folder_changed')"
check "the new public_html has mode 0750" test "$(stat -c %a "/home/$A_USER/public_html")" = 750
check "the web server may read it (ACL u:$ols_uid:r-x)" bash -c "getfacl -n --omit-header /home/$A_USER/public_html | grep -qx 'user:$ols_uid:r-x'"
resumed="$(drive state --id "$a_id" --revision "$a_rev" --state active --reason 'Folder fixed')" || fail "A is resumed"
a_rev="$(printf '%s' "$resumed" | revision)"
check "A serves its new folder" wait_for "$A_DOMAIN" /index.html 200 'new folder for A'
if quota="$(drive web --id "$a_id" --revision "$a_rev" --php 8.3 --quota-mib 300 --reason 'Larger quota')"; then
  pass "A's own web changes work again"
  a_rev="$(printf '%s' "$quota" | revision)"
else
  fail "A's own web changes work again"
fi

echo
echo "## 7. Delete, after the tenant changed its home's mode, with its processes running"
as_tenant "$A_USER" "chmod 0700 /home/$A_USER"
check "the list marks A's folder changed again" listed "$a_id" "a[0].get('site_folder_changed') is True"
tenant_processes "$A_USER"
check "A, active again, has a sleep and an SFTP server running" tenant_running "$a_uid"
drive delete --id "$a_id" --revision "$a_rev" --reason 'Remove tenant A' >/dev/null || fail "the operator deletes A"
check "A's Linux user is gone" bash -c "! getent passwd $A_USER"
check "no process runs as A's UID" bash -c "! pgrep -u $a_uid"
check "A's home is gone" test ! -e "/home/$A_USER"
check "A's vhost config is gone" test ! -e "$a_vhost/vhconf.conf"
check "B still serves" test "$(code "$B_DOMAIN" /)" = 200
check "B's processes still run" tenant_running "$b_uid"
if quota="$(drive web --id "$b_id" --revision "$b_rev" --php 8.4 --quota-mib 300 --reason 'Larger quota')"; then
  pass "B can still change after A's delete"
  b_rev="$(printf '%s' "$quota" | revision)"
else
  fail "B can still change after A's delete"
fi
drive delete --id "$b_id" --revision "$b_rev" --reason 'Remove account B' >/dev/null || fail "the operator deletes B, its processes running"
check "B's Linux user is gone" bash -c "! getent passwd $B_USER"
check "no process runs as B's UID" bash -c "! pgrep -u $b_uid"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws
config_status=0
"$LSWS/bin/openlitespeed" -t >/dev/null 2>&1 || config_status=$?
check "openlitespeed -t reports no error afterwards" test "$config_status" -ne 2

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
