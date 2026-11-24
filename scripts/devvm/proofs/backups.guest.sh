#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh backups copies it in).
# Proves website backups with restic, kept off the server, and the restore
# drill, through the broker's own operations: an SFTP storage user on this
# VM stands in for the storage server, a WordPress site is backed up,
# broken (files deleted, a table dropped), restored, and serves again; a
# 1 GiB sparse file in the site comes back sparse; the repository password
# is shown until it is confirmed saved, then never again; the drill passes;
# no password is in any process's arguments. Prints PASS/FAIL per check,
# and SKIP for a part this broker state cannot show.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
RESTIC=/usr/local/lib/sifruno/restic
RESTIC_VERSION=0.20.0
RESTIC_BZ2_SHA256=0ccd9fa7885074a24603b051e01bf9bd8b5e45d6a1791e9d9887e9e9372107f7
RESTIC_SHA256=c109579d3a1a4d26094bef5400ac5645fceb1043414c05f51b8fb48272001c72
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="bk${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
DB="${SITE_USER}_wp"
TITLE="Sifruno backup proof ${RUNID}"
# The storage user's home is outside /home, which belongs to the broker.
STORE_USER=sifbackup
STORE_HOME=/srv/sifruno-backup-target
REPO="$STORE_HOME/restic-$RUNID"
WORK="$(mktemp -d /root/backups-proof.XXXXXX)"
# What the panel holds lives in its own home, where brokerdrive (as
# sifpanel) can read it.
PANEL="/var/lib/sifpanel/backups-proof-$RUNID"
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
page() { curl -s -H "Host: $DOMAIN" "http://127.0.0.1$1"; }
sql() { mysql --protocol=socket -uroot -N -e "$1"; }
# Random one-line secrets; they live only in files and are never printed.
secret() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20; }
# Sample every process's arguments in the background until stopped.
sample_start() { ( while :; do ps -eo args >> "$WORK/ps-samples.txt"; echo '--' >> "$WORK/ps-samples.txt"; sleep 0.5; done ) & sampler=$!; }
sample_stop() { kill "$sampler" 2>/dev/null; wait "$sampler" 2>/dev/null; }

echo "# Website backups with restic over SFTP, restore of files and database, restore drill"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed mariadb-server openssh-server | paste -sd ' ')"
echo "# site user $SITE_USER, domain $DOMAIN, storage $STORE_USER@127.0.0.1:$REPO"

echo
echo "## 1. restic $RESTIC_VERSION is installed and pinned, and the tools the broker runs are in place"
if [ ! -f "$RESTIC" ]; then
  # A VM provisioned before restic joined the installer: install it the way
  # the installer does, both checksums checked.
  echo "  restic is missing; installing it as the installer's step_restic does"
  curl -fsSL -o "$WORK/restic.bz2" "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2"
  if [ "$(sha256sum "$WORK/restic.bz2" | cut -d' ' -f1)" = "$RESTIC_BZ2_SHA256" ]; then
    bunzip2 -c -- "$WORK/restic.bz2" > "$WORK/restic"
    [ "$(sha256sum "$WORK/restic" | cut -d' ' -f1)" = "$RESTIC_SHA256" ] && install -o root -g root -m 0755 "$WORK/restic" "$RESTIC"
  fi
fi
check "restic is root 0755 and its sha256 is the broker's pin" bash -c \
  "[ \"\$(stat -c '%U %a' $RESTIC)\" = 'root 755' ] && [ \"\$(sha256sum $RESTIC | cut -d' ' -f1)\" = $RESTIC_SHA256 ]"
echo "  $("$RESTIC" version)"
for tool in /usr/bin/ssh /usr/bin/mariadb /usr/bin/mariadb-dump /usr/bin/cp; do
  echo "  $(stat -c '%n: %F, %U, %a' "$tool" 2>&1)"
  check "$tool is a regular root-owned file (the broker refuses a link)" bash -c "[ \"\$(stat -c '%F %U' $tool)\" = 'regular file root' ]"
done

echo
echo "## 2. The broker runs with the web operation on"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
install -d -o sifpanel -g sifpanel -m 0700 "$PANEL"
status="$(drive backup-status)" || fail "the broker answers the backup status"
key="$(printf '%s' "$status" | field '["public_key"]')"
echo "  broker backup key: ${key:0:40}..."
check "restic is ready as the broker sees it" test "$(printf '%s' "$status" | field '["ready"]')" = True
check "the broker made its own ed25519 key, root-only" bash -c \
  "[[ '$key' == ssh-ed25519\ * ]] && [ \"\$(stat -c '%U %a' $STATE/backup/ssh_key)\" = 'root 600' ]"
check "the repository password file is root-only" test "$(stat -c '%U %a' "$STATE/backup/password")" = "root 600"

echo
echo "## 3. An SFTP storage user on this VM stands in for the storage server"
if ! id "$STORE_USER" >/dev/null 2>&1; then
  useradd --home-dir "$STORE_HOME" --create-home --shell /sbin/nologin "$STORE_USER"
fi
chmod 0700 "$STORE_HOME"
# The installer's sshd policy: a non-wheel user gets SFTP only, with keys
# from this root-owned folder.
printf 'restrict %s\n' "$key" > "/etc/sifruno/ssh/authorized_keys/$STORE_USER"
chown "root:$STORE_USER" "/etc/sifruno/ssh/authorized_keys/$STORE_USER"
chmod 0640 "/etc/sifruno/ssh/authorized_keys/$STORE_USER"
restorecon "/etc/sifruno/ssh/authorized_keys/$STORE_USER" 2>/dev/null
check "$STORE_USER is not in wheel, so sshd holds it to SFTP" bash -c "! id -nG $STORE_USER | grep -qw wheel"
ssh-keyscan -t ed25519 -p 22 127.0.0.1 2>/dev/null > "$PANEL/known_hosts"
ssh-keygen -q -t ed25519 -N '' -C bogus -f "$WORK/bogus"
printf '127.0.0.1 %s\n' "$(cut -d' ' -f1,2 "$WORK/bogus.pub")" > "$PANEL/bogus_hosts"
chown sifpanel:sifpanel "$PANEL/known_hosts" "$PANEL/bogus_hosts"
check "the storage server's host key was read with ssh-keyscan" grep -q 'ssh-ed25519' "$PANEL/known_hosts"
if drive backup-target --host 127.0.0.1 --port 22 --user "$STORE_USER" --path "$REPO" \
  --known-hosts-file "$PANEL/bogus_hosts" --password-out "$PANEL/repo-password" --reason 'Wrong host key' >/dev/null 2>"$WORK/bogus.err"; then
  fail "a target with the wrong host key is refused (no trust on first use)"
else
  sed 's/^/  broker answered: /' "$WORK/bogus.err"
  check "a target with the wrong host key is refused (no trust on first use)" grep -q 'backup connect step failed' "$WORK/bogus.err"
fi
check "the refused target made nothing on the storage server" test ! -e "$REPO"
# The password is shown in two steps: until the admin confirms it is saved,
# every target change answers it and it can be shown again. A broker whose
# state an earlier run already confirmed cannot show this part.
saved_before="$(drive backup-status | field '["password_saved"]')"
target="$(drive backup-target --host 127.0.0.1 --port 22 --user "$STORE_USER" --path "$REPO" \
  --known-hosts-file "$PANEL/known_hosts" --password-out "$PANEL/repo-password" --reason 'Backup storage proof' 2>"$WORK/target.err")" ||
  { sed 's/^/  broker answered: /' "$WORK/target.err"; fail "the broker opens the target"; }
check "the repository was made on the storage server" test "$(printf '%s' "$target" | field '["initialized"]')" = True
check "the repository belongs to the storage user" test "$(stat -c %U "$REPO/config")" = "$STORE_USER"
if [ "$saved_before" = True ]; then
  echo "SKIP  the two-step password: an earlier run confirmed this broker's password saved; it needs a fresh broker state"
else
  check "the repository password was shown (to a 0600 file), not printed" bash -c \
    "grep -q 'repository password shown' $WORK/target.err && [ \"\$(stat -c %a $PANEL/repo-password)\" = 600 ] && [ \$(tr -d '\n' < $PANEL/repo-password | wc -c) -eq 43 ]"
  again="$(drive backup-target --host 127.0.0.1 --port 22 --user "$STORE_USER" --path "$REPO" \
    --known-hosts-file "$PANEL/known_hosts" --password-out "$PANEL/second-password" --reason 'Same target again' 2>"$WORK/again.err")"
  again_initialized="$(printf '%s' "$again" | field '["initialized"]' 2>/dev/null)"
  check "saving the same target again opens the repository and, not yet confirmed, answers the same password" bash -c \
    "[ '$again_initialized' = False ] && cmp -s $PANEL/repo-password $PANEL/second-password"
  drive backup-password --password-out "$PANEL/shown-again" --reason 'The answer was lost' >/dev/null 2>"$WORK/shown.err"
  check "a lost answer does not lose it: the broker shows the same password again" cmp -s "$PANEL/repo-password" "$PANEL/shown-again"
  status="$(drive backup-status)"
  status_saved="$(printf '%s' "$status" | field '["password_saved"]')"
  check "the status says it is not confirmed yet and carries no password" bash -c \
    "[ '$status_saved' = False ] && ! printf '%s' '$status' | grep -qF -f $PANEL/repo-password"
  confirmed="$(drive backup-password-saved --reason 'Saved in the backup proof')"
  check "the confirmation is recorded" test "$(printf '%s' "$confirmed" | field '["password_saved"]')" = True
  if drive backup-password --password-out "$PANEL/after-confirm" --reason 'After the confirmation' >/dev/null 2>"$WORK/after-confirm.err"; then
    fail "after the confirmation the broker no longer shows the password"
  else
    sed 's/^/  broker answered: /' "$WORK/after-confirm.err"
    check "after the confirmation the broker no longer shows the password" bash -c "grep -q 'conflict' $WORK/after-confirm.err && [ ! -s $PANEL/after-confirm ]"
  fi
  third="$(drive backup-target --host 127.0.0.1 --port 22 --user "$STORE_USER" --path "$REPO" \
    --known-hosts-file "$PANEL/known_hosts" --password-out "$PANEL/third-password" --reason 'Same target after the confirmation' 2>"$WORK/third.err")"
  third_saved="$(printf '%s' "$third" | field '["status"]["password_saved"]' 2>/dev/null)"
  check "a target change after the confirmation shows no password" bash -c \
    "[ ! -e $PANEL/third-password ] && ! grep -q 'repository password shown' $WORK/third.err && [ '$third_saved' = True ]"
fi
check "the repository password file stayed root-only throughout" test "$(stat -c '%U %a' "$STATE/backup/password")" = "root 600"

echo
echo "## 4. A WordPress site through the broker and dbhost"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Backup proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | field '["id"]')"
rev="$(printf '%s' "$created" | field '["revision"]')"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 400 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | field '["account"]["revision"]')"
secret > "$PANEL/db-password"
secret > "$PANEL/admin-password"
chown sifpanel:sifpanel "$PANEL/db-password" "$PANEL/admin-password"
chmod 0600 "$PANEL/db-password" "$PANEL/admin-password"
"$BIN/dbdrive" --registry "$WORK/dbmap.json" --owner "$SITE_USER" --name "$DB" --password-file "$PANEL/db-password" | sed 's/^/  /'
drive wordpress --id "$id" --revision "$rev" --title "$TITLE" --admin-user proofadmin \
  --admin-email "admin@$DOMAIN" --admin-password-file "$PANEL/admin-password" \
  --db-name "$DB" --db-user "$DB" --db-password-file "$PANEL/db-password" >/dev/null 2>"$WORK/install.err" ||
  { sed 's/^/  broker answered: /' "$WORK/install.err"; fail "the broker installs WordPress"; }
ok=no
for _ in $(seq 1 300); do
  if page / | grep -qF "$TITLE"; then ok=yes; break; fi
  sleep 2
done
check "the site serves its title before the backup" test "$ok" = yes
public_inode="$(stat -c %i "/home/$SITE_USER/public_html")"
# A sparse file the tenant makes: 1 GiB long, a few bytes of data in the
# middle. It costs almost nothing under the quota and in the repository;
# the restore must not write it out in full.
SPARSE="/home/$SITE_USER/public_html/sparse.bin"
MARKER=sifruno-sparse-marker
runuser -u "$SITE_USER" -- truncate -s 1G "$SPARSE"
printf '%s' "$MARKER" | runuser -u "$SITE_USER" -- dd of="$SPARSE" bs=1 seek=536870912 conv=notrunc status=none
echo "  sparse.bin: $(stat -c %s "$SPARSE") bytes long, $(du -k "$SPARSE" | cut -f1) KiB on disk"
check "the site holds a 1 GiB sparse file using under 64 MiB of disk" bash -c \
  "[ \$(stat -c %s $SPARSE) -eq 1073741824 ] && [ \$(du -k $SPARSE | cut -f1) -lt 65536 ]"

echo
echo "## 5. Back it up"
sample_start
start=$(date +%s)
backup="$(drive backup --id "$id" --db "$DB" --reason 'Backup proof' 2>"$WORK/backup.err")"
status=$?
sample_stop
echo "  took $(( $(date +%s) - start )) s"
[ -s "$WORK/backup.err" ] && sed 's/^/  broker answered: /' "$WORK/backup.err"
check "the broker backed up the site and its database" test "$status" -eq 0
snap="$(printf '%s' "$backup" | field '["id"]' 2>/dev/null)"
echo "  snapshot ${snap:0:12}, $(printf '%s' "$backup" | field '["bytes"]' 2>/dev/null) bytes"
check "the snapshot names the database" bash -c "printf '%s' '$backup' | grep -q '\"$DB\"'"
check "the snapshot is stored on the storage server, as the storage user" bash -c \
  "[ \$(find $REPO/snapshots -type f | wc -l) -ge 1 ] && [ \"\$(stat -c %U $REPO/snapshots)\" = $STORE_USER ]"
check "the database dump did not stay on this server" bash -c "[ ! -e $STATE/backup/dump/$id ]"
listed="$(drive backups --id "$id")"
check "the site's backup list shows the snapshot" bash -c "printf '%s' '$listed' | grep -q '$snap'"

echo
echo "## 6. Break it: delete public_html's files and drop a table"
find "/home/$SITE_USER/public_html" -mindepth 1 -delete
sql "DROP TABLE \`$DB\`.wp_options"
check "public_html is empty" bash -c "[ -z \"\$(ls -A /home/$SITE_USER/public_html)\" ]"
check "wp_options is gone" bash -c "! mysql --protocol=socket -uroot -N -e 'SHOW TABLES' $DB | grep -qx wp_options"
check "the site no longer serves its title" bash -c "! curl -s -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -qF '$TITLE'"

echo
echo "## 7. Restore the files and the database"
# The broker refuses a restore whose snapshot (the sparse file counted at
# its full 1 GiB) would not leave 5% of the disk, at least 2 GiB, free.
echo "  staging disk: $(df -h --output=avail,size /var/lib/sifruno-restore | tail -1 | awk '{print $1 " free of " $2}')"
sample_start
start=$(date +%s)
restored="$(drive restore --id "$id" --revision "$rev" --snapshot "$snap" --files --db "$DB" --reason 'Restore proof' 2>"$WORK/restore.err")"
status=$?
sample_stop
echo "  took $(( $(date +%s) - start )) s"
[ -s "$WORK/restore.err" ] && sed 's/^/  broker answered: /' "$WORK/restore.err"
check "the broker restored the files and the database" test "$status" -eq 0
printf '%s\n' "$restored" | sed 's/^/  /'

echo
echo "## 8. The site is back"
ok=no
for _ in $(seq 1 150); do
  if page / | grep -qF "$TITLE"; then ok=yes; break; fi
  sleep 2
done
check "the site serves its title again" test "$ok" = yes
check "wp_options is back" bash -c "mysql --protocol=socket -uroot -N -e 'SHOW TABLES' $DB | grep -qx wp_options"
check "the restored files belong to the site user" test "$(stat -c %U "/home/$SITE_USER/public_html/wp-load.php")" = "$SITE_USER"
check "wp-config.php is the site user's and mode 0600 again" test "$(stat -c '%U %a' "/home/$SITE_USER/public_html/wp-config.php")" = "$SITE_USER 600"
echo "  restored sparse.bin: $(stat -c %s "$SPARSE" 2>&1) bytes long, $(du -k "$SPARSE" 2>&1 | cut -f1) KiB on disk"
check "the sparse file came back sparse (restic restore --sparse, then cp): 1 GiB long, under 64 MiB on disk, its data in place" bash -c \
  "[ \$(stat -c %s $SPARSE) -eq 1073741824 ] && [ \$(du -k $SPARSE | cut -f1) -lt 65536 ] && [ \"\$(dd if=$SPARSE bs=1 skip=536870912 count=${#MARKER} status=none)\" = $MARKER ]"
check "the home kept mode 0750 and public_html is the same folder" bash -c \
  "[ \"\$(stat -c '%U %a' /home/$SITE_USER)\" = '$SITE_USER 750' ] && [ \"\$(stat -c %i /home/$SITE_USER/public_html)\" = $public_inode ]"
check "no temporary restore user is left in MariaDB" test "$(sql "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'sifruno\\_rst\\_%'")" = 0
check "the staging folder is gone and its parent is root 0711" bash -c \
  "[ \"\$(stat -c '%U %a' /var/lib/sifruno-restore)\" = 'root 711' ] && [ -z \"\$(ls -A /var/lib/sifruno-restore)\" ]"
state="$(drive list | python3 -c "import json,sys; print([a['state'] for a in json.load(sys.stdin) if a['id'] == '$id'][0])" 2>/dev/null)"
check "the account still verifies and is active after the restore" test "$state" = active

echo
echo "## 9. The restore drill"
drill="$(drive drill --id "$id" --reason 'Drill proof' 2>"$WORK/drill.err")" || sed 's/^/  broker answered: /' "$WORK/drill.err"
printf '%s\n' "$drill" | sed 's/^/  /'
compared="$(printf '%s' "$drill" | field '["files"]' 2>/dev/null)"
check "the drill passed" test "$(printf '%s' "$drill" | field '["passed"]' 2>/dev/null)" = True
check "the drill compared the restored files with the snapshot's list (${compared:-0} entries)" test "${compared:-0}" -gt 100
check "the drill left no staging folder" bash -c "[ -z \"\$(ls -A /var/lib/sifruno-restore)\" ]"

echo
echo "## 10. No password in any process argument"
samples="$(grep -c '^--$' "$WORK/ps-samples.txt")"
echo "  process-argument samples taken during the backup and the restore: $samples"
check "no process argument held the repository, database or admin password" bash -c \
  "[ $samples -gt 0 ] && ! grep -qF -f <(for f in $STATE/backup/password $PANEL/db-password $PANEL/admin-password; do cat \$f; echo; done) $WORK/ps-samples.txt"
check "restic and ssh ran during the samples" bash -c "grep -q 'restic' $WORK/ps-samples.txt && grep -q 'HostKeyAlias=sifruno-backup-target' $WORK/ps-samples.txt"
check "the broker's answers hold no password" bash -c \
  "! grep -qF -f <(for f in $STATE/backup/password $PANEL/db-password $PANEL/admin-password; do cat \$f; echo; done) $WORK/target.err $WORK/backup.err $WORK/restore.err $WORK/drill.err"

echo
echo "## 11. Clean up the proof site"
drive delete --id "$id" --revision "$rev" --reason 'Remove the backup proof site' >/dev/null || fail "the broker deletes the account"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"
sql "DROP DATABASE IF EXISTS \`$DB\`; DROP USER IF EXISTS '$DB'@'localhost'"
# The proof's secrets and repository do not outlive it; the storage user
# stays for the next run.
rm -rf -- "$REPO" "$PANEL" "$WORK"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
