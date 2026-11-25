#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh broker-wordpress copies it in).
# Proves the WordPress install through the panel's own code paths: dbhost
# creates the site's database, and the root broker runs WP-CLI as the site's
# user with the passwords on stdin. Prints PASS/FAIL per check.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="wp${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
DB="${SITE_USER}_wp"
WORK="$(mktemp -d /root/broker-wordpress.XXXXXX)"
# What the panel holds lives in its own home, where brokerdrive (as sifpanel)
# can read it.
PANEL="/var/lib/sifpanel/wordpress-proof-$RUNID"
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
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://127.0.0.1$1"; }
# Random one-line secrets; they live only in files and are never printed.
secret() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20; }

echo "# Broker WordPress install: dbhost database, WP-CLI as the site user, passwords on stdin"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 mariadb-server | paste -sd ' ')"
echo "# site user $SITE_USER, domain $DOMAIN"

echo
echo "## 1. The broker runs with the web operation on"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
check "WP-CLI 2.12.0 is installed root-owned and matches its pinned sha512" bash -c \
  "[ \"\$(stat -c '%U %a' /usr/local/lib/sifruno/wp-cli.phar)\" = 'root 644' ] && sha512sum /usr/local/lib/sifruno/wp-cli.phar | grep -q '^be928f6b8ca1e8dfb9d2f4b75a13aa4a'"

echo
echo "## 2. An account with a live site"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'WordPress proof')" || fail "broker creates the account"
id="$(printf '%s' "$created" | field '["id"]')"
rev="$(printf '%s' "$created" | field '["revision"]')"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 400 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | field '["account"]["revision"]')"
check "the site is live with PHP 8.3" test -n "$rev"

echo
echo "## 3. The database, through the panel's database code"
install -d -o sifpanel -g sifpanel -m 0700 "$PANEL"
secret > "$PANEL/db-password"
secret > "$PANEL/admin-password"
chown sifpanel:sifpanel "$PANEL/db-password" "$PANEL/admin-password"
chmod 0600 "$PANEL/db-password" "$PANEL/admin-password"
# dbdrive signs in to MariaDB as root over the socket here, standing in for
# the panel's admin option file (--db-defaults-file).
db_out="$("$BIN/dbdrive" --registry "$WORK/dbmap.json" --owner "$SITE_USER" --name "$DB" --password-file "$PANEL/db-password" 2>&1)"
db_status=$?
printf '%s\n' "$db_out" | sed 's/^/  /'
check "dbhost created the database and its user" test "$db_status" -eq 0
# Sign in as that user over loopback TCP, as WordPress will, with the
# password in an option file rather than an argument.
printf '[client]\nuser=%s\npassword=%s\n' "$DB" "$(cat "$PANEL/db-password")" > "$WORK/site.cnf"
chmod 0600 "$WORK/site.cnf"
check "the database user signs in over 127.0.0.1 and sees its database" \
  bash -c "mysql --defaults-extra-file=$WORK/site.cnf -h 127.0.0.1 -N -e 'SELECT DATABASE()' $DB | grep -qx $DB"

echo
echo "## 4. The broker installs WordPress as the site user"
# Sample every process's arguments while the install runs: neither password
# may appear in any of them.
( while :; do ps -eo args >> "$WORK/ps-samples.txt"; echo '--' >> "$WORK/ps-samples.txt"; sleep 0.5; done ) &
sampler=$!
start=$(date +%s)
# The title carries what systemd would expand in a unit's command line ($
# and % specifiers): it must reach WordPress exactly as given.
# shellcheck disable=SC2016 # the $ is meant literally
TITLE='Sifruno WordPress proof 100% $HOME %h %n'
installed="$(drive wordpress --id "$id" --revision "$rev" --title "$TITLE" --admin-user proofadmin \
  --admin-email "admin@$DOMAIN" --admin-password-file "$PANEL/admin-password" \
  --db-name "$DB" --db-user "$DB" --db-password-file "$PANEL/db-password" 2>"$WORK/install.err")"
status=$?
kill "$sampler" 2>/dev/null
wait "$sampler" 2>/dev/null
echo "  took $(( $(date +%s) - start )) s"
[ -s "$WORK/install.err" ] && sed 's/^/  broker answered: /' "$WORK/install.err"
check "the broker installed WordPress" test "$status" -eq 0
version="$(printf '%s' "$installed" | field '["version"]' 2>/dev/null)"
echo "  WordPress version: ${version:-none}"
check "the result names the installed version" bash -c "[[ '$version' =~ ^[0-9]+\.[0-9]+ ]]"
samples="$(grep -c '^--$' "$WORK/ps-samples.txt")"
echo "  process-argument samples taken during the install: $samples"
check "no process argument held either password during the install" bash -c \
  "[ $samples -gt 0 ] && ! grep -qF -f <(cat $PANEL/db-password $PANEL/admin-password) $WORK/ps-samples.txt"
check "the WordPress files belong to the site user" test "$(stat -c %U "/home/$SITE_USER/public_html/wp-load.php")" = "$SITE_USER"
check "wp-config.php is the site user's and mode 0600" test "$(stat -c '%U %a' "/home/$SITE_USER/public_html/wp-config.php")" = "$SITE_USER 600"
check "wp-config.php points at 127.0.0.1" grep -q "define( 'DB_HOST', '127.0.0.1' )" "/home/$SITE_USER/public_html/wp-config.php"
check "WordPress's tables are in the site's database" \
  bash -c "mysql --defaults-extra-file=$WORK/site.cnf -h 127.0.0.1 -N -e 'SHOW TABLES' $DB | grep -qx wp_options"
check "the admin user exists" \
  bash -c "mysql --defaults-extra-file=$WORK/site.cnf -h 127.0.0.1 -N -e 'SELECT user_login FROM wp_users' $DB | grep -qx proofadmin"
stored="$(mysql --defaults-extra-file="$WORK/site.cnf" -h 127.0.0.1 -N -B -e "SELECT option_value FROM wp_options WHERE option_name = 'blogname'" "$DB" 2>&1)"
echo "  stored title: $stored"
check "the title reached WordPress exactly, \$ and % untouched" test "$stored" = "$TITLE"
plugins="$(mysql --defaults-extra-file="$WORK/site.cnf" -h 127.0.0.1 -N -B -e "SELECT option_value FROM wp_options WHERE option_name = 'active_plugins'" "$DB" 2>&1)"
check "the LiteSpeed Cache plugin is active" grep -q 'litespeed-cache/litespeed-cache.php' <<<"$plugins"

echo
echo "## 5. The site serves WordPress"
# The first request starts lsphp and loads WordPress cold; under software
# emulation on a busy host that has taken more than five minutes.
ok=no
first=$(date +%s)
for _ in $(seq 1 300); do
  if page / | grep -q 'Sifruno WordPress proof'; then ok=yes; break; fi
  sleep 2
done
echo "  first page after $(( $(date +%s) - first )) s"
check "the home page carries the site title" test "$ok" = yes
check "wp-login.php answers 200" test "$(code /wp-login.php)" = 200
check "wp-config.php is not served as text" bash -c "! page /wp-config.php | grep -q DB_PASSWORD"

echo
echo "## 6. A second install into the same site is refused and changes nothing"
before="$(sha256sum "/home/$SITE_USER/public_html/wp-config.php")"
if drive wordpress --id "$id" --revision "$rev" --title 'Again' --admin-user proofadmin \
  --admin-email "admin@$DOMAIN" --admin-password-file "$PANEL/admin-password" \
  --db-name "$DB" --db-user "$DB" --db-password-file "$PANEL/db-password" >/dev/null 2>"$WORK/again.err"; then
  fail "the broker refused to install over an existing WordPress"
else
  sed 's/^/  broker answered: /' "$WORK/again.err"
  check "the broker refused to install over an existing WordPress, naming the step" grep -q 'download step failed' "$WORK/again.err"
fi
check "neither password appears in the broker's answers" bash -c "! grep -qF -f <(cat $PANEL/db-password $PANEL/admin-password) $WORK/again.err $WORK/install.err"
check "wp-config.php is unchanged" bash -c "[ \"\$(sha256sum /home/$SITE_USER/public_html/wp-config.php)\" = '$before' ]"
check "the site still serves" bash -c "curl -s -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -q 'Sifruno WordPress proof'"

echo
echo "## 7. The account can be deleted after the install"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
check "the Linux user is gone" bash -c "! getent passwd $SITE_USER"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws

# The proof's secrets do not outlive it.
rm -f "$PANEL/db-password" "$PANEL/admin-password" "$WORK/site.cnf" "$WORK/ps-samples.txt"
rmdir "$PANEL" 2>/dev/null

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
