#!/usr/bin/env bash
# Proof 1 (docs/PRODUCT-PLAN.md, Phase 0 item 7), guest side. Runs as root in
# the dev VM after provision.sh and the broker proof (it reuses that broker's
# state). A WordPress site on OpenLiteSpeed, produced from config, running as
# its own Linux user inside OpenLiteSpeed's namespace container, with a disk
# quota:
#   1. the root broker creates the account (a regular Linux user)
#   2. olsweb renders the OpenLiteSpeed config from a typed site spec
#   3. WP-CLI installs WordPress as that user against its own database
#   4. checks from outside: the page, the PHP identity, what PHP can see,
#      the deny rules, the quota, and the time from account to live site
#
# Two steps are stand-ins for broker operations that do not exist yet and are
# labelled as such below: the web server's access to the home (an ACL) and
# the disk quota (xfs_quota). The database is created with the MariaDB
# client as root, as the wizard's job will do through the broker.
#
# Every check prints PASS or FAIL. The exit status is the number of FAILs.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
PHP_CLI="$LSWS/lsphp83/bin/php"
WPCLI_VERSION=2.12.0
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="wp${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
WORK="/root/sifruno-proof1-${RUNID}"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
as_site() { runuser -u "$SITE_USER" -- env HOME="/home/$SITE_USER" WP_CLI_CACHE_DIR="/tmp/wpcli-$SITE_USER" "$@"; }
wp() { as_site "$PHP_CLI" -d memory_limit=256M "$BIN/wp-cli.phar" --path="/home/$SITE_USER/public_html" "$@"; }
get() { curl -s -H "Host: $DOMAIN" "$@"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "$1"; }

echo "# Proof 1: WordPress on OpenLiteSpeed from config, own user, namespace, quota"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 mariadb-server | tr '\n' ' ')"
echo "# site user $SITE_USER, domain $DOMAIN"
mkdir -p "$WORK"
chmod 700 "$WORK"

echo
echo "## WP-CLI $WPCLI_VERSION, checksum-verified"
if [ ! -f "$BIN/wp-cli.phar" ]; then
  base="https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar"
  curl -fsSL -o "$WORK/wp-cli.phar" "$base" && curl -fsSL -o "$WORK/wp-cli.phar.sha512" "$base.sha512"
  if [ "$(sha512sum "$WORK/wp-cli.phar" | awk '{print $1}')" = "$(awk '{print $1}' "$WORK/wp-cli.phar.sha512")" ]; then
    install -m 0755 "$WORK/wp-cli.phar" "$BIN/wp-cli.phar"
  fi
fi
check "WP-CLI is installed and its checksum matched" test -x "$BIN/wp-cli.phar"

echo
echo "## 1. The broker creates the account"
if [ ! -S "$SOCKET" ]; then
  systemctl reset-failed sifruno-broker-proof 2>/dev/null
  systemd-run --quiet --unit sifruno-broker-proof --collect \
    "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)"
  for _ in $(seq 1 30); do [ -S "$SOCKET" ] && break; sleep 1; done
fi
started=$(date +%s)
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Proof 1 WordPress site')" || fail "broker creates the account"
account_id="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)"
check "the account exists as a regular Linux user" bash -c "getent passwd $SITE_USER | grep -q ':/home/$SITE_USER:/usr/sbin/nologin\$'"

echo
echo "## 2. Web server access and quota (stand-ins for broker operations still to build)"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
# OpenLiteSpeed reads static files as its own user. A named ACL entry gives it
# traverse on the home and read on public_html without changing the owner,
# group or mode bits that the broker verifies.
setfacl -m "u:${ols_user}:x" "/home/$SITE_USER"
setfacl -m "u:${ols_user}:rx" "/home/$SITE_USER/public_html"
check "the broker still sees the account as unchanged after the ACL" bash -c "runuser -u sifpanel -- $BIN/brokerdrive --socket $SOCKET list | python3 -c 'import json,sys; a=[x for x in json.load(sys.stdin) if x[\"username\"]==\"$SITE_USER\"]; sys.exit(0 if a and a[0][\"state\"]==\"active\" else 1)'"
xfs_quota -x -c "limit -u bsoft=180m bhard=200m $SITE_USER" /home
# -v: without it xfs_quota prints nothing for a user who has no usage yet.
check "a 200 MiB hard quota is set on the account" bash -c "xfs_quota -x -c 'quota -v -u -N -b $SITE_USER' /home | awk '{print \$4}' | grep -qx 204800"

echo
echo "## 3. Database"
db="${SITE_USER}_wp"
db_password="$(openssl rand -hex 20)"
mysql --protocol=socket -uroot <<SQL
CREATE DATABASE \`$db\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$SITE_USER'@'127.0.0.1' IDENTIFIED BY '$db_password';
CREATE USER '$SITE_USER'@'localhost' IDENTIFIED BY '$db_password';
GRANT ALL PRIVILEGES ON \`$db\`.* TO '$SITE_USER'@'127.0.0.1';
GRANT ALL PRIVILEGES ON \`$db\`.* TO '$SITE_USER'@'localhost';
SQL
check "the site's database user can sign in over TCP" mysql -h 127.0.0.1 -u "$SITE_USER" -p"$db_password" -e 'SELECT 1' "$db"
check "the site's database user cannot see the mysql schema" bash -c "! mysql -h 127.0.0.1 -u $SITE_USER -p$db_password -e 'SELECT 1 FROM mysql.user LIMIT 1' 2>/dev/null"

echo
echo "## 4. OpenLiteSpeed config from a typed spec"
python3 - "$SITE_USER" "$DOMAIN" "$WORK/spec.json" <<'PY'
import json, sys
user, domain, out = sys.argv[1:4]
spec = {
    "listeners": [{"name": "http", "address": "*", "port": 80}],
    "sites": [{
        "name": user, "username": user, "group": user, "domains": [domain],
        "doc_root": f"/home/{user}/public_html", "php_version": "8.3",
        "limits": {"php_children": 4}, "isolation": {"namespace": True},
    }],
}
json.dump(spec, open(out, "w"), indent=1)
PY
"$BIN/olsrender" --spec "$WORK/spec.json" --out "$WORK/ols" | sed 's/^/  wrote /'
conf="$LSWS/conf/httpd_config.conf"
if ! grep -q '^include /usr/local/lsws/conf/sifruno.conf' "$conf"; then
  cp -a "$conf" "$conf.bak-$(date +%Y%m%d-%H%M)"
  # A vhost namespace setting applies only when the server-level one is not 0.
  if grep -qE '^namespace[[:space:]]' "$conf"; then
    sed -i -E 's/^namespace[[:space:]].*/namespace                 1/' "$conf"
  else
    printf '%s\n' 'namespace                 1' >> "$conf"
  fi
  printf '%s\n' 'include /usr/local/lsws/conf/sifruno.conf' >> "$conf"
fi
install -d -m 0750 "$LSWS/logs/sifruno" "$LSWS/logs/sifruno/$SITE_USER"
chown --reference="$LSWS/logs" "$LSWS/logs/sifruno" "$LSWS/logs/sifruno/$SITE_USER"
install -d -m 0750 "$LSWS/conf/vhosts/sifruno-$SITE_USER"
install -m 0600 "$WORK/ols/conf/vhosts/sifruno-$SITE_USER/vhconf.conf" "$LSWS/conf/vhosts/sifruno-$SITE_USER/vhconf.conf"
install -m 0600 "$WORK/ols/conf/sifruno.conf" "$LSWS/conf/sifruno.conf"
chown -R --reference="$conf" "$LSWS/conf/sifruno.conf" "$LSWS/conf/vhosts/sifruno-$SITE_USER"
restorecon -R "$LSWS/conf" "$LSWS/logs" 2>/dev/null
# openlitespeed -t exits 1 when it logged anything at all, warnings included,
# and 2 only for an [ERROR] (v1.9.4 src/main/lshttpdmain.cpp). The stock
# Example vhost always logs two ownership warnings, so the check is: no error,
# and nothing logged about a Sifruno vhost.
test_status=0
"$LSWS/bin/openlitespeed" -t > "$WORK/config-test.txt" 2>&1 || test_status=$?
check "OpenLiteSpeed accepts the rendered config (openlitespeed -t, no error)" test "$test_status" -ne 2
check "openlitespeed -t logged nothing about the Sifruno vhost" bash -c "! grep -q 'sifruno' $WORK/config-test.txt"
sed 's/^/  /' "$WORK/config-test.txt" | tail -5

echo
echo "## 5. WordPress, installed by WP-CLI as the site user"
admin_password="$(openssl rand -hex 16)"
wp core download --locale=en_US > "$WORK/wp-download.txt" 2>&1
check "WordPress downloaded into public_html" test -f "/home/$SITE_USER/public_html/wp-load.php"
wp config create --dbname="$db" --dbuser="$SITE_USER" --dbpass="$db_password" --dbhost=127.0.0.1 > "$WORK/wp-config.txt" 2>&1
wp core install --url="http://$DOMAIN" --title="Sifruno proof site" --admin_user=proofadmin --admin_password="$admin_password" --admin_email="admin@$DOMAIN" --skip-email > "$WORK/wp-install.txt" 2>&1
check "WordPress is installed" wp core is-installed
check "WordPress files belong to the site user" test "$(stat -c %U "/home/$SITE_USER/public_html/wp-config.php")" = "$SITE_USER"
cat > "$WORK/whoami.php" <<'PHP'
<?php
header('Content-Type: text/plain');
$me = posix_getpwuid(posix_geteuid());
echo 'user=', $me['name'], "\n";
echo 'home_entries=', implode(',', array_diff(scandir('/home') ?: [], ['.', '..'])), "\n";
echo 'passwd_lines=', count(file('/etc/passwd')), "\n";
echo 'other_home_readable=', (@scandir('/home/sifpanel') !== false || @file_get_contents('/etc/shadow') !== false) ? 'yes' : 'no', "\n";
PHP
install -o "$SITE_USER" -g "$SITE_USER" -m 0644 "$WORK/whoami.php" "/home/$SITE_USER/public_html/whoami.php"
printf '%s\n' "<?php // backup copy" | as_site tee "/home/$SITE_USER/public_html/wp-config.php.bak" >/dev/null

echo
echo "## 6. Graceful restart and the live site"
systemctl restart lsws
live=""
# The first request starts lsphp and loads WordPress cold. Under software
# emulation that took over two minutes in one run (the server answered with
# errors meanwhile), so wait up to ten and record the statuses seen.
restarted=$(date +%s)
statuses=""
while [ $(( $(date +%s) - restarted )) -lt 600 ]; do
  status="$(curl -s -o "$WORK/home.html" -w '%{http_code}' --max-time 120 -H "Host: $DOMAIN" http://127.0.0.1/)"
  statuses="$statuses $status"
  if [ "$status" = 200 ] && grep -q 'Sifruno proof site' "$WORK/home.html"; then live=$(date +%s); break; fi
  sleep 5
done
echo "home page statuses until the first good answer:$statuses"
[ -n "$live" ] && echo "first good answer $((live - restarted)) s after the restart"
if [ -n "$live" ]; then
  pass "the WordPress home page answers on port 80 for $DOMAIN"
  echo "time from account creation to live site: $((live - started)) s (software-emulated VM; see the README)"
else
  fail "the WordPress home page answers on port 80 for $DOMAIN"
  tail -n 30 "$LSWS/logs/error.log" | sed 's/^/  /'
fi
check "wp-login.php answers 200" test "$(code http://127.0.0.1/wp-login.php)" = 200
get http://127.0.0.1/whoami.php > "$WORK/whoami.txt"
sed 's/^/  /' "$WORK/whoami.txt"
check "PHP runs as the site user" grep -qx "user=$SITE_USER" "$WORK/whoami.txt"
check "PHP sees only its own home under /home (namespace)" grep -qx "home_entries=$SITE_USER" "$WORK/whoami.txt"
check "PHP sees a short /etc/passwd (namespace)" bash -c "awk -F= '/^passwd_lines=/{exit !(\$2<=5)}' $WORK/whoami.txt"
check "PHP cannot read other homes or /etc/shadow" grep -qx 'other_home_readable=no' "$WORK/whoami.txt"
check "lsphp for this site runs as the site user" bash -c "ps -o user= -C lsphp | grep -qx $SITE_USER"
for path in /.htaccess /wp-config.php.bak /.env /.git/config; do
  check "$path is denied (403)" test "$(code "http://127.0.0.1$path")" = 403
done
check "another Host name is not served this site" bash -c "! curl -s -H 'Host: not-mapped.test' http://127.0.0.1/ | grep -q 'Sifruno proof site'"

echo
echo "## 7. The quota holds"
as_site dd if=/dev/zero of="/home/$SITE_USER/fill.bin" bs=1M count=300 status=none 2> "$WORK/dd.txt"
echo "  $(head -c 200 "$WORK/dd.txt")"
check "writing past 200 MiB fails with a quota error" grep -qi 'quota' "$WORK/dd.txt"
used_kib="$(xfs_quota -x -c "quota -u -N -b $SITE_USER" /home | awk '{print $2}')"
echo "  usage at the limit: ${used_kib} KiB"
check "usage never passes the hard limit" test "${used_kib:-999999}" -le 204800
as_site rm -f "/home/$SITE_USER/fill.bin"
check "the site still answers after the quota was hit" bash -c "curl -s -H 'Host: $DOMAIN' http://127.0.0.1/ | grep -q 'Sifruno proof site'"

echo
echo "## SELinux"
denials="$(ausearch -m avc -ts recent 2>/dev/null | grep -c denied || true)"
echo "AVC denials in the last 10 minutes: ${denials:-0}"
ausearch -m avc -ts recent 2>/dev/null | grep denied | sed 's/^/  /' | head -5

echo
echo "Account $account_id, work files in $WORK"
echo "# Result: $fails failed"
exit "$fails"
