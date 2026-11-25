#!/usr/bin/env bash
# Migration v1 proof, guest side (proof.sh migrate-cpanel copies it in).
# Runs as root in the dev VM:  migrate-cpanel.guest.sh DIR PORT
# DIR holds the panel (sifruno, dist.tgz, state.tgz); the panel listens on
# 127.0.0.1:PORT as sifpanel with the broker and the MariaDB option file.
#
# THE OLD SERVER HERE IS A STAND-IN, NOT cPANEL. cPanel's software is
# licensed and is not installed or analysed. A Podman container (AlmaLinux
# 9.6, pinned by digest) plays a cPanel server: sshd for root, MariaDB,
# Apache with PHP-FPM serving /home/<user>/public_html, cronie's crontab,
# and two small scripts at /usr/local/cpanel/bin/whmapi1 and
# /usr/local/cpanel/bin/uapi that print the JSON shapes cPanel's public API
# documentation gives for listaccts, domainuserdata,
# php_get_vhost_versions, Mysql list_databases and list_users, for exactly
# the accounts this script makes. Six accounts:
#   shop<id>   WordPress with its rewrite rules and the stock Akismet
#              plugin, whose .htaccess (deny all, a <FilesMatch> allow-list,
#              Apache 2.2 and 2.4 branches) the converter turns into an
#              OpenLiteSpeed rule: the full path, from discovery to the DNS
#              records, with the closed folder and its open files checked
#   staff<id>  a password-protected folder (.htaccess + a user file in
#              .htpasswds, as cPanel's Directory Privacy keeps it) and a
#              folder closed with Deny from all, two address-list folders
#              and root rewrite rules into the closed folders: all converted
#              or kept, so the site moves and answers 401 without the
#              password, 200 with it, 403 for the closed folder, the lists
#              by client address, and every other spelling of the paths
#   odd<id>    an .htaccess with a directive the converter does not know:
#              refused before anything is created
#   trig<id>   a PHP site whose database has a trigger: the copy fails at
#              the database and the job removes what it created
#   race<id>   a tenant that swaps a folder for a link to /root while the
#              copy runs: the old server reads the home as the account,
#              so nothing of /root reaches this server
#   hard<id>   a tenant holding a hard link to a root-only file: the copy
#              stops on what the account may not read; nothing arrives
# Every check prints PASS or FAIL; the exit status is the number of FAILs.
set -uo pipefail

DIR="${1:?usage: migrate-cpanel.guest.sh DIR PORT}"
PORT="${2:?usage: migrate-cpanel.guest.sh DIR PORT}"
BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
WPCLI=/usr/local/lib/sifruno/wp-cli.phar
# docker.io/library/almalinux:9.6, linux/amd64, pushed 2025-11-17.
IMAGE=docker.io/library/almalinux@sha256:1d06c00a6025b4faf042d3827d9ea8dc6b7a75278cacc1c1399dcc7a89c07a01
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
CTR="sifruno-cpanel-standin-$RUNID"
SHOP="shop$RUNID" STAFF="staff$RUNID" TRIG="trig$RUNID" RACE="race$RUNID" HARD="hard$RUNID" ODD="odd$RUNID"
SHOP_DOMAIN="$SHOP.proof.test" STAFF_DOMAIN="$STAFF.proof.test" TRIG_DOMAIN="$TRIG.proof.test" RACE_DOMAIN="$RACE.proof.test" HARD_DOMAIN="$HARD.proof.test" ODD_DOMAIN="$ODD.proof.test"
# Only root may read these on the stand-in; neither may reach this server.
ROOT_MARK="root-only-$RUNID-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TITLE="Stand-in cPanel site $RUNID"
API="http://127.0.0.1:$PORT"
WORK="$(mktemp -d /root/migrate-cpanel.XXXXXX)"
chmod 0700 "$WORK"
JAR="$WORK/cookies"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
in_ctr() { podman exec "$CTR" bash -c "$1"; }
secret() { head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20; }
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {'d': d}))" "$1" "$2" 2>/dev/null; }
# call METHOD PATH [BODYFILE]: the answer goes to $WORK/answer.json, the
# status to $code. Bodies go through files, never arguments.
call() {
  local data=()
  [ -n "${3:-}" ] && data=(--data "@$3")
  code="$(curl -s -o "$WORK/answer.json" -w '%{http_code}' -b "$JAR" -c "$JAR" -H "Origin: $API" -H "X-CSRF-Token: ${CSRF:-}" \
    -H 'Content-Type: application/json' -X "$1" "${data[@]}" "$API$2")"
}
body() { printf '%s' "$2" > "$WORK/$1.json"; echo "$WORK/$1.json"; }
sample_start() { ( while :; do ps -eo args >> "$WORK/ps-samples.txt"; sleep 0.5; done ) & sampler=$!; }
sample_stop() { kill "$sampler" 2>/dev/null; wait "$sampler" 2>/dev/null; }
# shellcheck disable=SC2317 # called by the EXIT trap below
cleanup() {
  sample_stop 2>/dev/null
  podman rm -f "$CTR" >/dev/null 2>&1
  sed -i "/ # sifruno-migrate-proof-$RUNID\$/d" /etc/hosts
}
trap cleanup EXIT

echo "# Migration v1: one website account from a cPanel stand-in over root SSH"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed mariadb-server podman rsync openssh-clients | paste -sd ' ')"
echo "# accounts $SHOP, $STAFF, $ODD, $TRIG, $RACE, $HARD; container $CTR from $IMAGE"

echo
echo "## 1. The broker and the panel"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
VMIP="$(ip -4 -o route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker runs with the web operation on" test -S "$SOCKET"
cd "$DIR" || exit 1
tar -xzf dist.tgz && tar -xzf state.tgz && chown -R sifpanel:sifpanel "$DIR" && chmod 0755 sifruno
restorecon -R "$DIR" 2>/dev/null
pkill -x sifruno 2>/dev/null
runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$PORT --sites-listen '' --state ./state --ui ./dist \
  --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf --dns-ip $VMIP > panel.log 2>&1 &"
for _ in $(seq 1 90); do curl -fs -o /dev/null "$API/" && break; sleep 2; done
check "the panel answers on 127.0.0.1:$PORT as sifpanel, its DNS address $VMIP" curl -fs -o /dev/null "$API/"
for tool in /usr/bin/rsync /usr/bin/ssh /usr/bin/ssh-keyscan /usr/bin/cp /usr/bin/mariadb; do
  check "$tool is a root-owned program the broker admits" test "$(stat -c '%U' "$tool" 2>/dev/null)" = root
done

echo
echo "## 2. The cPanel stand-in (Podman, not cPanel)"
podman pull -q "$IMAGE" >/dev/null 2>&1
check "the stand-in's base image is the pinned digest" test "$(podman image inspect -f '{{.Digest}}' "$IMAGE" 2>/dev/null)" = "${IMAGE#*@}"
# AUDIT_WRITE: EL9's sshd fails a public-key sign-in when it cannot write
# the audit record ("linux_audit_write_entry failed"), and Podman's default
# capabilities leave it out, so without it every key is refused.
podman run -d --name "$CTR" --cap-add AUDIT_WRITE --hostname cpanel-standin "$IMAGE" sleep infinity >/dev/null
CIP="$(podman inspect -f '{{.NetworkSettings.IPAddress}}' "$CTR")"
echo "  stand-in address: ${CIP:-none}"
in_ctr "dnf -y -q module enable php:8.3 >/dev/null 2>&1 || dnf -y -q module enable php:8.2 >/dev/null 2>&1; \
  dnf -y -q install openssh-server rsync mariadb-server httpd php-fpm php-cli php-mysqlnd php-json php-gd php-xml php-mbstring cronie procps-ng >/dev/null 2>&1"
PHPXY="$(in_ctr "php -r 'echo PHP_MAJOR_VERSION.PHP_MINOR_VERSION;'" 2>/dev/null)"
echo "  stand-in PHP: ${PHPXY:-none} (reported to Sifruno as ea-php$PHPXY)"
check "the stand-in has sshd, MariaDB, Apache, PHP-FPM, rsync and crontab" in_ctr "test -x /usr/sbin/sshd -a -x /usr/sbin/httpd -a -x /usr/sbin/php-fpm -a -x /usr/bin/rsync -a -x /usr/bin/crontab -a -n '$PHPXY'"
# This server runs that PHP for the copy.
if [ -n "$PHPXY" ] && [ ! -x "$LSWS/lsphp$PHPXY/bin/lsphp" ]; then
  dnf -y -q install "lsphp$PHPXY" "lsphp$PHPXY-common" "lsphp$PHPXY-mysqlnd" >/dev/null 2>&1
fi
check "this server has LSPHP $PHPXY for the copy" test -x "$LSWS/lsphp$PHPXY/bin/lsphp"
in_ctr "ssh-keygen -A >/dev/null; mkdir -p /root/.ssh && chmod 700 /root/.ssh && : > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys; \
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config; /usr/sbin/sshd; \
  mariadb-install-db --user=mysql >/dev/null 2>&1; (mysqld_safe --user=mysql >/dev/null 2>&1 &); \
  mkdir -p /run/php-fpm && php-fpm -D; httpd -k start" >/dev/null 2>&1
for _ in $(seq 1 30); do in_ctr "mysql -e 'select 1'" >/dev/null 2>&1 && break; sleep 1; done
check "the stand-in's MariaDB, sshd and Apache run" in_ctr "mysql -e 'select 1' && pgrep -x sshd && pgrep httpd"

podman cp "$WPCLI" "$CTR:/usr/local/bin/wp-cli.phar"
SHOP_PW="$(secret)" STAFF_PW="$(secret)" TRIG_PW="$(secret)" HT_PW="$(secret)"
printf '%s' "$SHOP_PW" > "$WORK/shop.pw"
{
  echo "set -e"
  # cPanel's layout: public_html is the user's with the web server's group
  # (nobody there, apache here), 0750; inside it, folders are 0755 and files
  # 0644, the user's own, so the web server reads them as anyone may.
  for u in "$SHOP" "$STAFF" "$TRIG" "$RACE" "$HARD" "$ODD"; do
    echo "useradd -m -d /home/$u $u; chmod 0711 /home/$u; install -d -o $u -g apache -m 0750 /home/$u/public_html"
  done
  echo "cat > /etc/httpd/conf.d/standin.conf <<'CONF'"
  for pair in "$SHOP:$SHOP_DOMAIN" "$STAFF:$STAFF_DOMAIN" "$TRIG:$TRIG_DOMAIN" "$RACE:$RACE_DOMAIN" "$HARD:$HARD_DOMAIN" "$ODD:$ODD_DOMAIN"; do
    u="${pair%%:*}" d="${pair#*:}"
    printf '<VirtualHost *:80>\n  ServerName %s\n  ServerAlias www.%s\n  DocumentRoot /home/%s/public_html\n  <Directory /home/%s/public_html>\n    AllowOverride All\n    Require all granted\n  </Directory>\n</VirtualHost>\n' "$d" "$d" "$u" "$u"
  done
  echo "CONF"
  # Databases and users as cPanel makes them: prefixed, a grant on the
  # escaped name, mysql_native_password.
  echo "mysql <<'SQL'"
  echo "CREATE DATABASE ${SHOP}_wp; CREATE USER '${SHOP}_wpu'@'localhost' IDENTIFIED BY '$SHOP_PW'; GRANT ALL PRIVILEGES ON \`${SHOP}\\_wp\`.* TO '${SHOP}_wpu'@'localhost';"
  echo "CREATE DATABASE ${STAFF}_db; CREATE USER '${STAFF}_u'@'localhost' IDENTIFIED BY '$STAFF_PW'; GRANT ALL PRIVILEGES ON \`${STAFF}\\_db\`.* TO '${STAFF}_u'@'localhost';"
  echo "CREATE DATABASE ${TRIG}_app; CREATE USER '${TRIG}_appu'@'localhost' IDENTIFIED BY '$TRIG_PW'; GRANT ALL PRIVILEGES ON \`${TRIG}\\_app\`.* TO '${TRIG}_appu'@'localhost';"
  echo "CREATE TABLE ${TRIG}_app.orders (id INT PRIMARY KEY, total INT); CREATE TABLE ${TRIG}_app.audit (id INT);"
  echo "CREATE TRIGGER ${TRIG}_app.orders_audit AFTER INSERT ON ${TRIG}_app.orders FOR EACH ROW INSERT INTO ${TRIG}_app.audit VALUES (NEW.id);"
  echo "SQL"
  echo "httpd -k graceful"
} > "$WORK/standin-setup.sh"
podman cp "$WORK/standin-setup.sh" "$CTR:/root/standin-setup.sh"
check "the stand-in's four accounts, sites and databases are made" in_ctr "bash /root/standin-setup.sh"
in_ctr "rm -f /root/standin-setup.sh"
# WP-CLI unpacks the WordPress archive in memory: PHP's default 128M runs out.
WPRUN="php -d memory_limit=512M /usr/local/bin/wp-cli.phar --no-color"
wp() { in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- $WPRUN $*"; }
# WordPress 7.1.5, the current release on 2026-11-24, whose Akismet
# .htaccess the converter's test pins.
wp "core download --version=7.1.5 --quiet" >/dev/null 2>&1
# WordPress ships Akismet with an .htaccess of access rules (deny all, a
# <FilesMatch> allow-list, in Apache 2.2 and 2.4 branches). It stays: the
# converter must carry it to OpenLiteSpeed.
AKISMET="/home/$SHOP/public_html/wp-content/plugins/akismet"
check "the stand-in WordPress keeps the stock Akismet .htaccess (deny all, <FilesMatch>, both branches)" in_ctr "grep -q 'Require all denied' $AKISMET/.htaccess && grep -q 'Deny from all' $AKISMET/.htaccess && grep -q '<FilesMatch' $AKISMET/.htaccess"
echo "  Akismet $(in_ctr "sed -n 's/^ \* Version: //p' $AKISMET/akismet.php" 2>/dev/null), .htaccess sha256 $(in_ctr "sha256sum $AKISMET/.htaccess" 2>/dev/null | cut -d' ' -f1) (the converter's test pins WordPress 7.1.5's: 63553e7f...)"
podman cp "$WORK/shop.pw" "$CTR:/root/shop.pw"
in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- $WPRUN config create --dbname=${SHOP}_wp --dbuser=${SHOP}_wpu --prompt=dbpass < /root/shop.pw && rm -f /root/shop.pw" >/dev/null 2>&1
secret > "$WORK/admin.pw"
podman cp "$WORK/admin.pw" "$CTR:/root/admin.pw"
in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- $WPRUN core install --url=http://$SHOP_DOMAIN --title='$TITLE' --admin_user=standin --admin_email=standin@proof.test --skip-email --prompt=admin_password < /root/admin.pw && rm -f /root/admin.pw" >/dev/null 2>&1
wp "post create --post_title='Moved with Sifruno' --post_status=publish" >/dev/null 2>&1
# WordPress's own rewrite block, and a rewrite deny OpenLiteSpeed honours.
in_ctr "cat > /home/$SHOP/public_html/.htaccess <<'HT'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php\$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
HT
chown -R $SHOP:$SHOP /home/$SHOP/public_html; chgrp apache /home/$SHOP/public_html
find /home/$SHOP/public_html -mindepth 1 -type d -exec chmod 0755 {} +; find /home/$SHOP/public_html -type f -exec chmod 0644 {} +"
in_ctr "echo '*/15 * * * * php /home/$SHOP/public_html/wp-cron.php >/dev/null 2>&1' | crontab -u $SHOP -"
# staff: a password folder (the password file outside public_html, as
# cPanel's Directory Privacy keeps it, with a subfolder and a PHP page in
# it), a folder closed with Apache 2.2's Deny from all, a folder open to
# 127.0.0.2 only and one closed to it only (this server's copy is asked
# from 127.0.0.2 and 127.0.0.1; the old server sees neither), and root
# rewrite rules into the closed folders, which must not open them.
in_ctr "set -e; install -d -o $STAFF -g $STAFF -m 0755 /home/$STAFF/public_html/private /home/$STAFF/public_html/private/sub /home/$STAFF/public_html/backups /home/$STAFF/public_html/office /home/$STAFF/public_html/lobby
install -d -o $STAFF -g apache -m 0750 /home/$STAFF/.htpasswds /home/$STAFF/.htpasswds/public_html /home/$STAFF/.htpasswds/public_html/private
echo '<?php echo \"Staff site\";' > /home/$STAFF/public_html/index.php
echo 'Payroll' > /home/$STAFF/public_html/private/index.html
echo 'Payroll archive' > /home/$STAFF/public_html/private/sub/index.html
echo '<?php echo \"Payroll from PHP\";' > /home/$STAFF/public_html/private/report.php
printf '# Directory Privacy\nstaff:%s\n' \"\$(openssl passwd -apr1 '$HT_PW')\" > /home/$STAFF/.htpasswds/public_html/private/passwd
printf 'AuthType Basic\nAuthName \"Staff area\"\nAuthUserFile /home/$STAFF/.htpasswds/public_html/private/passwd\nRequire valid-user\n' > /home/$STAFF/public_html/private/.htaccess
printf 'Order Deny,Allow\nDeny from all\n' > /home/$STAFF/public_html/backups/.htaccess
echo 'dump' > /home/$STAFF/public_html/backups/backup.sql
printf 'Order Deny,Allow\nDeny from all\nAllow from 127.0.0.2\n' > /home/$STAFF/public_html/office/.htaccess
echo 'Office' > /home/$STAFF/public_html/office/index.html
printf 'Order Allow,Deny\nAllow from all\nDeny from 127.0.0.2\n' > /home/$STAFF/public_html/lobby/.htaccess
echo 'Lobby' > /home/$STAFF/public_html/lobby/index.html
printf 'RewriteEngine On\nRewriteRule ^pub/(.*)\$ /private/\$1 [L]\nRewriteRule ^old-backups/(.*)\$ /backups/\$1 [L]\n' > /home/$STAFF/public_html/.htaccess
chown -R $STAFF:$STAFF /home/$STAFF/public_html; chgrp apache /home/$STAFF/public_html
chown $STAFF:apache /home/$STAFF/.htpasswds/public_html/private/passwd; chmod 0640 /home/$STAFF/.htpasswds/public_html/private/passwd"
# odd: a directive the converter does not know.
in_ctr "set -e; echo 'Odd site' > /home/$ODD/public_html/index.html; install -d -o $ODD -g apache -m 0750 /home/$ODD/public_html/tools
printf 'Deny from all\nSifrunoProofUnknown On\n' > /home/$ODD/public_html/tools/.htaccess
chown -R $ODD:apache /home/$ODD/public_html"
in_ctr "echo '<?php echo \"Orders\";' > /home/$TRIG/public_html/index.php; chown -R $TRIG:apache /home/$TRIG/public_html"
in_ctr "set -e; printf '%s\n' '$ROOT_MARK' > /root/standin-secret.txt; chmod 0600 /root/standin-secret.txt
printf '%s\n' '$ROOT_MARK' > /root/standin-linked.txt; chmod 0600 /root/standin-linked.txt
ln /root/standin-linked.txt /home/$HARD/public_html/linked.txt
echo '<?php echo \"Hard\";' > /home/$HARD/public_html/index.php; chown $HARD:apache /home/$HARD/public_html/index.php
install -d -o $RACE -g apache -m 0750 /home/$RACE/public_html/assets
echo '<?php echo \"Race\";' > /home/$RACE/public_html/index.php; echo 'a' > /home/$RACE/public_html/assets/a.css
chown $RACE:apache /home/$RACE/public_html/index.php /home/$RACE/public_html/assets/a.css"

# The cPanel API stand-ins: the documented JSON shapes for these accounts.
cat > "$WORK/whmapi1" <<'STUB'
#!/bin/bash
# STAND-IN for cPanel's whmapi1 in the migration proof: not cPanel. It
# prints the JSON shapes cPanel's public API documentation gives, for the
# accounts in /etc/standin-accounts (user domain per line).
fn="$2"; arg="${3#domain=}"
php=$(php -r 'echo PHP_MAJOR_VERSION.PHP_MINOR_VERSION;')
case "$fn" in
listaccts)
  sep=""; printf '{"data":{"acct":['
  while read -r u d; do
    used=$(du -sm "/home/$u" | cut -f1)
    printf '%s{"user":"%s","domain":"%s","diskused":"%sM","disklimit":"unlimited","suspended":0,"partition":"home","plan":"default"}' "$sep" "$u" "$d" "$used"; sep=,
  done < /etc/standin-accounts
  printf ']},"metadata":{"command":"listaccts","reason":"OK","result":1,"version":1}}\n' ;;
domainuserdata)
  while read -r u d; do
    [ "$d" = "$arg" ] && printf '{"data":{"userdata":{"documentroot":"/home/%s/public_html","servername":"%s","serveralias":"www.%s","user":"%s","homedir":"/home/%s","ip":"10.0.0.1","port":80}},"metadata":{"command":"domainuserdata","result":1,"reason":"Obtained userdata.","version":1}}\n' "$u" "$d" "$d" "$u" "$u" && exit 0
  done < /etc/standin-accounts
  exit 1 ;;
php_get_vhost_versions)
  sep=""; printf '{"data":{"versions":['
  while read -r u d; do
    printf '%s{"account":"%s","vhost":"%s","version":"ea-php%s","documentroot":"/home/%s/public_html","homedir":"/home/%s","main_domain":1,"php_fpm":1}' "$sep" "$u" "$d" "$php" "$u" "$u"; sep=,
  done < /etc/standin-accounts
  printf ']},"metadata":{"command":"php_get_vhost_versions","reason":"OK","result":1,"version":1}}\n' ;;
*) echo "stand-in whmapi1: $fn is not part of the proof" >&2; exit 1 ;;
esac
STUB
cat > "$WORK/uapi" <<'STUB'
#!/bin/bash
# STAND-IN for cPanel's uapi in the migration proof: not cPanel. It prints
# the JSON shapes cPanel's public API documentation gives for Mysql
# list_databases and list_users, read from this container's MariaDB.
user="${2#--user=}"; fn="$3 $4"
q() { mysql -N -B -e "$1"; }
sep=""
case "$fn" in
"Mysql list_databases")
  printf '{"apiversion":3,"func":"list_databases","module":"Mysql","result":{"data":['
  for db in $(q "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE '${user}\\_%'"); do
    users=$(q "SELECT DISTINCT CONCAT('\"',User,'\"') FROM mysql.db WHERE REPLACE(Db,'\\\\','')='$db'" | paste -sd,)
    printf '%s{"database":"%s","disk_usage":0,"users":[%s]}' "$sep" "$db" "$users"; sep=,
  done
  printf '],"errors":null,"messages":null,"metadata":{"transformed":1},"status":1,"warnings":null}}\n' ;;
"Mysql list_users")
  printf '{"apiversion":3,"func":"list_users","module":"Mysql","result":{"data":['
  for u in $(q "SELECT User FROM mysql.user WHERE User LIKE '${user}\\_%' AND Host='localhost'"); do
    printf '%s{"user":"%s","shortuser":"%s","databases":[]}' "$sep" "$u" "${u#${user}_}"; sep=,
  done
  printf '],"errors":null,"messages":null,"metadata":{"transformed":1},"status":1,"warnings":null}}\n' ;;
*) echo "stand-in uapi: $fn is not part of the proof" >&2; exit 1 ;;
esac
STUB
printf '%s %s\n' "$SHOP" "$SHOP_DOMAIN" "$STAFF" "$STAFF_DOMAIN" "$TRIG" "$TRIG_DOMAIN" "$RACE" "$RACE_DOMAIN" "$HARD" "$HARD_DOMAIN" "$ODD" "$ODD_DOMAIN" > "$WORK/accounts"
in_ctr "install -d -m 0755 /usr/local/cpanel/bin"
podman cp "$WORK/whmapi1" "$CTR:/usr/local/cpanel/bin/whmapi1"
podman cp "$WORK/uapi" "$CTR:/usr/local/cpanel/bin/uapi"
podman cp "$WORK/accounts" "$CTR:/etc/standin-accounts"
in_ctr "chmod 0755 /usr/local/cpanel/bin/whmapi1 /usr/local/cpanel/bin/uapi"
check "the stand-in whmapi1 prints listaccts JSON for the six accounts" bash -c "podman exec $CTR /usr/local/cpanel/bin/whmapi1 --output=json listaccts | python3 -c 'import json,sys; assert len(json.load(sys.stdin)[\"data\"][\"acct\"]) == 6'"
# The old site is reached by its domain, as DNS would reach it.
for d in "$SHOP_DOMAIN" "$STAFF_DOMAIN" "$TRIG_DOMAIN" "$RACE_DOMAIN" "$HARD_DOMAIN" "$ODD_DOMAIN"; do echo "$CIP $d www.$d # sifruno-migrate-proof-$RUNID" >> /etc/hosts; done
check "the old WordPress site answers with its title" bash -c "curl -s http://$SHOP_DOMAIN/ | grep -q '$TITLE'"
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
check "the old staff site closes /private/ with 401" test "$(status "http://$STAFF_DOMAIN/private/")" = 401
check "the old staff site opens /private/ with the password (200)" test "$(status -u "staff:$HT_PW" "http://$STAFF_DOMAIN/private/")" = 200
check "the old staff site denies /backups/backup.sql with 403" test "$(status "http://$STAFF_DOMAIN/backups/backup.sql")" = 403
check "the old staff site answers 401 for /pub/index.html, rewritten into /private/" test "$(status "http://$STAFF_DOMAIN/pub/index.html")" = 401
check "the old staff site answers 403 for /old-backups/backup.sql, rewritten into /backups/" test "$(status "http://$STAFF_DOMAIN/old-backups/backup.sql")" = 403
check "the old staff site closes /office/ to this server (403) and opens /lobby/ (200)" test "$(status "http://$STAFF_DOMAIN/office/")" = 403 -a "$(status "http://$STAFF_DOMAIN/lobby/")" = 200
check "the old WordPress denies Akismet's folder with 403" test "$(status "http://$SHOP_DOMAIN/wp-content/plugins/akismet/akismet.php")" = 403
check "the old WordPress serves Akismet's allow-listed akismet.css with 200" test "$(status "http://$SHOP_DOMAIN/wp-content/plugins/akismet/_inc/akismet.css")" = 200

echo
echo "## 3. Sign in, connect, confirm the host key"
# The access key goes in a file, never an argument.
python3 -c "import json,sys; print(json.dumps({'access_key': open(sys.argv[1]).read().strip()}))" "$DIR/state/operator/access.key" > "$WORK/login.json"
CSRF=""
call POST /api/v1/session/login "$WORK/login.json"
CSRF="$(json "$WORK/answer.json" "d['csrf_token']")"
check "the panel signs in with the server's access key" test "$code" = 200 -a -n "$CSRF"
connect() { # connect NAME: opens a source and leaves its id in $SRC
  call POST /api/v1/websites/migrations/sources "$(body open "{\"host\":\"$CIP\",\"port\":22}")"
  SRC="$(json "$WORK/answer.json" "d['source']['id']")"
  cp "$WORK/answer.json" "$WORK/source-$1.json"
}
connect shop
echo "  migration $SRC; key line ends $(json "$WORK/source-shop.json" "d['source']['key_line'].split()[-1]")"
check "connecting makes a key for this migration only" test -n "$SRC" -a -d "$STATE/migrate/$SRC"
check "its private key is root's, mode 0600, in a 0700 folder" test "$(stat -c '%U %a' "$STATE/migrate/$SRC/ssh_key" "$STATE/migrate/$SRC" 2>/dev/null | paste -sd ' ')" = "root 600 root 700"
call GET "/api/v1/websites/migrations/sources/$SRC/accounts"
check "the old server is not read before its host key is confirmed (422)" test "$code" = 422
call POST "/api/v1/websites/migrations/sources/$SRC/host-key" "$(body fp '{"fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}')"
check "a fingerprint the server did not offer is refused (422)" test "$code" = 422
pin() { # pin NAME: confirms the fingerprint the stand-in's own key has
  local fp
  fp="$(in_ctr "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" | awk '{print $2}')"
  call POST "/api/v1/websites/migrations/sources/$SRC/host-key" "$(body fp "{\"fingerprint\":\"$fp\"}")"
  pinned="$(json "$WORK/answer.json" "d['source']['pinned_fingerprint']")"
  [ "$code" = 200 ] && [ "$pinned" = "$fp" ]
}
check "the fingerprint ssh-keygen shows on the old server is confirmed" pin shop
check "known_hosts holds only that key, under the migration alias" bash -c "[ \$(wc -l < $STATE/migrate/$SRC/known_hosts) = 1 ] && grep -q '^sifruno-migration-source ssh-ed25519 ' $STATE/migrate/$SRC/known_hosts"
call GET "/api/v1/websites/migrations/sources/$SRC/accounts"
check "without the key line on the old server, the sign-in is refused (422)" test "$code" = 422
install_key() { in_ctr "$(json "$WORK/source-$1.json" "d['source']['install_command']")"; }
install_key shop
check "the admin's command adds one restricted key line to root's authorized_keys" in_ctr "grep -c ' sifruno-migration-$SRC\$' /root/.ssh/authorized_keys | grep -qx 1 && grep -q '^restrict ssh-ed25519 ' /root/.ssh/authorized_keys"
call GET "/api/v1/websites/migrations/sources/$SRC/accounts"
echo "  accounts listed: $(json "$WORK/answer.json" "' '.join(a['user'] for a in d['accounts'])")"
check "discovery lists the six accounts with whmapi1 listaccts" test "$(json "$WORK/answer.json" "len(d['accounts'])")" = 6

echo
echo "## 4. Move $SHOP_DOMAIN"
run_job() { # run_job USER: starts the move and waits for its end; JOB and $WORK/job.json
  call POST /api/v1/websites/migrations "$(body start "{\"source\":\"$SRC\",\"username\":\"$1\"}")"
  JOB="$(json "$WORK/answer.json" "d['job']['id']")"
  [ "$code" = 202 ] || echo "  start answered $code: $(head -c 400 "$WORK/answer.json")"
  for _ in $(seq 1 450); do
    call GET "/api/v1/websites/jobs/$JOB"
    cp "$WORK/answer.json" "$WORK/job.json"
    state="$(json "$WORK/job.json" "d['job']['state']")"
    [ "$state" != running ] && break
    sleep 2
  done
  echo "  job $JOB: $state"
  python3 -c "import json,sys; [print('    %-8s %-8s %s' % (s['name'], s['state'], s['message'][:150])) for s in json.load(open(sys.argv[1]))['job']['steps']]" "$WORK/job.json"
}
sample_start
run_job "$SHOP"
# The comparison runs after the copy; wait for it too.
for _ in $(seq 1 120); do
  [ "$(json "$WORK/job.json" "(d['job']['migration'].get('verify') or {}).get('running')")" = False ] && break
  sleep 2; call GET "/api/v1/websites/jobs/$JOB"; cp "$WORK/answer.json" "$WORK/job.json"
done
sample_stop
m() { json "$WORK/job.json" "d['job']['migration']$1"; }
check "the move succeeded" test "$state" = succeeded
check "the tier is Native (rewrite rules, and Akismet's access rules converted)" test "$(m "['tier']")" = native
echo "  converted: $(m "['converted']")"
check "the job names Akismet's .htaccess as converted" test "$(json "$WORK/job.json" "[x['file'] for x in d['job']['migration']['converted']]")" = "['wp-content/plugins/akismet/.htaccess']"
check "the account has the same name and /home/$SHOP/public_html" test "$(stat -c %U "/home/$SHOP/public_html" 2>/dev/null)" = "$SHOP"
src_sum="$(in_ctr "sha256sum /home/$SHOP/public_html/wp-config.php" | cut -d' ' -f1)"
dst_sum="$(sha256sum "/home/$SHOP/public_html/wp-config.php" 2>/dev/null | cut -d' ' -f1)"
check "wp-config.php arrived unchanged (same sha256) and is the site user's" test -n "$src_sum" -a "$src_sum" = "$dst_sum" -a "$(stat -c %U "/home/$SHOP/public_html/wp-config.php" 2>/dev/null)" = "$SHOP"
check "mail, .ssh and logs folders of the old home were left out" test ! -e "/home/$SHOP/mail" -a ! -e "/home/$SHOP/.ssh"
src_hash="$(in_ctr "mysql -N -e \"SELECT authentication_string FROM mysql.user WHERE User='${SHOP}_wpu' AND Host='localhost'\"")"
dst_hash="$(mysql --protocol=socket -uroot -N -e "SELECT authentication_string FROM mysql.user WHERE User='${SHOP}_wpu' AND Host='localhost'" 2>/dev/null)"
check "the database user ${SHOP}_wpu has the same password hash as on the old server" test -n "$src_hash" -a "$src_hash" = "$dst_hash"
src_posts="$(in_ctr "mysql -N -e 'SELECT COUNT(*) FROM ${SHOP}_wp.wp_posts'")"
dst_posts="$(mysql --protocol=socket -uroot -N -e "SELECT COUNT(*) FROM ${SHOP}_wp.wp_posts" 2>/dev/null)"
check "the database ${SHOP}_wp has the same rows (wp_posts $src_posts = $dst_posts)" test -n "$src_posts" -a "$src_posts" = "$dst_posts"
check "the site's own user signs in to its database with the old password (wp-config unchanged)" bash -c "mysql --protocol=socket -u${SHOP}_wpu -p\"\$(cat $WORK/shop.pw)\" -N -e 'SELECT 1' ${SHOP}_wp 2>/dev/null | grep -qx 1"
account="$(json "$WORK/job.json" "d['job']['result']['account_id']")"
vhconf="$LSWS/conf/vhosts/sifruno-u${account:0:31}/vhconf.conf"
check "the copy runs PHP ${PHPXY:0:1}.${PHPXY:1} (lsphp$PHPXY), the old site's version" grep -q "lsphp$PHPXY/bin/lsphp" "$vhconf"
check "the vhost has Akismet's folder as a regex context closed to all" grep -q '^context exp:(?s)^/wp-content/plugins/akismet/(?!' "$vhconf"
new() { status -H "Host: $1" "http://127.0.0.1$2" "${@:3}"; }
for path in /wp-content/plugins/akismet/ /wp-content/plugins/akismet/akismet.php /wp-content/plugins/akismet/readme.txt /wp-content/plugins/akismet/_inc/ /wp-content/plugins/akismet/akismet.php/akismet.css; do
  check "the copy answers 403 for $path, as the old site" test "$(new "$SHOP_DOMAIN" "$path")" = 403
done
for path in /wp-content/plugins/akismet/_inc/akismet.css /wp-content/plugins/akismet/_inc/akismet-frontend.js /wp-content/plugins/akismet/_inc/img/logo-a-2x.png; do
  check "the copy answers 200 for the allow-listed $path, as the old site ($(status "http://$SHOP_DOMAIN$path"))" test "$(new "$SHOP_DOMAIN" "$path")" = 200
done
echo "  probes: $(m "['probes']")"
check "verify checked Akismet's closed folder and its open files, all passing" test "$(m "['verify']['probes_fail']")" = 0 -a "$(m "['verify']['probes_pass']")" -ge 2
# D-0001: the stand-in's Apache read this site through the group alone
# (0640 files, 0750 folders, group apache). The copy keeps those modes with
# the site's own group, and this server's web server reads them through one
# ACL entry each; the home and public_html keep GrantWebAccess's own.
css="/home/$SHOP/public_html/wp-content/plugins/akismet/_inc/akismet.css"
check "a moved 0640 file of group apache keeps its mode, has the site's group, and ${ols_user:-nobody} reads it through its ACL" bash -c "[ \"\$(stat -c '%a %G' $css)\" = '640 $SHOP' ] && getfacl -p $css 2>/dev/null | grep -qx 'user:${ols_user:-nobody}:r--' && getfacl -p $css 2>/dev/null | grep -qx 'mask::r--'"
check "a moved 0750 folder of group apache keeps its mode, and ${ols_user:-nobody} reads and enters it through its ACL" bash -c "[ \"\$(stat -c '%a' /home/$SHOP/public_html/wp-content)\" = 750 ] && getfacl -p /home/$SHOP/public_html/wp-content 2>/dev/null | grep -qx 'user:${ols_user:-nobody}:r-x'"
check "the home and public_html keep the web server's own ACL entries (--x, r-x)" bash -c "getfacl -p /home/$SHOP 2>/dev/null | grep -qx 'user:${ols_user:-nobody}:--x' && getfacl -p /home/$SHOP/public_html 2>/dev/null | grep -qx 'user:${ols_user:-nobody}:r-x'"
# D-0002: below the closed Akismet folder verify also asks for its first
# subfolder, expecting 403.
check "verify probed Akismet's _inc/ subfolder as closed (403)" test "$(json "$WORK/job.json" "[p['kind'] for p in d['job']['migration']['probes'] if p['path'] == '/wp-content/plugins/akismet/_inc/']")" = "['deny']"
check "the scheduled job arrived in the site user's crontab" grep -q "wp-cron.php" "/var/spool/cron/$SHOP"
page="$(curl -s -H "Host: $SHOP_DOMAIN" http://127.0.0.1/)"
check "the preview (this server, the site's Host header) serves the site's title" grep -q "$TITLE" <<<"$page"
check "the preview serves the moved post" bash -c "curl -s -H 'Host: $SHOP_DOMAIN' 'http://127.0.0.1/?s=Moved' | grep -q 'Moved with Sifruno'"
echo "  verify: $(m "['verify']['verdict']")"
echo "  pages $(m "['verify']['pages_compared']") compared, $(m "['verify']['pages_pass']") pass, $(m "['verify']['pages_fail']") fail; notes: $(m "['notes']")"
check "verify ran and found no difference (cutover allowed by verify)" test "$(m "['verify']['cutover_allowed']")" = True
gate="$(m "['gate']")"
if [ "$gate" = closed ]; then
  # Only notes (such as a PHP version this server maps) close it; the
  # proof accepts them on purpose, as an admin would, with a reason.
  call POST "/api/v1/websites/migrations/$JOB/accept" "$(body accept '{"reason":"Proof run: the notes were read and accepted"}')"
  cp "$WORK/answer.json" "$WORK/job.json"; gate="$(m "['gate']")"
  check "the accepted red lines are in the activity log with the reason" bash -c "python3 -c \"import json; a=json.load(open('$WORK/job.json'))['job']['migration']['activity']; assert any('Proof run' in x['what'] for x in a)\""
fi
check "the cutover gate is open (gate: $gate)" test "$gate" = open -o "$gate" = accepted
call POST "/api/v1/websites/migrations/$JOB/ready" "$(body ready '{}')"
cp "$WORK/answer.json" "$WORK/job.json"
echo "  DNS records: $(m "['dns']")"
check "marked ready, the panel names A records for the domain and www at $VMIP" test "$(m "['dns'][0]['value']")" = "$VMIP" -a "$(m "['gate']")" = ready
check "the migration key is gone from the old server's authorized_keys" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"
check "and from this server" test ! -e "$STATE/migrate/$SRC"
check "the job says the old server refused the key afterwards" test "$(m "['key_removed']")" = True
check "no password or hash was in any process's arguments during the move" bash -c "! grep -qF -e \"$(cat "$WORK/shop.pw")\" -e '$src_hash' $WORK/ps-samples.txt"
check "the job record holds no password or hash" bash -c "! grep -qF -e \"$(cat "$WORK/shop.pw")\" -e '$src_hash' $DIR/state/wizard/jobs.json"
check "the panel lists the moved site under Websites" bash -c "curl -s -b $JAR $API/api/v1/websites/sites | grep -q '\"domain\":\"$SHOP_DOMAIN\"'"

echo
echo "## 5. $STAFF_DOMAIN: a password folder, a closed folder and two address lists move, converted"
connect staff; pin staff >/dev/null 2>&1; install_key staff
run_job "$STAFF"
for _ in $(seq 1 120); do
  [ "$(json "$WORK/job.json" "(d['job']['migration'].get('verify') or {}).get('running')")" = False ] && break
  sleep 2; call GET "/api/v1/websites/jobs/$JOB"; cp "$WORK/answer.json" "$WORK/job.json"
done
echo "  converted: $(m "['converted']")"
check "the move succeeded (Native: four folders converted, the root rewrite rules kept)" test "$state" = succeeded -a "$(m "['tier']")" = native
check "the job names the four converted .htaccess files" test "$(json "$WORK/job.json" "len(d['job']['migration']['converted'])")" = 4
staff_account="$(json "$WORK/job.json" "d['job']['result']['account_id']")"
staff_site="u${staff_account:0:31}"
staff_vhconf="$LSWS/conf/vhosts/sifruno-$staff_site/vhconf.conf"
# A realm's file is numbered by its folder's place among the site's
# protected folders: /private/ is the fourth here.
realm="$(sed -n "s|^ *location  *\(/var/lib/sifruno-realms/$staff_site/realm[0-9]*\.htpasswd\)\$|\1|p" "$staff_vhconf" 2>/dev/null | head -1)"
realm="${realm:-/var/lib/sifruno-realms/$staff_site/none}"
check "the vhost has a realm whose user file is outside the home" grep -q "location  *$realm\$" "$staff_vhconf"
check "the realm file is root's, 0640, readable by the web server user ($ols_user) through its ACL" bash -c "[ \"\$(stat -c '%U:%G %a' $realm)\" = 'root:root 640' ] && getfacl -p $realm 2>/dev/null | grep -qx 'user:${ols_user:-nobody}:r--' && getfacl -p $realm 2>/dev/null | grep -qx 'group::---'"
check "the realm file holds the old user and hash, comments left out" bash -c "[ \"\$(cut -d: -f1 $realm)\" = staff ] && grep -q '^staff:\\\$apr1\\\$' $realm && ! grep -q '#' $realm"
check "the realm's folder is root's, 0750" test "$(stat -c '%U %a' "$(dirname "$realm")")" = "root 750"
check "the copy answers 401 for /private/ without the password" test "$(new "$STAFF_DOMAIN" /private/)" = 401
check "the copy answers 401 for /private/sub/ without the password" test "$(new "$STAFF_DOMAIN" /private/sub/)" = 401
check "the copy answers 401 for /private/ with a wrong password" test "$(new "$STAFF_DOMAIN" /private/ -u staff:wrong-password)" = 401
check "the copy answers 200 for /private/ with the password, and serves the page" bash -c "curl -s -u 'staff:$HT_PW' -H 'Host: $STAFF_DOMAIN' http://127.0.0.1/private/ | grep -qx Payroll"
check "the copy answers 200 for /private/sub/ with the password" test "$(new "$STAFF_DOMAIN" /private/sub/ -u "staff:$HT_PW")" = 200
check "the copy runs PHP in the password folder with the password" bash -c "curl -s -u 'staff:$HT_PW' -H 'Host: $STAFF_DOMAIN' http://127.0.0.1/private/report.php | grep -qx 'Payroll from PHP'"
check "the copy answers 403 for /backups/ and /backups/backup.sql" test "$(new "$STAFF_DOMAIN" /backups/)" = 403 -a "$(new "$STAFF_DOMAIN" /backups/backup.sql)" = 403
# Other spellings of the same paths answer exactly as the folder does. A
# folder named without its slash gets OpenLiteSpeed's redirect to the
# slash form first (which then answers 401 or 403); a name in another case
# is another, missing, path on this filesystem, as on the old server.
spelled() { # spelled PATH WANT
  local got
  got="$(status --path-as-is -H "Host: $STAFF_DOMAIN" "http://127.0.0.1$1")"
  check "the copy answers $2 for $1 without the password (got $got)" test "$got" = "$2"
}
for path in //private/index.html /./private/index.html /x/../private/index.html /%70rivate/index.html /private%2Findex.html \
  /%2e/private/index.html /private/%2e%2e/private/index.html /private/index.html/ /private/sub/ /private//index.html; do
  spelled "$path" 401
done
for path in //backups/backup.sql /%62ackups/backup.sql /backups/./backup.sql /backups/%2e/backup.sql /backups/backup.sql/ /backups//backup.sql; do
  spelled "$path" 403
done
spelled /private 301
check "and that redirect names /private/" bash -c "curl -s -o /dev/null -w '%{redirect_url}' -H 'Host: $STAFF_DOMAIN' http://127.0.0.1/private | grep -q '/private/\$'"
spelled /backups 301
spelled /PRIVATE/index.html 404
spelled /Backups/backup.sql 404
# A rewrite from the root .htaccess into a closed folder is checked again
# in that folder's context.
check "the copy answers 401 for /pub/index.html, rewritten into /private/" test "$(new "$STAFF_DOMAIN" /pub/index.html)" = 401
check "the copy does not show /private/ content through /pub/" bash -c "! curl -s -H 'Host: $STAFF_DOMAIN' http://127.0.0.1/pub/index.html | grep -q Payroll"
check "the copy answers 200 for /pub/index.html with the password" test "$(new "$STAFF_DOMAIN" /pub/index.html -u "staff:$HT_PW")" = 200
check "the copy answers 403 for /old-backups/backup.sql, rewritten into /backups/" test "$(new "$STAFF_DOMAIN" /old-backups/backup.sql)" = 403
# Address lists, asked from two loopback addresses (curl --interface).
from() { status --interface "$1" -H "Host: $STAFF_DOMAIN" "http://127.0.0.1$2"; }
check "the copy opens /office/ to 127.0.0.2, its one allowed address (200)" test "$(from 127.0.0.2 /office/)" = 200
check "the copy closes /office/ to 127.0.0.1 (403)" test "$(from 127.0.0.1 /office/)" = 403
check "the copy closes /lobby/ to 127.0.0.2, its one denied address (403)" test "$(from 127.0.0.2 /lobby/)" = 403
check "the copy opens /lobby/ to 127.0.0.1 (200)" test "$(from 127.0.0.1 /lobby/)" = 200
check "the vhost lists the address without a prefix length (OpenLiteSpeed refuses /32)" grep -q '^ *allow  *127\.0\.0\.2$' "$staff_vhconf"
# IPv4 clients reach OpenLiteSpeed as IPv4 addresses, never as ::ffff:
# forms an IPv4 list would miss: port 80 has no IPv6 listener.
ss -Hltn 'sport = :80' > "$WORK/listen80.txt" 2>/dev/null
echo "  port 80 listeners: $(paste -sd ' ' "$WORK/listen80.txt" | tr -s ' ')"
check "port 80 listens on IPv4 only (0.0.0.0:80, no [::]:80 or *:80)" bash -c "grep -q '0\.0\.0\.0:80 ' $WORK/listen80.txt && ! grep -Eq '\[::\]:80 |[[:space:]]\*:80 ' $WORK/listen80.txt"
check "a request over IPv6 to port 80 is not answered" bash -c "! curl -s -o /dev/null -g --max-time 5 -H 'Host: $STAFF_DOMAIN' 'http://[::1]/lobby/'"
check "the site's own page is open (200)" test "$(new "$STAFF_DOMAIN" /)" = 200
echo "  probes: $(m "['probes']"); verify: $(m "['verify']['verdict']")"
check "verify probed /private/ (401) and /backups/ (403)" test "$(json "$WORK/job.json" "sorted((p['path'], p['kind']) for p in d['job']['migration']['probes'] if p['path'] in ('/private/', '/backups/'))")" = "[('/backups/', 'deny'), ('/private/', 'auth')]"
# D-0002: verify also asks for the password folder's first subfolder
# (401), and checks each address-list folder against the status its rule
# gives each side's client address: the stand-in's view of this server,
# which its sshd reported to the plan, and the copy's 127.0.0.1.
seen="$(m ".get('client_address')")"
apache_saw="$(in_ctr "awk '/Sifruno-MigrationVerify/ {ip=\$1} END {print ip}' /var/log/httpd/access_log")"
check "the job keeps the address the old server's sshd saw this server come from ($seen), the one its Apache saw verify come from ($apache_saw)" test -n "$seen" -a "$seen" = "$apache_saw"
check "verify probed /private/sub/ (auth) and /lobby/ and /office/ by their address lists" test "$(json "$WORK/job.json" "sorted((p['path'], p['kind'], p.get('hosts')) for p in d['job']['migration']['probes'] if p['path'] in ('/private/sub/', '/lobby/', '/office/'))")" = "[('/lobby/', 'hosts', 'except'), ('/office/', 'hosts', 'only'), ('/private/sub/', 'auth', None)]"
echo "  verify problems: $(m "['verify'].get('problems')")"
sub_ok="$([ "$(new "$STAFF_DOMAIN" /private/sub/)" = 401 ] && echo yes || echo no)"
lobby_ok="$([ "$(from 127.0.0.1 /lobby/)" = 200 ] && echo yes || echo no)"
office_ok="$([ "$(from 127.0.0.1 /office/)" = 403 ] && echo yes || echo no)"
check "verify allows cutover only if the copy answers /private/sub/ 401, /lobby/ 200 and /office/ 403 to 127.0.0.1 (copy: $sub_ok $lobby_ok $office_ok)" bash -c "[ '$sub_ok $lobby_ok $office_ok' = 'yes yes yes' ] || [ '$(m "['verify']['cutover_allowed']")' = False ]"
check "a folder the copy answers against its address list is named in verify's plain problems" bash -c "[ '$lobby_ok' = yes ] || grep -qF '/lobby/' <<<\"\$1\"" _ "$(m "['verify'].get('problems')")"
check "with the copy right, verify passes all five folder checks" bash -c "[ '$sub_ok $lobby_ok $office_ok' != 'yes yes yes' ] || [ '$(m "['verify']['probes_pass']") $(m "['verify']['probes_fail']")' = '5 0' ]"
check "the key is removed after the move" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"

echo
echo "## 5b. $ODD_DOMAIN: a directive the converter does not know is refused"
connect odd; pin odd >/dev/null 2>&1; install_key odd
run_job "$ODD"
echo "  why: $(json "$WORK/job.json" "d['job']['error']['why']")"
echo "  technical: $(json "$WORK/job.json" "d['job']['error'].get('technical','')")"
check "the move stops at the old server's site, before anything is created" test "$state" = failed -a "$(json "$WORK/job.json" "d['job']['error']['step']")" = source
check "the reason names the directives this panel does not know" grep -q 'directives this panel does not know' "$WORK/job.json"
check "no account $ODD was created" bash -c "! getent passwd $ODD"
check "the key is removed after the refusal too" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"
check "no staging folder or migration folder is left" bash -c "[ -z \"\$(ls -A /var/lib/sifruno-restore 2>/dev/null)\" ] && [ ! -e $STATE/migrate/$SRC ]"

echo
echo "## 6. $TRIG_DOMAIN: a database with a trigger fails the copy, which is undone"
connect trig; pin trig >/dev/null 2>&1; install_key trig
run_job "$TRIG"
echo "  why: $(json "$WORK/job.json" "d['job']['error']['why']")"
check "the move fails at the database step" test "$state" = failed -a "$(json "$WORK/job.json" "d['job']['error']['step']")" = database
check "the account step is marked undone" test "$(json "$WORK/job.json" "[s['state'] for s in d['job']['steps'] if s['name']=='account'][0]")" = undone
check "the created account $TRIG is gone" bash -c "! getent passwd $TRIG && [ ! -e /home/$TRIG ]"
check "the created database and user are gone" test -z "$(mysql --protocol=socket -uroot -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${TRIG}_app' UNION SELECT 1 FROM mysql.user WHERE User='${TRIG}_appu'" 2>/dev/null)"
check "the key is removed after the failure too" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"

echo
echo "## 7. $RACE_DOMAIN: a folder swapped for a link to /root during the copy"
connect race; pin race >/dev/null 2>&1; install_key race
# The tenant swaps assets for a link to /root and back, as fast as it can,
# for the whole copy.
in_ctr "runuser -u $RACE -- bash -c 'cd /home/$RACE/public_html; while :; do mv assets assets.real 2>/dev/null; ln -sfn /root assets; rm -f assets; mv assets.real assets 2>/dev/null; done' >/dev/null 2>&1 &"
run_job "$RACE"
in_ctr "pkill -u $RACE -f 'while :'" >/dev/null 2>&1
echo "  ended $state; why: $(json "$WORK/job.json" "(d['job'].get('error') or {}).get('why', '')")"
# Three safe ends, by when the swap lands: the real folder is copied; the
# account cannot read /root through the link; or the link itself is copied
# and the check of the copied files refuses a folder reached through it.
check "the move finished, or stopped on what the account may not read or on the copied link" bash -c "[ $state = succeeded ] || grep -qe 'cannot be read by the account itself' -e 'a folder reached through a link, which the check does not follow' $WORK/job.json"
check "nothing of /root reached this server (homes, staging)" bash -c "! grep -rqsF '$ROOT_MARK' /home /var/lib/sifruno-restore"
check "the key is removed afterwards" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"

echo
echo "## 8. $HARD_DOMAIN: a hard link to a root-only file"
check "the stand-in tenant holds a hard link to a root-only file" in_ctr "[ \"\$(stat -c '%U %a %h' /home/$HARD/public_html/linked.txt)\" = 'root 600 2' ]"
connect hard; pin hard >/dev/null 2>&1; install_key hard
run_job "$HARD"
echo "  why: $(json "$WORK/job.json" "(d['job'].get('error') or {}).get('why', '')")"
check "the move stops on the file the account may not read" bash -c "[ $state = failed ] && grep -q 'cannot be read by the account itself' $WORK/job.json"
check "the root-only content is nowhere on this server" bash -c "! grep -rqsF '$ROOT_MARK' /home /var/lib/sifruno-restore"
check "the failed move removed the account $HARD" bash -c "! getent passwd $HARD"
check "the key is removed after the failure too" in_ctr "! grep -q 'sifruno-migration-$SRC' /root/.ssh/authorized_keys"

echo
echo "## 9. API tokens cannot move websites"
call POST /api/v1/session/tokens "$(body tok '{"name":"Proof token","expires_in_days":1}')"
token="$(json "$WORK/answer.json" "d['token']")"
printf 'Authorization: Bearer %s\n' "$token" > "$WORK/token.hdr"
tcode="$(curl -s -o "$WORK/answer.json" -w '%{http_code}' -H @"$WORK/token.hdr" -H 'Content-Type: application/json' --data "@$WORK/open.json" "$API/api/v1/websites/migrations/sources")"
check "a token's request to open a source is refused (403 token_not_allowed)" bash -c "[ $tcode = 403 ] && grep -q token_not_allowed $WORK/answer.json"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: every check passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
