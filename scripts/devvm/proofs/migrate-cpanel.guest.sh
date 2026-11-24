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
# the accounts this script makes. Three accounts:
#   shop<id>   WordPress whose .htaccess has only rewrite rules (Native):
#              the full path, from discovery to the DNS records
#   staff<id>  a password-protected folder (.htaccess + .htpasswd) and a
#              deny rule (Compat): refused before anything is created,
#              because OpenLiteSpeed would open the folder
#   trig<id>   a PHP site whose database has a trigger: the copy fails at
#              the database and the job removes what it created
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
SHOP="shop$RUNID" STAFF="staff$RUNID" TRIG="trig$RUNID"
SHOP_DOMAIN="$SHOP.proof.test" STAFF_DOMAIN="$STAFF.proof.test" TRIG_DOMAIN="$TRIG.proof.test"
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
echo "# accounts $SHOP, $STAFF, $TRIG; container $CTR from $IMAGE"

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
podman run -d --name "$CTR" --hostname cpanel-standin "$IMAGE" sleep infinity >/dev/null
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
  for u in "$SHOP" "$STAFF" "$TRIG"; do
    echo "useradd -m -d /home/$u $u; chmod 0711 /home/$u; install -d -o $u -g apache -m 0750 /home/$u/public_html"
  done
  echo "cat > /etc/httpd/conf.d/standin.conf <<'CONF'"
  for pair in "$SHOP:$SHOP_DOMAIN" "$STAFF:$STAFF_DOMAIN" "$TRIG:$TRIG_DOMAIN"; do
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
check "the stand-in's three accounts, sites and databases are made" in_ctr "bash /root/standin-setup.sh"
in_ctr "rm -f /root/standin-setup.sh"
wp() { in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- php /usr/local/bin/wp-cli.phar --no-color $*"; }
wp "core download --version=6.8.3 --quiet" >/dev/null 2>&1
# WordPress ships Akismet with an .htaccess of access rules (Require all
# denied, <FilesMatch>), which alone makes a site Compat. The Native path
# is shown without it; section 5 shows what Compat does.
in_ctr "rm -rf /home/$SHOP/public_html/wp-content/plugins/akismet"
check "the stand-in WordPress has no .htaccess with access rules (Akismet removed)" bash -c "[ -z \"\$(podman exec $CTR find /home/$SHOP/public_html -name .htaccess)\" ]"
podman cp "$WORK/shop.pw" "$CTR:/root/shop.pw"
in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- php /usr/local/bin/wp-cli.phar --no-color config create --dbname=${SHOP}_wp --dbuser=${SHOP}_wpu --prompt=dbpass < /root/shop.pw && rm -f /root/shop.pw" >/dev/null 2>&1
secret > "$WORK/admin.pw"
podman cp "$WORK/admin.pw" "$CTR:/root/admin.pw"
in_ctr "cd /home/$SHOP/public_html && runuser -u $SHOP -- php /usr/local/bin/wp-cli.phar --no-color core install --url=http://$SHOP_DOMAIN --title='$TITLE' --admin_user=standin --admin_email=standin@proof.test --skip-email --prompt=admin_password < /root/admin.pw && rm -f /root/admin.pw" >/dev/null 2>&1
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
chown -R $SHOP:apache /home/$SHOP/public_html; find /home/$SHOP/public_html -type d -exec chmod 0750 {} +; find /home/$SHOP/public_html -type f -exec chmod 0640 {} +"
in_ctr "echo '*/15 * * * * php /home/$SHOP/public_html/wp-cron.php >/dev/null 2>&1' | crontab -u $SHOP -"
# staff: a password folder (the password file outside public_html, as
# cPanel's Directory Privacy keeps it) and a deny rule.
in_ctr "set -e; install -d -o $STAFF -g apache -m 0750 /home/$STAFF/public_html/private /home/$STAFF/.htpasswds/public_html/private
echo '<?php echo \"Staff site\";' > /home/$STAFF/public_html/index.php
echo 'Payroll' > /home/$STAFF/public_html/private/index.html
printf 'staff:%s\n' \"\$(openssl passwd -apr1 '$HT_PW')\" > /home/$STAFF/.htpasswds/public_html/private/passwd
printf 'AuthType Basic\nAuthName \"Staff\"\nAuthUserFile /home/$STAFF/.htpasswds/public_html/private/passwd\nRequire valid-user\n' > /home/$STAFF/public_html/private/.htaccess
printf '<Files \"backup.sql\">\n  Require all denied\n</Files>\n' > /home/$STAFF/public_html/.htaccess
echo 'dump' > /home/$STAFF/public_html/backup.sql
chown -R $STAFF:apache /home/$STAFF; chmod 0711 /home/$STAFF"
in_ctr "echo '<?php echo \"Orders\";' > /home/$TRIG/public_html/index.php; chown -R $TRIG:apache /home/$TRIG/public_html"

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
printf '%s %s\n%s %s\n%s %s\n' "$SHOP" "$SHOP_DOMAIN" "$STAFF" "$STAFF_DOMAIN" "$TRIG" "$TRIG_DOMAIN" > "$WORK/accounts"
in_ctr "install -d -m 0755 /usr/local/cpanel/bin"
podman cp "$WORK/whmapi1" "$CTR:/usr/local/cpanel/bin/whmapi1"
podman cp "$WORK/uapi" "$CTR:/usr/local/cpanel/bin/uapi"
podman cp "$WORK/accounts" "$CTR:/etc/standin-accounts"
in_ctr "chmod 0755 /usr/local/cpanel/bin/whmapi1 /usr/local/cpanel/bin/uapi"
check "the stand-in whmapi1 prints listaccts JSON for the three accounts" bash -c "podman exec $CTR /usr/local/cpanel/bin/whmapi1 --output=json listaccts | python3 -c 'import json,sys; assert len(json.load(sys.stdin)[\"data\"][\"acct\"]) == 3'"
# The old site is reached by its domain, as DNS would reach it.
for d in "$SHOP_DOMAIN" "$STAFF_DOMAIN" "$TRIG_DOMAIN"; do echo "$CIP $d www.$d # sifruno-migrate-proof-$RUNID" >> /etc/hosts; done
check "the old WordPress site answers with its title" bash -c "curl -s http://$SHOP_DOMAIN/ | grep -q '$TITLE'"
check "the old staff site closes /private/ with 401" test "$(curl -s -o /dev/null -w '%{http_code}' "http://$STAFF_DOMAIN/private/")" = 401
check "the old staff site denies /backup.sql with 403" test "$(curl -s -o /dev/null -w '%{http_code}' "http://$STAFF_DOMAIN/backup.sql")" = 403

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
check "discovery lists the three accounts with whmapi1 listaccts" test "$(json "$WORK/answer.json" "len(d['accounts'])")" = 3

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
check "the tier is Native (.htaccess has rewrite rules only)" test "$(m "['tier']")" = native
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
echo "## 5. $STAFF_DOMAIN: password folder and deny rule (Compat) are refused"
connect staff; pin staff >/dev/null 2>&1; install_key staff
run_job "$STAFF"
echo "  why: $(json "$WORK/job.json" "d['job']['error']['why']")"
check "the move stops at the old server's site, before anything is created" test "$state" = failed -a "$(json "$WORK/job.json" "d['job']['error']['step']")" = source
check "the reason names the password-protected folders" grep -q 'password-protected folders' "$WORK/job.json"
check "no account $STAFF was created" bash -c "! getent passwd $STAFF"
check "no database ${STAFF}_db was created" test -z "$(mysql --protocol=socket -uroot -N -e "SHOW DATABASES LIKE '${STAFF}_db'" 2>/dev/null)"
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
echo "## 7. API tokens cannot move websites"
call POST /api/v1/session/tokens "$(body tok '{"name":"Proof token","expires_in_days":1}')"
token="$(json "$WORK/answer.json" "d['token']")"
printf 'Authorization: Bearer %s\n' "$token" > "$WORK/token.hdr"
tcode="$(curl -s -o "$WORK/answer.json" -w '%{http_code}' -H @"$WORK/token.hdr" -H 'Content-Type: application/json' --data "@$WORK/open.json" "$API/api/v1/websites/migrations/sources")"
check "a token's request to open a source is refused (403 token_not_allowed)" bash -c "[ $tcode = 403 ] && grep -q token_not_allowed $WORK/answer.json"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: every check passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
