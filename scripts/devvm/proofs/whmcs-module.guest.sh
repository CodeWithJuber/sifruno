#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh whmcs-module copies it in).
#   whmcs-module.guest.sh DIR DOMAIN
# Starts the broker, and the panel as sifpanel with throwaway state in DIR,
# also over HTTPS on 127.0.0.1 with the panel's own self-signed certificate.
# Makes an API token through the panel's session API with the access key, as
# Security > API tokens does, then runs the WHMCS module's functions with
# lsphp's PHP CLI against the real panel (whmcs-module.drive.php): create,
# suspend, unsuspend and terminate a WordPress website for DOMAIN. The session
# cookie, its CSRF token and the API token stay in 0600 files, never in a
# command's arguments or the transcript, and are deleted at the end.
set -uo pipefail

SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
PHP_CLI="$LSWS/lsphp83/bin/php"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

dir="${1:?usage: whmcs-module.guest.sh DIR DOMAIN}"
domain="${2:?usage: whmcs-module.guest.sh DIR DOMAIN}"
port="$(free_port)"
https_port="$(free_port)"
secrets="$dir/secrets"

echo "# guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"
echo "# $(rpm -q openlitespeed lsphp83 mariadb-server | paste -sd ' ')"
echo "# module PHP: $("$PHP_CLI" -r 'echo PHP_VERSION, " curl ", curl_version()["version"], " ", curl_version()["ssl_version"];' 2>&1)"
check "lsphp's PHP CLI has the curl and openssl extensions the module needs" \
  bash -c "'$PHP_CLI' -m | grep -qx curl && '$PHP_CLI' -m | grep -qx openssl"

ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  /opt/sifruno-proof/hostbroker --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker runs" test -S "$SOCKET"

cd "$dir" || exit 1
install -d -m 0755 whmcs && tar -xzf whmcs.tgz -C whmcs
chown -R sifpanel:sifpanel "$dir" && chmod 0755 sifruno
restorecon -R "$dir" 2>/dev/null
# No --acme-email: certificates are off, so the wizard skips https and the
# site serves over http. This proof is about the module, not certificates.
runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$port --sites-listen '' --state ./state --ui ./dist \
  --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf \
  --https-listen 127.0.0.1:$https_port --panel-host 127.0.0.1 > panel.log 2>&1 & echo \$! > panel.pid"
for _ in $(seq 1 90); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/v1/websites/sites")" != 000 ] && break
  sleep 2
done
check "the panel answers on 127.0.0.1:$port as sifpanel" bash -c "[ \"\$(ps -o user= -p \$(cat panel.pid))\" = sifpanel ]"
cp state/tls/panel-cert.pem whmcs/panel-cert.pem
echo "  panel certificate: $(openssl x509 -in whmcs/panel-cert.pem -noout -subject -ext subjectAltName 2>&1 | paste -sd ' ')"
check "over HTTPS on 127.0.0.1:$https_port the panel's certificate verifies and an unsigned request gets 401" \
  test "$(curl -s -o /dev/null -w '%{http_code}' --cacert whmcs/panel-cert.pem "https://127.0.0.1:$https_port/api/v1/websites/sites")" = 401

# The API token, as Security > API tokens makes it: a session opened with the
# access key on the server, then POST /api/v1/session/tokens with its CSRF token.
umask 077
install -d -m 0700 "$secrets"
origin="http://127.0.0.1:$port"
python3 -c 'import json, sys; print(json.dumps({"access_key": open(sys.argv[1]).read().strip()}))' state/operator/access.key \
  | curl -s -c "$secrets/cookies" -H "Origin: $origin" -H 'Content-Type: application/json' --data-binary @- "$origin/api/v1/session/login" \
  | python3 -c 'import json, sys; print("X-CSRF-Token: " + json.load(sys.stdin)["csrf_token"])' > "$secrets/csrf.header"
printf '{"name":"WHMCS proof","expires_in_days":1}' \
  | curl -s -b "$secrets/cookies" -H @"$secrets/csrf.header" -H "Origin: $origin" -H 'Content-Type: application/json' --data-binary @- "$origin/api/v1/session/tokens" \
  | python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["token"])' > "$secrets/token"
check "an API token was made through the panel's session API" grep -Eq '^sfr_[A-Za-z0-9_-]{43}$' "$secrets/token"

echo "## The module, with lsphp's PHP CLI, against the panel over HTTPS"
"$PHP_CLI" -d display_errors=stderr whmcs/whmcs-module.drive.php "$dir/whmcs" "$https_port" "$dir/whmcs/panel-cert.pem" "$secrets/token" "$domain"
driver=$?
fails=$((fails + driver))

jobs="$dir/state/wizard/jobs.json"
user="$(python3 -c "import json,sys; j=[x for x in json.load(open('$jobs'))['jobs'] if x['domain']=='$domain' and x['state']=='succeeded']; print(j[0]['username'] if j else '')" 2>/dev/null)"
echo "  hosting account the wizard made: ${user:-none}"
check "after TerminateAccount its Linux user is gone" bash -c "[ -n '$user' ] && ! getent passwd '$user'"
check "the panel's log does not hold the API token" bash -c "! grep -qF -f '$secrets/token' panel.log"

kill "$(cat panel.pid)" 2>/dev/null
rm -rf -- "$secrets"
exit "$fails"
