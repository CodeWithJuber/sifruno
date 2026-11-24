#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh wordpress-wizard copies it in).
#   wordpress-wizard.guest.sh start DIR PORT       start Pebble, the broker and the panel
#   wordpress-wizard.guest.sh check DIR DOMAIN     check the WordPress site the wizard made,
#                                                  LiteSpeed Cache included
#   wordpress-wizard.guest.sh check-php DIR DOMAIN check the PHP site the wizard made
# The panel runs as sifpanel, the broker's controller, with throwaway state
# in DIR, the broker socket and the MariaDB admin option file; it listens on
# 127.0.0.1:PORT only, and the host reaches it through an SSH forward. It
# gets the site's certificate from Pebble, Let's Encrypt's test CA, which
# provision.sh installs: Pebble's DNS answers 127.0.0.1 for every name, so
# Pebble validates HTTP-01 against this VM's OpenLiteSpeed on port 80.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
ACME_DIRECTORY=https://127.0.0.1:14000/dir
# The CA of Pebble's own HTTPS API, which the panel trusts for ACME only. It
# is not the root Pebble issues from: that one is new at every Pebble start
# and is saved per run as DIR/pebble-root.pem.
PEBBLE_API_CA=/etc/pebble/api-ca.pem
ACME_CHALLENGES=/var/lib/sifruno-acme
WPCLI=/usr/local/lib/sifruno/wp-cli.phar
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

# job_field JOBS DOMAIN KIND FIELD: a field of the succeeded job of that kind
# for the domain ("username", or "result.account_id").
job_field() {
  python3 - "$1" "$2" "$3" "$4" <<'PY' 2>/dev/null
import json, sys
path, domain, kind, field = sys.argv[1:5]
jobs = [j for j in json.load(open(path))["jobs"] if j["domain"] == domain and j["kind"] == kind and j["state"] == "succeeded"]
value = jobs[0] if jobs else {}
for key in field.split("."):
    value = value.get(key, "") if isinstance(value, dict) else ""
print(value)
PY
}

# cache_header URL [CURL ARGS...]: the X-LiteSpeed-Cache value of one
# request over https to this VM, trusting only this run's Pebble root.
cache_header() {
  local url="$1" host
  shift
  host="${url#https://}"
  host="${host%%/*}"
  curl -s -o /dev/null -D - --resolve "$host:443:127.0.0.1" --cacert "$dir/pebble-root.pem" "$@" "$url" |
    tr -d '\r' | awk -F': *' 'tolower($1)=="x-litespeed-cache"{print $2}'
}

# site_store ACCOUNT: the site's own LSCache store, named as olsweb names its
# vhost ("u" and the first 31 characters of the account ID).
site_store() { printf '%s/cachedata/sifruno-u%s' "$LSWS" "${1:0:31}"; }

case "${1:-}" in
  start)
    dir="$2"
    port="$3"
    echo "# guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"
    echo "# $(rpm -q openlitespeed lsphp83 mariadb-server | paste -sd ' ')"
    ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
    systemctl stop sifruno-broker-proof 2>/dev/null
    systemctl reset-failed sifruno-broker-proof 2>/dev/null
    systemd-run --quiet --unit sifruno-broker-proof --collect \
      "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
    check "the broker runs with the web operation on" test -S "$SOCKET"
    # A restart gives each run a new Pebble: a new issuing CA and no old orders.
    systemctl restart pebble-challtestsrv pebble
    for _ in $(seq 1 60); do curl -fs -o /dev/null --cacert "$PEBBLE_API_CA" "$ACME_DIRECTORY" && break; sleep 1; done
    check "Pebble serves its ACME directory at $ACME_DIRECTORY" curl -fs -o /dev/null --cacert "$PEBBLE_API_CA" "$ACME_DIRECTORY"
    check "Pebble's DNS answers 127.0.0.1 for any name" test "$(dig +short @127.0.0.1 -p 8053 any-name.proof.test A)" = 127.0.0.1
    check "the ACME challenge folder is sifpanel's, mode 0755" test "$(stat -c '%U %a' "$ACME_CHALLENGES" 2>/dev/null)" = "sifpanel 755"
    cd "$dir" || exit 1
    tar -xzf dist.tgz && tar -xzf state.tgz && chown -R sifpanel:sifpanel "$dir" && chmod 0755 sifruno
    # The check step trusts only this root for the site's certificate.
    curl -fsS --cacert "$PEBBLE_API_CA" -o pebble-root.pem https://127.0.0.1:15000/roots/0 && chown sifpanel:sifpanel pebble-root.pem
    echo "  Pebble issues from: $(openssl x509 -in pebble-root.pem -noout -subject 2>&1)"
    check "Pebble's root CA for this run is saved in $dir/pebble-root.pem" openssl x509 -in pebble-root.pem -noout
    restorecon -R "$dir" 2>/dev/null
    runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$port --sites-listen '' --state ./state --ui ./dist \
      --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf \
      --acme-email admin@proof.test --acme-directory $ACME_DIRECTORY --acme-ca-file $PEBBLE_API_CA > panel.log 2>&1 &"
    for _ in $(seq 1 90); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 2; done
    check "the panel answers on 127.0.0.1:$port as sifpanel" bash -c "curl -fs -o /dev/null http://127.0.0.1:$port/ && [ \"\$(ps -o user= -p \$(pgrep -x sifruno | head -1))\" = sifpanel ]"
    ;;
  check)
    dir="$2"
    domain="$3"
    jobs="$dir/state/wizard/jobs.json"
    user="$(python3 -c "import json,sys; j=[x for x in json.load(open('$jobs'))['jobs'] if x['domain']=='$domain' and x['state']=='succeeded']; print(j[0]['username'] if j else '')" 2>/dev/null)"
    echo "  account made by the wizard: ${user:-none}"
    check "the job file is the panel's and private (0600 in a 0700 folder)" bash -c \
      "[ \"\$(stat -c '%U %a' $jobs)\" = 'sifpanel 600' ] && [ \"\$(stat -c '%a' $(dirname "$jobs"))\" = 700 ]"
    check "the account's Linux user exists" getent passwd "$user"
    check "WordPress is in its public_html, owned by it" test "$(stat -c %U "/home/$user/public_html/wp-load.php" 2>/dev/null)" = "$user"
    check "wp-config.php is mode 0600" test "$(stat -c %a "/home/$user/public_html/wp-config.php" 2>/dev/null)" = 600
    # Over http the site serves WordPress, or, once its address is https,
    # WordPress sends the visitor to https (checked further down).
    ok=no
    for _ in $(seq 1 300); do
      answer="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $domain" http://127.0.0.1/)"
      if [ "$answer" = "301 https://$domain/" ] || curl -s -H "Host: $domain" http://127.0.0.1/ | grep -q 'Sifruno wizard proof'; then ok=yes; break; fi
      sleep 2
    done
    answer="${answer% }"
    echo "  over http: ${answer:-no answer}"
    check "over http the site serves WordPress, or sends the visitor to its https address" test "$ok" = yes
    check "wp-admin redirects to the login page" bash -c "curl -s -o /dev/null -w '%{http_code}' -H 'Host: $domain' http://127.0.0.1/wp-admin/ | grep -qx 302"

    # HTTPS: the certificate comes from this run's Pebble, so curl trusts
    # nothing but that root. The broker keeps a site's files in
    # /etc/sifruno/tls/<site>, where <site> is olsweb's site name for the
    # account: "u" and the first 31 characters of its ID.
    account="$(python3 -c "import json,sys; j=[x for x in json.load(open('$jobs'))['jobs'] if x['domain']=='$domain' and x['state']=='succeeded']; print(j[0]['result']['account_id'] if j else '')" 2>/dev/null)"
    tls="/etc/sifruno/tls/u${account:0:31}"
    echo "  its certificate folder: $tls"
    # As long as the http wait above: one run's https page came after more
    # than two minutes, though it served at once when checked again later.
    ok=no
    for _ in $(seq 1 300); do
      if curl -s --resolve "$domain:443:127.0.0.1" --cacert "$dir/pebble-root.pem" "https://$domain/" | grep -q 'Sifruno wizard proof'; then ok=yes; break; fi
      sleep 2
    done
    check "the site serves WordPress over https with a certificate from Pebble's root" test "$ok" = yes
    served="$(openssl s_client -connect 127.0.0.1:443 -servername "$domain" </dev/null 2>/dev/null | openssl x509 2>/dev/null)"
    san="$(printf '%s\n' "$served" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
    echo "  names in the served certificate: ${san:-none}"
    check "the served certificate names exactly the domain" test "$san" = "DNS:$domain"
    served_fp="$(printf '%s\n' "$served" | openssl x509 -noout -fingerprint -sha256 2>/dev/null)"
    file_fp="$(openssl x509 -in "$tls/cert.pem" -noout -fingerprint -sha256 2>/dev/null)"
    check "it is the certificate in $tls/cert.pem" test "${served_fp:-none served}" = "${file_fp:-no file}"
    check "cert.pem and key.pem are root's, mode 0600" test "$(stat -c '%U %a' "$tls/cert.pem" "$tls/key.pem" 2>/dev/null | paste -sd ' ')" = "root 600 root 600"
    # Read from the site's own wp-config.php; the patterns admit only
    # identifier characters, so the names are safe to put in the query.
    config="/home/$user/public_html/wp-config.php"
    db="$(sed -n "s/^define( *'DB_NAME', *'\([a-z0-9_]*\)' *);.*/\1/p" "$config" 2>/dev/null)"
    prefix="$(sed -n "s/^[\$]table_prefix *= *'\([A-Za-z0-9_]*\)';.*/\1/p" "$config" 2>/dev/null)"
    urls="$(mysql --protocol=socket -uroot -N -B -e "SELECT option_value FROM \`$db\`.\`${prefix}options\` WHERE option_name IN ('home', 'siteurl') ORDER BY option_name" 2>&1 | paste -sd ' ')"
    echo "  WordPress home and siteurl in $db: $urls"
    check "WordPress's home and siteurl are https" test "$urls" = "https://$domain https://$domain"

    # LSCache: the site's vhost has the cache module with its own store, the
    # plugin is active at its pinned version, and the second anonymous GET of
    # the home page is a hit.
    ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
    vhconf="$LSWS/conf/vhosts/sifruno-u${account:0:31}/vhconf.conf"
    store="$(site_store "$account")"
    check "the site's vhconf.conf turns the cache module on with its own store" bash -c \
      "grep -A2 '^module cache {' $vhconf | grep -q 'ls_enabled *1' && grep -q '^  storagePath *$store\$' $vhconf"
    check "httpd_config.conf registers the cache module (the package's block)" grep -q '^module cache {' "$LSWS/conf/httpd_config.conf"
    # WP-CLI as the site's user, as the broker runs it.
    wp() { runuser -u "$user" -- "$LSWS/lsphp83/bin/php" "$WPCLI" --path="/home/$user/public_html" --no-color "$@"; }
    # shellcheck disable=SC2317 # called through check
    verified() { wp plugin verify-checksums litespeed-cache 2>&1 | grep -q 'Verified 1 of 1 plugins'; }
    plugin="$(wp plugin get litespeed-cache --field=version 2>/dev/null)"
    echo "  LiteSpeed Cache plugin: ${plugin:-not installed}"
    check "the LiteSpeed Cache plugin 7.9.3 is installed" test "$plugin" = 7.9.3
    check "it is active" wp plugin is-active litespeed-cache
    check "its files match wordpress.org's checksums" verified
    check "it does not cache signed-in visitors (cache-priv 0)" test "$(wp litespeed-option get cache-priv 2>/dev/null)" = 0
    first="$(cache_header "https://$domain/")"
    second="$(cache_header "https://$domain/")"
    echo "  X-LiteSpeed-Cache on two GETs of https://$domain/: ${first:-none}, ${second:-none}"
    check "the second GET of the home page is served from the cache" test "$second" = hit
    posted="$(cache_header "https://$domain/" -X POST --data probe=1)"
    echo "  X-LiteSpeed-Cache on a POST: ${posted:-none}"
    check "a POST is not served from the cache" test "$posted" != hit
    check "the store is the web server's, 2770, outside every home" test "$(stat -c '%U %a' "$store" 2>/dev/null)" = "${ols_user:-nobody} 2770"
    ;;
  check-php)
    dir="$2"
    domain="$3"
    jobs="$dir/state/wizard/jobs.json"
    user="$(job_field "$jobs" "$domain" php username)"
    account="$(job_field "$jobs" "$domain" php result.account_id)"
    echo "  PHP site account made by the wizard: ${user:-none}"
    check "the account's Linux user exists" getent passwd "$user"
    page="/home/$user/public_html/index.php"
    check "the placeholder index.php is the site user's, mode 0644" test "$(stat -c '%U %a' "$page" 2>/dev/null)" = "$user 644"
    check "it is the only file in public_html" test "$(find "/home/$user/public_html" -mindepth 1 | wc -l)" = 1
    check "it says the site is ready" grep -q '<h1>This website is ready</h1>' "$page"
    # "It runs PHP." is printed by PHP; the file itself does not hold it.
    ok=no
    for _ in $(seq 1 300); do
      if curl -s --resolve "$domain:443:127.0.0.1" --cacert "$dir/pebble-root.pem" "https://$domain/" | grep -q 'It runs PHP\.'; then ok=yes; break; fi
      sleep 2
    done
    check "the site serves the placeholder over https, run by PHP, with a certificate from Pebble's root" test "$ok" = yes
    served="$(openssl s_client -connect 127.0.0.1:443 -servername "$domain" </dev/null 2>/dev/null | openssl x509 2>/dev/null)"
    san="$(printf '%s\n' "$served" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
    check "the served certificate names exactly the domain" test "$san" = "DNS:$domain"
    vhconf="$LSWS/conf/vhosts/sifruno-u${account:0:31}/vhconf.conf"
    check "the site runs PHP 8.3 (lsphp83)" grep -q '^  path *'"$LSWS"'/lsphp83/bin/lsphp$' "$vhconf"
    check "its vhost has the cache module with its own store" grep -q "^  storagePath *$(site_store "$account")\$" "$vhconf"
    first="$(cache_header "https://$domain/")"
    second="$(cache_header "https://$domain/")"
    echo "  X-LiteSpeed-Cache on two GETs of the placeholder: ${first:-none}, ${second:-none}"
    check "the placeholder is not cached: the page does not ask for it" test "$second" != hit
    names="$(mysql --protocol=socket -uroot -N -B -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${user}_wp'; SELECT COUNT(*) FROM mysql.user WHERE User='${user}_wp'" 2>/dev/null | paste -sd ' ')"
    check "the database ${user}_wp and its user exist" test "$names" = "1 1"
    ;;
  *)
    echo "usage: wordpress-wizard.guest.sh start DIR PORT | check DIR DOMAIN | check-php DIR DOMAIN" >&2
    exit 2
    ;;
esac
exit "$fails"
