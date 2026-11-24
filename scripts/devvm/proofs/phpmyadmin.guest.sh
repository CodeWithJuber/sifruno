#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh phpmyadmin copies it in).
#   phpmyadmin.guest.sh install               run the installer's phpMyAdmin step twice
#   phpmyadmin.guest.sh start DIR LOOP PANEL PMA
#                                             start the broker, a sampler of every process's
#                                             arguments and the panel (a proof build whose
#                                             temporary users last 2 minutes): loopback on
#                                             LOOP, HTTPS for panel.proof.test on PANEL, and
#                                             phpMyAdmin's own HTTPS origin on PMA
#   phpmyadmin.guest.sh check DIR USER OTHER  after the browser opened phpMyAdmin for USER's
#                                             website: the temporary user, its grants, its
#                                             password nowhere but phpMyAdmin's session
#   phpmyadmin.guest.sh expire                wait for the sweeper to drop the temporary user
# The installer's step comes from this release's install.sh, with the
# release's phpmyadmin/ files beside it in /opt/sifruno-proof/install. The
# panel runs as sifpanel on 127.0.0.1 only, and the host reaches its three
# ports through SSH forwards. Prints PASS/FAIL per check; exits with the
# failure count.
set -uo pipefail

BIN=/opt/sifruno-proof
INSTALL=$BIN/install
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
PMA_DIR=/usr/local/lib/sifruno/phpmyadmin
PMA_STATE=/var/lib/sifruno-phpmyadmin
PANEL_RUN=/run/sifruno-panel
PANEL_HOST=panel.proof.test
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
sql() { mysql --protocol=socket -uroot -N -B -e "$1" 2>&1; }
# The temporary users on the server, one per line.
temp_users() { sql "SELECT User FROM mysql.user WHERE User LIKE 'SifrunoPMA\\_%' ORDER BY User"; }

case "${1:-}" in
  install)
    echo "# guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"
    echo "# $(rpm -q openlitespeed lsphp83 mariadb-server | paste -sd ' ')"
    echo "## The installer's phpMyAdmin step, as an upgrade runs it"
    # In a subshell: install.sh turns on errexit, which this script does not use.
    # shellcheck disable=SC1091
    (SIFRUNO_INSTALL_FUNCTIONS_ONLY=1 . "$INSTALL/install.sh" && step_phpmyadmin && printf '  changed: %s\n' "${CHANGES[@]}") || fail "the installer's phpMyAdmin step runs"
    # shellcheck disable=SC2016 # expands in the inner shell
    check "the step changes nothing the second time" bash -c 'SIFRUNO_INSTALL_FUNCTIONS_ONLY=1 . "$0" && step_phpmyadmin && [ "${#CHANGES[@]}" -eq 0 ]' "$INSTALL/install.sh"
    uid="$(id -u sifpma 2>/dev/null)"
    echo "  sifpma: $(id sifpma 2>&1)"
    check "sifpma is a system user outside the accounts' 20000 to 60000, in its own group only" bash -c "[ -n '$uid' ] && [ '$uid' -gt 0 ] && [ '$uid' -lt 20000 ] && [ \"\$(id -G sifpma)\" = \"\$(id -g sifpma)\" ]"
    check "phpMyAdmin 5.2.3 is in $PMA_DIR" grep -qx '5.2.3' <(sed -n "s/.*VERSION = '\\([0-9.]*\\)'.*/\\1/p" "$PMA_DIR/libraries/classes/Version.php")
    check "every file of it is root's and no one else can write it" test -z "$(find "$PMA_DIR" \( ! -user root -o -perm /022 -o -type l \) -print -quit)"
    check "there is no setup/ or examples/ folder" bash -c "[ ! -e $PMA_DIR/setup ] && [ ! -e $PMA_DIR/examples ]"
    check "config.inc.php is root:sifpma 0640, the sign-in script root's 0644" test "$(stat -c '%U:%G %a' "$PMA_DIR/config.inc.php" "$PMA_DIR/sifruno-signon.php" | paste -sd ' ')" = "root:sifpma 640 root:root 644"
    check "the blowfish secret is root:sifpma 0640 and 32 bytes" bash -c "[ \"\$(stat -c '%U:%G %a' /etc/sifruno/phpmyadmin/secret.inc.php)\" = 'root:sifpma 640' ] && grep -qE \"hex2bin\\('[0-9a-f]{64}'\\)\" /etc/sifruno/phpmyadmin/secret.inc.php"
    check "the session and temp folders are sifpma's, 0700" test "$(stat -c '%U %a' "$PMA_STATE/sessions" "$PMA_STATE/tmp" | paste -sd ' ')" = "sifpma 700 sifpma 700"
    check "httpd_config.conf includes the phpMyAdmin fragment once" test "$(grep -cxF "include $LSWS/conf/sifruno-phpmyadmin.conf" "$LSWS/conf/httpd_config.conf")" = 1
    errors="$("$LSWS/bin/openlitespeed" -t 2>&1 | grep -F '[ERROR]' | grep -i 'phpmyadmin' || true)"
    echo "  openlitespeed -t errors naming phpMyAdmin: ${errors:-none}"
    check "OpenLiteSpeed's config test has no error for phpMyAdmin's vhost" test -z "$errors"
    # OpenLiteSpeed's graceful restart takes a few seconds.
    for _ in $(seq 1 30); do ss -ltn | grep -q '127.0.0.1:8090 ' && break; sleep 1; done
    echo "  listening on 8090: $(ss -ltnp | awk '$4 ~ /:8090$/ {print $4}' | paste -sd ' ')"
    check "OpenLiteSpeed listens for phpMyAdmin on 127.0.0.1:8090 only" bash -c "[ \"\$(ss -ltn | awk '\$4 ~ /:8090\$/ {print \$4}' | paste -sd ' ')\" = 127.0.0.1:8090 ]"
    answer() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:8090$1"; }
    got="$(answer /)"
    echo "  GET / on the listener: $got"
    check "phpMyAdmin (at the root) with no sign-in sends the browser to the sign-in script" test "$got" = "302 http://127.0.0.1:8090/sifruno-signon.php"
    got="$(curl -s -w ' %{http_code}' "http://127.0.0.1:8090/sifruno-signon.php")"
    check "the sign-in script without a code asks for a new sign-in (401)" bash -c "[[ \"\$0\" == *'phpMyAdmin needs a new sign-in.'*' 401' ]]" "$got"
    for path in /api/v1/session /API/x /libraries/classes/Version.php /vendor/autoload.php /templates/login/form.twig /config.inc.php /composer.json /.rtlcssrc.json; do
      check "the listener refuses $path (403)" test "$(answer "$path")" = "403 "
    done
    ;;
  start)
    dir="$2"
    port="$3"
    panel="$4"
    pma="$5"
    ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
    systemctl stop sifruno-broker-proof 2>/dev/null
    systemctl reset-failed sifruno-broker-proof 2>/dev/null
    systemd-run --quiet --unit sifruno-broker-proof --collect \
      "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
    check "the broker runs" test -S "$SOCKET"
    # systemd makes this folder for the installed panel (RuntimeDirectory).
    install -d -o sifpanel -g sifpanel -m 0755 "$PANEL_RUN"
    cd "$dir" || exit 1
    tar -xzf dist.tgz && tar -xzf state.tgz && chown -R sifpanel:sifpanel "$dir" && chmod 0755 sifruno
    restorecon -R "$dir" 2>/dev/null
    # Every process's arguments, sampled until the check step stops it.
    nohup bash -c 'while :; do ps -eo args; echo --; sleep 0.2; done' > "$dir/ps-samples.txt" 2>/dev/null &
    echo $! > "$dir/sampler.pid"
    runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$port --sites-listen '' --state ./state --ui ./dist \
      --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf \
      --https-listen 127.0.0.1:$panel --panel-host $PANEL_HOST --phpmyadmin-listen 127.0.0.1:$pma \
      --phpmyadmin-upstream 127.0.0.1:8090 --phpmyadmin-uid $(id -u sifpma) --phpmyadmin-test-login-ttl 2m > panel.log 2>&1 &"
    for _ in $(seq 1 90); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 2; done
    check "the panel answers on 127.0.0.1:$port as sifpanel" bash -c "curl -fs -o /dev/null http://127.0.0.1:$port/ && [ \"\$(ps -o user= -p \$(pgrep -x sifruno | head -1))\" = sifpanel ]"
    check "the panel says phpMyAdmin has its own origin, with 2-minute proof sign-ins" grep -qF "phpMyAdmin on its own origin, HTTPS on 127.0.0.1:$pma for $PANEL_HOST (OpenLiteSpeed listener 127.0.0.1:8090, sign-ins last 2m0s)" "$dir/panel.log"
    check "its sign-in socket is in $PANEL_RUN" test -S "$PANEL_RUN/phpmyadmin.sock"
    # The same certificate as the panel's HTTPS listener, on another port.
    fp() { openssl s_client -connect "127.0.0.1:$1" -servername "$PANEL_HOST" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null; }
    check "phpMyAdmin's origin serves the panel's certificate" bash -c "[ -n \"\$0\" ] && [ \"\$0\" = \"\$1\" ]" "$(fp "$panel")" "$(fp "$pma")"
    https() { curl -sk -o /dev/null -w '%{http_code}' --resolve "$PANEL_HOST:$1:127.0.0.1" "https://$PANEL_HOST:$1$2"; }
    check "phpMyAdmin's origin answers 404 for the panel's API" test "$(https "$pma" /api/v1/session)" = 404
    check "it answers 401 to a browser with no code and no admission" test "$(https "$pma" /index.php)" = 401
    check "it answers only for the panel's host name (421)" test "$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$pma/index.php")" = 421
    ;;
  check)
    dir="$2"
    user="$3"
    other="$4"
    kill "$(cat "$dir/sampler.pid")" 2>/dev/null
    mapfile -t temps < <(temp_users)
    echo "  temporary users: ${temps[*]:-none}"
    check "there is exactly one temporary user" test "${#temps[@]}" = 1
    temp="${temps[0]:-none}"
    grants="$(sql "SHOW GRANTS FOR '$temp'@'localhost'" | grep -v '^GRANT USAGE ON \*\.\*' | paste -sd '|')"
    echo "  its grants: $grants"
    # SHOW GRANTS quotes names with backticks and escapes the database's "_",
    # so the grant names exactly that database.
    db_grant="ON \`${user}\\_wp\`.* TO \`$temp\`@\`localhost\`"
    # shellcheck disable=SC2317 # called through check
    one_grant() { [[ "$grants" == "GRANT "*" $db_grant" ]] && [[ "$grants" != *'|'* ]]; }
    # shellcheck disable=SC2317 # called through check
    reads_and_changes() {
      local p
      for p in SELECT INSERT UPDATE DELETE CREATE DROP ALTER; do [[ "$grants" == *"$p"* ]] || return 1; done
    }
    # shellcheck disable=SC2317 # called through check
    no_definer() { ! grep -qE 'ALL PRIVILEGES|TRIGGER|CREATE VIEW|CREATE ROUTINE|ALTER ROUTINE|EVENT' <<<"$grants"; }
    check "it has one grant, on exactly ${user}_wp" one_grant
    check "it may read and change tables (SELECT to ALTER)" reads_and_changes
    check "it has no privilege that records a definer (no ALL, TRIGGER, CREATE VIEW, routines or EVENT)" no_definer
    check "nothing of $other's is in its grants" bash -c "! grep -q '$other' <<<\"\$0\"" "$grants"
    check "the panel's record holds it, with $user as the owner" grep -q "\"user\":\"$temp\",\"owner\":\"$user\"" "$dir/state/phpmyadmin/logins.json"
    check "the record is the panel's, 0600" test "$(stat -c '%U %a' "$dir/state/phpmyadmin/logins.json")" = "sifpanel 600"
    # The password exists only in phpMyAdmin's signon session, which root reads here.
    session="$(grep -l "PMA_single_signon_user|s:31:\"$temp\"" "$PMA_STATE"/sessions/sess_* 2>/dev/null | head -1)"
    check "phpMyAdmin's signon session holds the login, sifpma's 0600" bash -c "[ -n '$session' ] && [ \"\$(stat -c '%U %a' '$session')\" = 'sifpma 600' ]"
    password="$(sed -n 's/.*PMA_single_signon_password|s:43:"\([A-Za-z0-9_-]\{43\}\)".*/\1/p' "$session" 2>/dev/null)"
    check "the session's password is 43 characters" test "${#password}" = 43
    check "with it the temporary user signs in to MariaDB and sees $user's database only" bash -c \
      "[ \"\$(MYSQL_PWD=\"\$0\" mysql --protocol=socket -u '$temp' -N -B -e 'SHOW DATABASES' | grep -v '^information_schema\$' | paste -sd ' ')\" = '${user}_wp' ]" "$password"
    samples="$(grep -c '^--$' "$dir/ps-samples.txt")"
    echo "  process-argument samples taken while phpMyAdmin opened: $samples"
    check "no process argument held the temporary user's password" bash -c "[ $samples -gt 0 ] && ! grep -qF -- \"\$0\" '$dir/ps-samples.txt'" "$password"
    check "the panel ran the mysql client during the samples" grep -q -- '--defaults-extra-file=/var/lib/sifpanel/db-admin.cnf' "$dir/ps-samples.txt"
    # The password goes to mysql in its environment, never as an argument.
    # shellcheck disable=SC2317 # called through check
    as_temp() { MYSQL_PWD="$password" mysql --protocol=socket -u "$temp" -N -B -e "$1"; }
    # shellcheck disable=SC2317 # called through check
    definers_refused() {
      local db="\`${user}_wp\`"
      ! as_temp "CREATE VIEW $db.sifruno_proof_v AS SELECT 1" &&
        as_temp "CREATE TABLE $db.sifruno_proof_t (a INT)" &&
        ! as_temp "CREATE TRIGGER $db.sifruno_proof_tr BEFORE INSERT ON $db.sifruno_proof_t FOR EACH ROW SET @x = 1" &&
        as_temp "DROP TABLE $db.sifruno_proof_t"
    }
    check "with it the temporary user makes a table but no view or trigger" definers_refused
    logs=("$dir/panel.log" "$LSWS"/logs/*.log "$LSWS"/logs/sifruno_phpmyadmin/*.log "$PMA_STATE"/logs/*.log)
    check "phpMyAdmin's PHP error log folder is sifpma's, 0700" test "$(stat -c '%U %a' "$PMA_STATE/logs")" = "sifpma 700"
    check "neither the panel's log nor OpenLiteSpeed's logs hold the password" bash -c "! grep -qF -- \"\$0\" ${logs[*]}" "$password"
    check "no OpenLiteSpeed log holds a sign-in link's code" bash -c "! grep -q 'sifruno-signon.php?code=' ${logs[*]:1}"
    check "sifpma cannot open $user's or $other's home" bash -c "! runuser -u sifpma -- ls /home/$user >/dev/null 2>&1 && ! runuser -u sifpma -- ls /home/$other >/dev/null 2>&1"
    lsphp="$(ps -eo user,args | awk '$1=="sifpma" && /lsphp/ {print; exit}')"
    echo "  phpMyAdmin's PHP: ${lsphp:-not running}"
    check "phpMyAdmin's PHP runs as sifpma" test -n "$lsphp"
    ;;
  expire)
    echo "  waiting for the sweeper (2-minute sign-ins, a sweep every minute)"
    gone=no
    for _ in $(seq 1 60); do
      if [ -z "$(temp_users)" ]; then gone=yes; break; fi
      sleep 5
    done
    check "the sweeper dropped the temporary user within 5 minutes" test "$gone" = yes
    check "no connection of a temporary user is left" test "$(sql "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER LIKE 'SifrunoPMA\\_%'")" = 0
    ;;
  *)
    echo "usage: phpmyadmin.guest.sh install | start DIR LOOP PANEL PMA | check DIR USER OTHER | expire" >&2
    exit 2
    ;;
esac
exit "$fails"
