#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh wordpress-wizard copies it in).
#   wordpress-wizard.guest.sh start DIR PORT   start the broker and the panel
#   wordpress-wizard.guest.sh check DIR DOMAIN check the site the wizard made
# The panel runs as sifpanel, the broker's controller, with throwaway state
# in DIR, the broker socket and the MariaDB admin option file; it listens on
# 127.0.0.1:PORT only, and the host reaches it through an SSH forward.
set -uo pipefail

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

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
    cd "$dir" || exit 1
    tar -xzf dist.tgz && tar -xzf state.tgz && chown -R sifpanel:sifpanel "$dir" && chmod 0755 sifruno
    restorecon -R "$dir" 2>/dev/null
    runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$port --sites-listen '' --state ./state --ui ./dist \
      --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf > panel.log 2>&1 &"
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
    ok=no
    for _ in $(seq 1 300); do
      if curl -s -H "Host: $domain" http://127.0.0.1/ | grep -q 'Sifruno wizard proof'; then ok=yes; break; fi
      sleep 2
    done
    check "the site serves WordPress with the title from the wizard" test "$ok" = yes
    check "wp-admin redirects to the login page" bash -c "curl -s -o /dev/null -w '%{http_code}' -H 'Host: $domain' http://127.0.0.1/wp-admin/ | grep -qx 302"
    ;;
  *)
    echo "usage: wordpress-wizard.guest.sh start DIR PORT | check DIR DOMAIN" >&2
    exit 2
    ;;
esac
exit "$fails"
