#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh customer-login copies it in).
#   customer-login.guest.sh start DIR PORT HTTPS_PORT   start the broker and the panel
#   customer-login.guest.sh check DIR                   check the panel's private state
# The panel runs as sifpanel, the broker's controller, with throwaway state in
# DIR, the broker socket and the MariaDB admin option file. It listens on
# 127.0.0.1:PORT and serves HTTPS on 127.0.0.1:HTTPS_PORT for
# panel.sifruno.test with a self-signed certificate; the host reaches both
# through SSH forwards, the HTTPS one as a customer's computer would.
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
    https_port="$4"
    echo "# guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"
    ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
    systemctl stop sifruno-broker-proof 2>/dev/null
    systemctl reset-failed sifruno-broker-proof 2>/dev/null
    systemd-run --quiet --unit sifruno-broker-proof --collect \
      "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
    for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
    check "the broker runs" test -S "$SOCKET"
    cd "$dir" || exit 1
    tar -xzf dist.tgz && tar -xzf state.tgz && chown -R sifpanel:sifpanel "$dir" && chmod 0755 sifruno
    restorecon -R "$dir" 2>/dev/null
    runuser -u sifpanel -- sh -c "nohup ./sifruno --listen 127.0.0.1:$port --sites-listen '' --state ./state --ui ./dist \
      --accounts-socket $SOCKET --db-defaults-file /var/lib/sifpanel/db-admin.cnf \
      --https-listen 127.0.0.1:$https_port --panel-host panel.sifruno.test > panel.log 2>&1 &"
    for _ in $(seq 1 90); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 2; done
    check "the panel answers on 127.0.0.1:$port as sifpanel" bash -c "curl -fs -o /dev/null http://127.0.0.1:$port/ && [ \"\$(ps -o user= -p \$(pgrep -x sifruno | head -1))\" = sifpanel ]"
    check "the panel answers over HTTPS for panel.sifruno.test" curl -fsk -o /dev/null --resolve "panel.sifruno.test:$https_port:127.0.0.1" "https://panel.sifruno.test:$https_port/"
    check "the start-up note says customers sign in over HTTPS" grep -q 'sign-in (admins and customers)' panel.log
    exit "$fails"
    ;;
  check)
    dir="$2"
    file="$dir/state/operator/customers.json"
    check "customers.json is the panel's and private (0600)" test "$(stat -c '%U %a' "$file" 2>/dev/null)" = "sifpanel 600"
    check "it keeps an Argon2id hash, never a password or a setup link" bash -c "grep -q '\"algorithm\": \"argon2id\"' $file && ! grep -q '/setup#' $file"
    check "the panel log holds no setup link" bash -c "! grep -q '/setup#' $dir/panel.log"
    exit "$fails"
    ;;
  *)
    echo "usage: customer-login.guest.sh start DIR PORT HTTPS_PORT | check DIR" >&2
    exit 2
    ;;
esac
