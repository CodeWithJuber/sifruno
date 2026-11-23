#!/usr/bin/env bash
# Builds what a proof needs, copies it into the running dev VM, runs the
# guest-side script there and saves its transcript. Exit status is the
# guest script's: zero only when every check passed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"

usage() {
  cat <<'USAGE'
usage: proof.sh broker-sftp [extra-accounts] | wordpress-ols | migrate-verify | broker-web | panel-shell
  broker-sftp   Proof 2: the root broker creates a regular Linux user and the
                user signs in over SFTP with a broker-managed key. With
                extra-accounts (for example 105) it also creates that many
                more accounts to show the old 100-account bound is gone.
  wordpress-ols Proof 1: the broker creates an account, olsweb renders the
                OpenLiteSpeed config, WP-CLI installs WordPress as that user,
                and the site runs in a namespace container under a quota.
                Run broker-sftp first; this proof reuses its broker state.
  migrate-verify
                Proof 3 rehearsal: the .htaccess scan sends an Apache site
                with a password folder to the Compat tier, and migrate verify
                keeps the cutover gate closed against an OpenLiteSpeed copy
                (where the folder opens) and opens it against an Apache copy.
  broker-web    The broker's web operation: OpenLiteSpeed may read the home,
                a quota is set, the vhost is rendered, tested and reloaded,
                a rejected config changes nothing, a symlinked public_html is
                refused, and delete takes the site out first.
  panel-shell   Phase 1 panel shell and admin sign-in: the panel runs in the VM
                with throwaway state and a browser on this host drives it
                (first-run admin setup with 2FA, sign-in, code replay and rate
                limits, menu, page URLs, Ctrl+K, Websites to Files, phone
                width, public preview), and over the HTTPS listener as
                another machine would (admin-only, certificate fingerprint). Needs Node, the repo's npm packages and Playwright's
                Chromium, or a Chrome binary in SIFRUNO_PROOF_CHROME.
USAGE
}

build() { # build <output> <package>
  (cd "$REPO" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$1" "$2")
}

case "${1:-}" in
  broker-sftp)
    extra="${2:-0}"
    case "$extra" in ''|*[!0-9]*) usage >&2; exit 2 ;; esac
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    (cd "$REPO" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -trimpath -buildvcs=false -o "$stage/hostaccounts.test" ./internal/hostaccounts)
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive hostaccounts.test; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/broker-sftp.guest.sh" /opt/sifruno-proof/broker-sftp.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/hostaccounts.test /opt/sifruno-proof/broker-sftp.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/proof2-broker-sftp-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh "EXTRA_ACCOUNTS=$extra /opt/sifruno-proof/broker-sftp.guest.sh" | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  wordpress-ols)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    build "$stage/olsrender" ./scripts/devvm/olsrender
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive olsrender; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/wordpress-ols.guest.sh" /opt/sifruno-proof/wordpress-ols.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/olsrender /opt/sifruno-proof/wordpress-ols.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/proof1-wordpress-ols-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/wordpress-ols.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  migrate-verify)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/panelctl" ./cmd/panelctl
    "$HERE/vm.sh" ssh 'install -d -m 0755 /opt/sifruno-proof'
    "$HERE/vm.sh" put "$stage/panelctl" /opt/sifruno-proof/panelctl
    "$HERE/vm.sh" put "$HERE/proofs/migrate-verify.guest.sh" /opt/sifruno-proof/migrate-verify.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/panelctl /opt/sifruno-proof/migrate-verify.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/proof3-migrate-verify-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/migrate-verify.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  broker-web)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/broker-web.guest.sh" /opt/sifruno-proof/broker-web.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/broker-web.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/broker-web-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/broker-web.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  panel-shell)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    # shellcheck disable=SC1091
    . "${SIFRUNO_DEVVM_DIR:-$HOME/.cache/sifruno-devvm}/ports"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/opt/sifruno-proof/panel-$stamp"
    build "$stage/sifruno" ./cmd/sifruno
    (cd "$REPO" && npm run --silent panel:build >/dev/null)
    # Seed the state here so the browser checks can read its operator key
    # without the key ever leaving a file. A few seconds is enough to create it.
    timeout 5 "$stage/sifruno" --listen 127.0.0.1:0 --sites-listen "" --state "$stage/state" --ui "$REPO/web/dist" >/dev/null 2>&1 || true
    test -s "$stage/state/operator/access.key"
    tar -czf "$stage/dist.tgz" -C "$REPO/web" dist
    tar -czf "$stage/state.tgz" -C "$stage" state
    # Each run gets its own directory in the disposable VM; stop the last one.
    "$HERE/vm.sh" ssh "pkill -x sifruno; if [ -f /opt/sifruno-proof/relay.pid ]; then kill \$(cat /opt/sifruno-proof/relay.pid) 2>/dev/null; fi; install -d -m 0700 $guest" || true
    for file in sifruno dist.tgz state.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/panel-relay.py" /opt/sifruno-proof/panel-relay.py
    # The panel accepts browser writes only from its own origin, so it listens
    # on the same port number QEMU forwards from this host to guest port 80.
    "$HERE/vm.sh" ssh "set -e; cd $guest; tar -xzf dist.tgz; tar -xzf state.tgz; chmod 0755 sifruno; restorecon -R /opt/sifruno-proof; \
      (nohup ./sifruno --listen 127.0.0.1:$HTTP_PORT --sites-listen 127.0.0.1:8082 --state ./state --ui ./dist --https-listen 0.0.0.0:443 --panel-host panel.sifruno.test > panel.log 2>&1 &); \
      nohup /usr/bin/python3 /opt/sifruno-proof/panel-relay.py $HTTP_PORT > relay.log 2>&1 & echo \$! > /opt/sifruno-proof/relay.pid"
    # Python starts slowly under software emulation; wait for the relay.
    for _ in $(seq 90); do curl -fs -o /dev/null "http://127.0.0.1:$HTTP_PORT/" && break; sleep 2; done
    # The guest also serves HTTPS on 443 (QEMU forwards HTTPS_PORT to it) for
    # panel.sifruno.test with a self-signed certificate; the browser checks
    # that it serves the fingerprint the panel printed at start.
    fingerprint="$("$HERE/vm.sh" ssh "grep -o 'SHA-256 [0-9A-F:]*' $guest/panel.log | head -1 | cut -d' ' -f2")"
    mkdir -p "$OUT"
    run="$OUT/panel-shell-$stamp"
    transcript="$run.txt"
    status=0
    {
      # shellcheck disable=SC2016 # expands in the guest
      "$HERE/vm.sh" ssh 'echo "guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"'
      (cd "$REPO" && node scripts/devvm/proofs/panel-shell.qa.mjs "http://127.0.0.1:$HTTP_PORT" "$stage/state" "$run" "${SIFRUNO_PROOF_CHROME:-}" "https://panel.sifruno.test:$HTTPS_PORT" "$fingerprint")
    } | tee "$transcript" || status=$?
    echo "Transcript: $transcript (screenshots in $run/)"
    exit "$status"
    ;;
  *)
    usage
    exit 2
    ;;
esac
