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
usage: proof.sh broker-sftp [extra-accounts] | wordpress-ols | migrate-verify
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
  *)
    usage
    exit 2
    ;;
esac
