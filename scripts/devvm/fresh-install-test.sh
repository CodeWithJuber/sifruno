#!/usr/bin/env bash
# Fresh-install test for the Phase 1 gate "one command installs on a new
# AlmaLinux server". It destroys the dev VM, creates a new one, provisions
# it with the installer starting the services, smoke-tests the result, runs
# the installer a second time to show it changes nothing, and saves the
# transcript. Exit status is zero only when every step and check passed.
#
# The VM is left with both Sifruno units running. The proofs start their own
# broker on the same socket, so turn the units off before a proof:
#   scripts/devvm/vm.sh ssh 'systemctl disable --now sifruno sifruno-broker'
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"
RELEASE="${SIFRUNO_RELEASE:-}"

if [ $# -ne 1 ] || [ "$1" != --destroy-vm ]; then
  cat >&2 <<'USAGE'
usage: fresh-install-test.sh --destroy-vm
  Deletes the dev VM's disks (vm.sh destroy) and builds a new VM, so the
  flag is required. Builds the release first with
  scripts/install/build-release.sh; set SIFRUNO_RELEASE to a tarball that
  has its .sha256 beside it to test that one instead.
USAGE
  exit 2
fi

if [ -z "$RELEASE" ]; then
  "$REPO/scripts/install/build-release.sh"
  RELEASE="$REPO/artifacts/release/sifruno-linux-amd64.tar.gz"
fi
if [ ! -f "$RELEASE" ] || [ ! -f "$RELEASE.sha256" ]; then
  echo "fresh-install-test.sh: no release at $RELEASE with its .sha256 beside it" >&2
  exit 1
fi

vm() { "$HERE/vm.sh" "$@"; }

smoke() {
  vm ssh 'bash -s' <<'GUEST'
set -uo pipefail
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
main_pid() { systemctl show -p MainPID --value "$1"; }

echo
echo "# Smoke test: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"
echo "## The two units"
check "sifruno-broker.service is active" systemctl is-active --quiet sifruno-broker.service
check "sifruno.service is active" systemctl is-active --quiet sifruno.service
check "both units start at boot" bash -c 'systemctl is-enabled --quiet sifruno-broker.service && systemctl is-enabled --quiet sifruno.service'
echo "## The panel and the broker"
check "the panel answers on 127.0.0.1:8080" curl -fsS -o /dev/null http://127.0.0.1:8080/
check "the panel runs as sifpanel" test "$(ps -o user= -p "$(main_pid sifruno.service)" | tr -d ' ')" = sifpanel
check "the broker socket exists" test -S /run/sifruno-broker/control.sock
check "the socket is sifpanel's, mode 0600" test "$(stat -c '%U %a' /run/sifruno-broker/control.sock)" = "sifpanel 600"
check "hostbroker --check-host passes" /usr/local/lib/sifruno/bin/hostbroker --check-host
check "SELinux is still enforcing" test "$(getenforce)" = Enforcing
echo "  SELinux labels of the two processes and their programs, for the record:"
ps -o label=,user=,comm= -p "$(main_pid sifruno-broker.service)" -p "$(main_pid sifruno.service)" 2>&1 | sed 's/^/    /'
ls -Z /usr/local/lib/sifruno/bin 2>&1 | sed 's/^/    /'

echo "## A second run of the installer changes nothing"
second="$(bash /root/sifruno-release/sifruno-linux-amd64/install.sh 2>&1)"
second_status=$?
printf '%s\n' "$second" | sed 's/^/  | /'
check "the second run succeeds" test "$second_status" -eq 0
check "it reports that nothing changed" grep -qx 'Changed in this run: nothing' <<<"$second"
check "both units are still active" bash -c 'systemctl is-active --quiet sifruno-broker.service && systemctl is-active --quiet sifruno.service'

echo
echo "# $fails check(s) failed"
exit "$fails"
GUEST
}

# Chained with &&: a function called on the left of || runs with errexit off,
# so each step must name the next one itself.
run() {
  echo "# Fresh install test $(date -u +%FT%TZ)" &&
    echo "# release sha256 $(cut -d' ' -f1 "$RELEASE.sha256"), source $(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown)" &&
    vm destroy &&
    vm create &&
    vm start &&
    vm put "$RELEASE" /root/sifruno-linux-amd64.tar.gz &&
    vm put "$RELEASE.sha256" /root/sifruno-linux-amd64.tar.gz.sha256 &&
    vm put "$HERE/provision.sh" /root/provision.sh &&
    vm ssh 'SIFRUNO_INSTALL_START=1 bash /root/provision.sh' </dev/null &&
    smoke
}

mkdir -p "$OUT"
transcript="$OUT/fresh-install-$(date -u +%Y%m%dT%H%M%SZ).txt"
status=0
run 2>&1 | tee "$transcript" || status=$?
echo "Transcript: $transcript"
if [ "$status" -eq 0 ]; then
  echo "The VM is left with both units running. Before a proof: scripts/devvm/vm.sh ssh 'systemctl disable --now sifruno sifruno-broker'"
fi
exit "$status"
