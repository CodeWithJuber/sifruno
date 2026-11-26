#!/usr/bin/env bash
# Nightly fresh-install test on a throwaway Linode: the Phase 1 item "an
# installer that is tested every night on a fresh VM" (decision D-0006).
# .github/workflows/nightly-install.yml runs it every night; it also runs by
# hand.
#
# It builds the release, deletes what earlier failed runs left behind, and
# creates a Linode with AlmaLinux 9 and /home on a second disk, formatted XFS
# and mounted with user and group quota as docs/installation.md asks. A Cloud
# Firewall admits SSH from this machine only. Then it runs
# scripts/devvm/fresh-install-test.sh --existing-host against the Linode. On
# every way out it deletes the Linode and the firewall and checks through the
# API that both are gone.
#
#   nightly-fresh-install.sh           the whole test
#   nightly-fresh-install.sh cleanup   delete this run's Linode and firewall if
#                                      they are still there (for a killed run)
#
# Environment:
#   SIFRUNO_NIGHTLY_LINODE_TOKEN  required: a Linode personal access token
#                                 with Linodes and Firewalls read/write and
#                                 nothing else. A run costs one started hour
#                                 of a g6-standard-2 ($0.036 on 2026-11-25).
#   SIFRUNO_NIGHTLY_ID            names this run's Linode and firewall
#                                 sifruno-nightly-ID. Default: RUN_ID-ATTEMPT
#                                 in GitHub Actions, h + UTC time by hand.
#                                 cleanup needs the run's value.
#   SIFRUNO_PROOF_OUT             folder for the transcripts (default
#                                 artifacts/devvm): this script's log
#                                 nightly-ID.txt and the test's
#                                 fresh-install-*.txt
#   SIFRUNO_RELEASE               a release tarball with its .sha256 beside it,
#                                 to test instead of building one
#
# Exit status is zero only when every check passed and nothing of the run is
# left on the Linode account. Needs curl, jq, ssh, scp, ssh-keygen and
# timeout, and what scripts/install/build-release.sh needs.
set -euo pipefail
# The token is in this shell's memory, and a trace would print it.
set +x

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
API=https://api.linode.com/v4

# The server the test runs on: Frankfurt.
REGION=de-fra-2
TYPE=g6-standard-2
IMAGE=linode/almalinux9
ROOT_DISK_MB=30720
HOME_DISK_MB=10240
# The sweep deletes only what has both tags and a label starting
# sifruno-nightly-, once it is older than any healthy run lasts.
TAGS='["sifruno-nightly","delete-after-use"]'
SWEEP_AGE_SECONDS=10800
TEST_LIMIT=60m

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

die() {
  echo "nightly: $*" >&2
  exit 1
}

MODE="${1:-run}"
case "$MODE" in
  run | cleanup) ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

TOKEN="${SIFRUNO_NIGHTLY_LINODE_TOKEN:-}"
# Nothing this script starts (the build, ssh, the test) needs the token.
unset SIFRUNO_NIGHTLY_LINODE_TOKEN
[ -n "$TOKEN" ] || die "SIFRUNO_NIGHTLY_LINODE_TOKEN is not set. It holds the Linode token; see the top of this script."
# It goes into a curl config line, so only a token's own characters may.
[[ "$TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] || die "SIFRUNO_NIGHTLY_LINODE_TOKEN holds characters no Linode token has."

if [ -n "${SIFRUNO_NIGHTLY_ID:-}" ]; then
  ID="$SIFRUNO_NIGHTLY_ID"
elif [ -n "${GITHUB_RUN_ID:-}" ]; then
  ID="$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT:-1}"
elif [ "$MODE" = run ]; then
  ID="h$(date -u +%y%m%d%H%M%S)"
else
  die "cleanup needs SIFRUNO_NIGHTLY_ID, the ID the run printed when it started."
fi
# A firewall label has at most 32 characters and no doubled hyphen.
if ! [[ "$ID" =~ ^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$ ]] || [ "${#ID}" -gt 16 ]; then
  die "SIFRUNO_NIGHTLY_ID must be letters and digits, single hyphens between them, at most 16 characters."
fi
LABEL="sifruno-nightly-$ID"

for tool in curl jq ssh scp ssh-keygen timeout; do
  command -v "$tool" >/dev/null 2>&1 || die "missing program: $tool (Ubuntu packages: curl, jq, openssh-client, coreutils)"
done

OUT="${SIFRUNO_PROOF_OUT:-$REPO/artifacts/devvm}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
LOG="$OUT/nightly-$ID.txt"
WORK="$(mktemp -d)"
chmod 700 "$WORK"
# tee ignores Ctrl-C and SIGTERM, so the log stays open for the cleanup that
# those trigger.
exec > >(
  trap '' INT TERM
  exec tee -a "$LOG"
) 2>&1
TEE_PID=$!

ARMED=0
LINODE_ID=""
FIREWALL_ID=""
CREATED_AT=""
STEP="start"
TEST_STATUS=""
TRANSCRIPT=""
PRICE=""

log() { printf '== %s %s\n' "$(date -u +%FT%TZ)" "$*"; }

# call METHOD PATH [JSON]: one Linode API request. The answer's body goes to
# $WORK/answer.json and its HTTP status to HTTP_STATUS. Fails only when no
# answer came. The token reaches curl in a config read from a pipe, so it is
# in no argument list, file or log.
call() {
  local method="$1" path="$2" body="${3:-}"
  local -a opts=(-sS --connect-timeout 15 --max-time 120 -X "$method"
    -o "$WORK/answer.json" -w '%{http_code}' -H 'Accept: application/json')
  # Reading and deleting can be sent again; a create is sent once.
  if [ "$method" != POST ]; then
    opts+=(--retry 3 --retry-delay 5)
  fi
  if [ -n "$body" ]; then
    opts+=(-H 'Content-Type: application/json' --data-binary @-)
  fi
  if ! HTTP_STATUS="$(printf '%s' "$body" | curl "${opts[@]}" \
    --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") "$API$path")"; then
    HTTP_STATUS=000
    echo "nightly: no answer from the Linode API to $method $path" >&2
    return 1
  fi
}

reasons() {
  jq -r '[.errors[]? | (if .field then .field + ": " else "" end) + .reason] | join("; ")' \
    "$WORK/answer.json" 2>/dev/null || echo "no reason given"
}

# accepted METHOD PATH: prints the last answer's body, or fails with the API's
# own reasons when it refused.
accepted() {
  if [ "$HTTP_STATUS" -lt 200 ] || [ "$HTTP_STATUS" -ge 300 ]; then
    echo "nightly: the Linode API refused $1 $2 (HTTP $HTTP_STATUS): $(reasons)" >&2
    return 1
  fi
  cat -- "$WORK/answer.json"
}

# api METHOD PATH [JSON]: call, then print the answer's body.
api() {
  call "$@" || return 1
  accepted "$1" "$2"
}

# api_when_free METHOD PATH JSON: api for a change to the Linode. While an
# earlier job on it still runs, the API refuses with "Linode busy." even when
# its status reads offline; then this asks again every 10 s, for up to 5
# minutes. A refused request made nothing, so asking again is safe.
api_when_free() {
  local deadline=$((SECONDS + 300)) said=0
  while :; do
    call "$@" || return 1
    if [ "$HTTP_STATUS" = 400 ] && [ "$SECONDS" -lt "$deadline" ] &&
      jq -e 'any(.errors[]?; .reason | test("busy"; "i"))' "$WORK/answer.json" >/dev/null 2>&1; then
      [ "$said" = 1 ] || echo "   Linode $LINODE_ID is still busy with an earlier job; asking again every 10 s" >&2
      said=1
      sleep 10
      continue
    fi
    accepted "$1" "$2"
    return
  done
}

# api_list PATH: every item of a paged collection, as one JSON array.
api_list() {
  local page=1 pages=1 items='[]' answer
  while [ "$page" -le "$pages" ]; do
    answer="$(api GET "$1?page=$page&page_size=500")" || return 1
    pages="$(jq -r '.pages' <<<"$answer")"
    [[ "$pages" =~ ^[0-9]+$ ]] || { echo "nightly: GET $1 gave no page count" >&2; return 1; }
    items="$(printf '%s\n%s\n' "$items" "$answer" | jq -cs '.[0] + .[1].data')"
    page=$((page + 1))
  done
  printf '%s\n' "$items"
}

# wait_for SECONDS WHAT COMMAND...: runs COMMAND every 10 s until it succeeds.
wait_for() {
  local limit="$1" what="$2" deadline
  shift 2
  deadline=$((SECONDS + limit))
  until "$@"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "nightly: $what did not happen within $((limit / 60)) minutes" >&2
      return 1
    fi
    sleep 10
  done
}

instance_is() {
  call GET "/linode/instances/$LINODE_ID" && [ "$HTTP_STATUS" = 200 ] &&
    [ "$(jq -r .status "$WORK/answer.json")" = "$1" ]
}

disk_is_ready() {
  call GET "/linode/instances/$LINODE_ID/disks/$1" && [ "$HTTP_STATUS" = 200 ] &&
    [ "$(jq -r .status "$WORK/answer.json")" = ready ]
}

ssh_answers() {
  timeout 60 "$REPO/scripts/devvm/vm.sh" ssh true </dev/null >/dev/null 2>&1
}

# delete_and_wait PATH WHAT: deletes PATH, asking again while it is there, and
# returns once the API answers 404 for it.
delete_and_wait() {
  local path="$1" what="$2" deadline=$((SECONDS + 300))
  while :; do
    if call GET "$path" && [ "$HTTP_STATUS" = 404 ]; then
      log "deleted: $what"
      return 0
    fi
    if call DELETE "$path" && [ "$HTTP_STATUS" != 200 ] && [ "$HTTP_STATUS" != 404 ]; then
      echo "nightly: deleting $what answered HTTP $HTTP_STATUS: $(reasons)" >&2
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "nightly: $what is still there after 5 minutes of deleting" >&2
      return 1
    fi
    sleep 15
  done
}

# delete_run: deletes this run's Linode and firewall, by the IDs it got and by
# label, then checks that nothing with the label is left. The Linode goes
# first, so a running server is never without its firewall.
delete_run() {
  local failed=0 linodes="" firewalls="" id left
  local -a ids
  linodes="$(api_list /linode/instances)" || failed=1
  firewalls="$(api_list /networking/firewalls)" || failed=1
  mapfile -t ids < <({
    [ -z "$LINODE_ID" ] || echo "$LINODE_ID"
    [ -z "$linodes" ] || jq -r --arg l "$LABEL" '.[] | select(.label == $l) | .id' <<<"$linodes"
  } | sort -u)
  for id in "${ids[@]}"; do
    delete_and_wait "/linode/instances/$id" "Linode $id ($LABEL)" || failed=1
  done
  mapfile -t ids < <({
    [ -z "$FIREWALL_ID" ] || echo "$FIREWALL_ID"
    [ -z "$firewalls" ] || jq -r --arg l "$LABEL" '.[] | select(.label == $l) | .id' <<<"$firewalls"
  } | sort -u)
  for id in "${ids[@]}"; do
    delete_and_wait "/networking/firewalls/$id" "firewall $id ($LABEL)" || failed=1
  done

  if ! linodes="$(api_list /linode/instances)" || ! firewalls="$(api_list /networking/firewalls)"; then
    echo "LEFT ON THE ACCOUNT? The Linode API could not be asked what is left named $LABEL." >&2
    return 1
  fi
  left="$(jq -r --arg l "$LABEL" '.[] | select(.label == $l) | "Linode \(.id) \(.label) (\(.status))"' <<<"$linodes")
$(jq -r --arg l "$LABEL" '.[] | select(.label == $l) | "firewall \(.id) \(.label)"' <<<"$firewalls")"
  if [ -n "${left//[$'\n']/}" ]; then
    printf '%s\n' "$left" | sed '/^$/d; s/^/LEFT ON THE ACCOUNT: /' >&2
    return 1
  fi
  log "checked through the API: no Linode and no firewall named $LABEL is left"
  return "$failed"
}

# earlier_runs CUTOFF: the IDs in a Linode or firewall list (stdin) that this
# script made (both tags, the label) before CUTOFF (Unix time). The API gives
# times in UTC without a zone.
earlier_runs() {
  jq -r --argjson cutoff "$1" '.[]
    | select((.tags | any(. == "sifruno-nightly")) and (.tags | any(. == "delete-after-use"))
      and (.label | startswith("sifruno-nightly-"))
      and ((.created | sub("\\.[0-9]+$"; "") + "Z" | fromdateiso8601) < $cutoff))
    | .id'
}

# sweep: deletes Linodes and firewalls that earlier runs left behind.
sweep() {
  local cutoff list ids id
  cutoff=$(($(date -u +%s) - SWEEP_AGE_SECONDS))
  list="$(api_list /linode/instances)"
  ids="$(earlier_runs "$cutoff" <<<"$list")"
  for id in $ids; do
    delete_and_wait "/linode/instances/$id" "Linode $id, left by an earlier run"
  done
  list="$(api_list /networking/firewalls)"
  ids="$(earlier_runs "$cutoff" <<<"$list")"
  for id in $ids; do
    delete_and_wait "/networking/firewalls/$id" "firewall $id, left by an earlier run"
  done
}

is_public_ipv4() {
  local a b c d
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]})) c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
  ((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
  # This network, private, shared (carrier NAT), loopback, link-local,
  # IETF, benchmarking, multicast and reserved ranges.
  ((a == 0 || a == 10 || a == 127 || a >= 224)) && return 1
  ((a == 100 && b >= 64 && b <= 127)) && return 1
  ((a == 169 && b == 254)) && return 1
  ((a == 172 && b >= 16 && b <= 31)) && return 1
  ((a == 192 && b == 168)) && return 1
  ((a == 192 && b == 0 && c == 0)) && return 1
  ((a == 198 && (b == 18 || b == 19))) && return 1
  return 0
}

# runner_address DEST: sets RUNNER_IP to the IPv4 address this machine's
# connections to DEST come from, as DEST sees them, and RUNNER_IP_FROM to how
# it was found. The firewall admits SSH from that address only.
runner_address() {
  local src
  # A server whose public address is on its own interface: the kernel's route
  # to the Linode names it, and nobody is asked.
  src="$(ip -4 route get "$1" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')" || src=""
  if is_public_ipv4 "$src"; then
    RUNNER_IP="$src"
    RUNNER_IP_FROM="this machine's own address, from its route to the Linode"
    return 0
  fi
  # Behind NAT, as the CI runner's container is, only a machine outside sees
  # the address. Akamai, which owns Linode, answers at whatismyip.akamai.com:
  # it already holds the token, the server and its traffic, so asking it tells
  # nobody new where the runner is. A wrong answer fails safe: SSH then
  # cannot connect at all.
  src="$(curl -4 -sS --connect-timeout 10 --max-time 20 https://whatismyip.akamai.com/)" || src=""
  src="${src//[$'\t\r\n ']/}"
  if ! is_public_ipv4 "$src"; then
    echo "nightly: found no public IPv4 address for this machine, which the firewall must admit (whatismyip.akamai.com answered: ${src:0:40})" >&2
    return 1
  fi
  RUNNER_IP="$src"
  RUNNER_IP_FROM="the address whatismyip.akamai.com (Akamai, Linode's owner) sees, as this machine is behind NAT"
}

finish() {
  local status=$? left=0 fails=0 passes=0 verdict=1 seconds hours
  trap - EXIT
  # A second Ctrl-C, or a closed terminal, must not stop the deletion.
  trap '' INT TERM PIPE
  set +e
  if [ "$ARMED" = 1 ]; then
    log "Delete this run's Linode and firewall ($LABEL)"
    delete_run || left=1
  fi
  rm -rf -- "$WORK"

  echo
  if [ "$MODE" = cleanup ]; then
    [ "$left" = 0 ] && verdict=0
  else
    if [ -n "$TRANSCRIPT" ]; then
      fails="$(grep -c '^FAIL  ' "$TRANSCRIPT")"
      passes="$(grep -c '^PASS  ' "$TRANSCRIPT")"
    fi
    if [ "$TEST_STATUS" = 0 ] && [ "$status" = 0 ] && [ "$fails" = 0 ] && [ "$passes" -gt 0 ] &&
      grep -qx '# 0 check(s) failed' "$TRANSCRIPT"; then
      echo "PASS: the fresh-install test passed $passes checks on a new $TYPE Linode ($IMAGE). Transcript: $TRANSCRIPT"
      [ "$left" = 0 ] && verdict=0
    elif [ "$TEST_STATUS" = 124 ] || [ "$TEST_STATUS" = 137 ]; then
      echo "FAIL: the fresh-install test did not finish within $TEST_LIMIT. Look at the last lines of ${TRANSCRIPT:-$LOG} to see where it stopped."
    elif [ -n "$TEST_STATUS" ]; then
      echo "FAIL: the fresh-install test failed ($fails FAIL lines, exit status $TEST_STATUS). Look at the FAIL lines in ${TRANSCRIPT:-$LOG}, or at its last lines if it stopped early."
    else
      echo "FAIL: the run stopped before the test, at the step \"$STEP\" (exit status $status). Look at the lines above it in $LOG."
    fi
  fi
  if [ "$left" = 1 ]; then
    echo "FAIL: this run left something on the Linode account (the LEFT ON THE ACCOUNT lines above), and it is billed until it is deleted. Delete it in Cloud Manager under Linodes and Firewalls (label $LABEL), or run: SIFRUNO_NIGHTLY_ID=$ID scripts/ci/nightly-fresh-install.sh cleanup"
  elif [ "$ARMED" = 1 ] && [ "$MODE" = run ]; then
    echo "The Linode and its firewall are deleted: nothing named $LABEL is left on the account."
  fi
  if [ -n "$CREATED_AT" ]; then
    seconds=$((SECONDS - CREATED_AT))
    hours=$(((seconds + 3599) / 3600))
    echo "The Linode existed for $((seconds / 60)) min $((seconds % 60)) s. Linode bills each started hour; at ${PRICE:-an unknown price} USD an hour this run cost about $(awk -v h="$hours" -v p="${PRICE:-0}" 'BEGIN { printf "%.3f", h * p }') USD."
  fi
  echo "Log: $LOG"
  exec >&- 2>&-
  wait "$TEE_PID" 2>/dev/null
  exit "$verdict"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$MODE" = cleanup ]; then
  # finish deletes and checks.
  ARMED=1
  exit 0
fi

log "Nightly fresh-install test: a $TYPE Linode in $REGION from $IMAGE, named $LABEL"
echo "# source $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "# If this run is killed, delete what it made with: SIFRUNO_NIGHTLY_ID=$ID scripts/ci/nightly-fresh-install.sh cleanup"
PRICE="$(api GET "/linode/types/$TYPE" | jq -r --arg r "$REGION" '[.region_prices[]? | select(.id == $r) | .hourly][0] // .price.hourly')" || PRICE=""
[ -z "$PRICE" ] || echo "# price: $PRICE USD an hour"

STEP="build the release"
if [ -z "${SIFRUNO_RELEASE:-}" ]; then
  log "Build the release"
  "$REPO/scripts/install/build-release.sh"
  SIFRUNO_RELEASE="$REPO/artifacts/release/sifruno-linux-amd64.tar.gz"
fi
if [ ! -f "$SIFRUNO_RELEASE" ] || [ ! -f "$SIFRUNO_RELEASE.sha256" ]; then
  die "there is no release at $SIFRUNO_RELEASE with its .sha256 beside it"
fi
export SIFRUNO_RELEASE

STEP="delete what earlier runs left"
log "Delete Linodes and firewalls tagged sifruno-nightly that earlier runs left (older than 3 hours)"
sweep

STEP="make the SSH key"
install -d -m 0700 "$WORK/vm"
ssh-keygen -q -t ed25519 -N '' -C "$LABEL" -f "$WORK/vm/id_ed25519"
# scripts/devvm/vm.sh, and the test through it, reach the Linode with this
# key; the ports file written below names the Linode's address.
export SIFRUNO_DEVVM_DIR="$WORK/vm"

STEP="create the Linode"
log "Create the Linode, switched off, with no disks and no firewall yet"
ARMED=1
body="$(jq -cn --arg label "$LABEL" --arg region "$REGION" --arg type "$TYPE" --argjson tags "$TAGS" \
  '{label: $label, region: $region, type: $type, tags: $tags, booted: false,
    backups_enabled: false, private_ip: false, interface_generation: "legacy_config", firewall_id: -1}')"
answer="$(api POST /linode/instances "$body")"
CREATED_AT=$SECONDS
LINODE_ID="$(jq -r .id <<<"$answer")"
IP="$(jq -r '.ipv4[0] // empty' <<<"$answer")"
[[ "$LINODE_ID" =~ ^[0-9]+$ ]] || die "the API created a Linode but gave no ID for it"
is_public_ipv4 "$IP" || die "Linode $LINODE_ID has no public IPv4 address"
log "Linode $LINODE_ID created"
wait_for 300 "Linode $LINODE_ID to finish provisioning" instance_is offline

STEP="create the firewall"
runner_address "$IP"
log "Create the Cloud Firewall: SSH from $RUNNER_IP_FROM; everything else in is dropped"
body="$(jq -cn --arg label "$LABEL" --argjson tags "$TAGS" --arg from "$RUNNER_IP/32" --argjson linode "$LINODE_ID" \
  '{label: $label, tags: $tags, devices: {linodes: [$linode]},
    rules: {inbound_policy: "DROP", outbound_policy: "ACCEPT", outbound: [],
      inbound: [{label: "ssh-from-runner", description: "SSH from the machine that runs the nightly test",
        action: "ACCEPT", protocol: "TCP", ports: "22", addresses: {ipv4: [$from]}}]}}')"
answer="$(api POST /networking/firewalls "$body")"
FIREWALL_ID="$(jq -r .id <<<"$answer")"
[[ "$FIREWALL_ID" =~ ^[0-9]+$ ]] || die "the API created a firewall but gave no ID for it"
# The Linode boots only once the API shows this firewall, and only it, on it.
guards="$(api GET "/linode/instances/$LINODE_ID/firewalls")"
jq -e --argjson fw "$FIREWALL_ID" '[.data[] | select(.status == "enabled") | .id] == [$fw]' <<<"$guards" >/dev/null ||
  die "the API does not show firewall $FIREWALL_ID, enabled and alone, on Linode $LINODE_ID"
log "Firewall $FIREWALL_ID is on Linode $LINODE_ID"

STEP="create the disks"
log "Create the root disk: $IMAGE, $ROOT_DISK_MB MB, root signs in with this run's key"
# Deploying the image sets root's password from the request. This one is
# random, sent once and kept nowhere, so the run's key is the only way in.
root_pass="$(head -c 30 /dev/urandom | base64 | tr -d '\n/+=')"
[ "${#root_pass}" -ge 32 ] || die "could not make a random root password"
body="$(printf '%s' "$root_pass" | jq -cR --arg image "$IMAGE" --argjson size "$ROOT_DISK_MB" \
  --arg key "$(cat "$WORK/vm/id_ed25519.pub")" \
  '{label: "root", image: $image, size: $size, authorized_keys: [$key], root_pass: .}')"
unset root_pass
answer="$(api_when_free POST "/linode/instances/$LINODE_ID/disks" "$body")"
unset body
root_disk="$(jq -r .id <<<"$answer")"
[[ "$root_disk" =~ ^[0-9]+$ ]] || die "the API gave no ID for the root disk"
wait_for 600 "the root disk to be ready" disk_is_ready "$root_disk"
wait_for 300 "Linode $LINODE_ID to be idle" instance_is offline

log "Create the disk for /home: $HOME_DISK_MB MB, raw (formatted XFS on the server, as the installation guide says)"
answer="$(api_when_free POST "/linode/instances/$LINODE_ID/disks" \
  "$(jq -cn --argjson size "$HOME_DISK_MB" '{label: "home", filesystem: "raw", size: $size}')")"
home_disk="$(jq -r .id <<<"$answer")"
[[ "$home_disk" =~ ^[0-9]+$ ]] || die "the API gave no ID for the home disk"
wait_for 300 "the home disk to be ready" disk_is_ready "$home_disk"
wait_for 300 "Linode $LINODE_ID to be idle" instance_is offline

STEP="create the configuration profile"
# GRUB 2 boots AlmaLinux's own kernel, as a customer's server runs it, with
# SELinux enforcing; the test checks that it still is after the install.
answer="$(api_when_free POST "/linode/instances/$LINODE_ID/configs" \
  "$(jq -cn --argjson root "$root_disk" --argjson home "$home_disk" \
    '{label: "sifruno-nightly", kernel: "linode/grub2", root_device: "/dev/sda",
      devices: {sda: {disk_id: $root}, sdb: {disk_id: $home}},
      helpers: {network: true}, interfaces: [{purpose: "public"}]}')")"
config_id="$(jq -r .id <<<"$answer")"
[[ "$config_id" =~ ^[0-9]+$ ]] || die "the API gave no ID for the configuration profile"

STEP="boot the Linode"
log "Boot Linode $LINODE_ID: root disk in slot sda, home disk in slot sdb, GRUB 2"
api_when_free POST "/linode/instances/$LINODE_ID/boot" "$(jq -cn --argjson c "$config_id" '{config_id: $c}')" >/dev/null
wait_for 600 "Linode $LINODE_ID to run" instance_is running

STEP="reach the Linode over SSH"
printf 'VM_HOST=%s\nSSH_PORT=22\n' "$IP" >"$WORK/vm/ports"
log "Wait for SSH; the firewall admits $RUNNER_IP_FROM"
wait_for 600 "SSH on Linode $LINODE_ID to answer" ssh_answers

STEP="put /home on its own XFS disk"
log "Put /home on the second disk: XFS, mounted with user and group quota (docs/installation.md, Set up /home)"
timeout 15m "$REPO/scripts/devvm/vm.sh" ssh "bash -s -- $((HOME_DISK_MB * 1024 * 1024))" <<'GUEST'
set -euo pipefail
want="$1"
# Linode's image runs cloud-init at first boot; let it finish first.
if command -v cloud-init >/dev/null; then timeout 600 cloud-init status --wait >/dev/null 2>&1 || true; fi
# The kernel names disks in the order it finds them, not by the configuration
# profile's slots: on a test boot sdb was the root disk. So the home disk is
# found by what it is: a whole disk of its size, unmounted, unpartitioned and
# blank. Exactly one must match, or nothing is formatted.
lsblk -dno NAME,SIZE,TYPE | sed 's/^/  disk /'
found=()
while read -r dev type; do
  if [ "$type" != disk ]; then continue; fi
  size="$(blockdev --getsize64 "$dev")"
  if [ "$size" -lt $((want * 95 / 100)) ] || [ "$size" -gt $((want * 105 / 100)) ]; then continue; fi
  if [ "$(lsblk -nro NAME "$dev" | wc -l)" != 1 ]; then continue; fi
  if findmnt -S "$dev" >/dev/null || blkid -p "$dev" >/dev/null 2>&1; then continue; fi
  found+=("$dev")
done < <(lsblk -dnpo NAME,TYPE)
if [ "${#found[@]}" != 1 ]; then
  echo "Found ${#found[@]} blank, unmounted disks of about $want bytes, not exactly one; nothing is formatted." >&2
  exit 1
fi
home_dev="${found[0]}"
echo "home disk: $home_dev"
if findmnt /home >/dev/null; then echo "/home is already a mount point." >&2; exit 1; fi
command -v mkfs.xfs >/dev/null || dnf -y -q install xfsprogs
mkfs.xfs -q "$home_dev"
echo "UUID=$(blkid -s UUID -o value "$home_dev") /home xfs defaults,usrquota,grpquota 0 0" >>/etc/fstab
systemctl daemon-reload
mount /home
mounted="$(findmnt -no FSTYPE,OPTIONS /home)"
state="$(xfs_quota -x -c 'state -u' /home)"
echo "/home: $mounted"
echo "SELinux context of /home: $(stat -c %C /home)"
printf '%s\n' "$state" | grep -E 'Accounting|Enforcement' | sed 's/^ */  user quota /'
[[ "$mounted" =~ ^xfs\ .*usrquota ]] || { echo "/home is not XFS with usrquota." >&2; exit 1; }
if ! grep -q 'Accounting: ON' <<<"$state" || ! grep -q 'Enforcement: ON' <<<"$state"; then
  echo "User quota is not on for /home." >&2
  exit 1
fi
GUEST

STEP="run the fresh-install test"
touch "$WORK/test-started"
log "Run scripts/devvm/fresh-install-test.sh --existing-host (at most $TEST_LIMIT)"
set +e
SIFRUNO_PROOF_OUT="$OUT" timeout --kill-after=1m "$TEST_LIMIT" \
  "$REPO/scripts/devvm/fresh-install-test.sh" --existing-host </dev/null
TEST_STATUS=$?
set -e
TRANSCRIPT="$(find "$OUT" -maxdepth 1 -name 'fresh-install-*.txt' -newer "$WORK/test-started" | sort | tail -n 1)"
STEP="delete the Linode"
[ "$TEST_STATUS" = 0 ] || exit 1
