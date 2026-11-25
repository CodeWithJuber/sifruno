#!/usr/bin/env bash
# Disposable AlmaLinux 9 dev VM for the proofs in docs/PRODUCT-PLAN.md.
#
# The VM runs under QEMU as an ordinary user: KVM when /dev/kvm is usable,
# software emulation otherwise (works anywhere, several times slower). It is
# reachable only through loopback port forwards, and root signs in with a key
# generated for this VM alone. Nothing here touches a real server.
set -euo pipefail

DIR="${SIFRUNO_DEVVM_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sifruno-devvm}"
CPUS="${SIFRUNO_DEVVM_CPUS:-4}"
MEM_MB="${SIFRUNO_DEVVM_MEM_MB:-4096}"

# Pinned image. To move to a newer build, take the name and SHA-256 from
# https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM
IMAGE_NAME="AlmaLinux-9-GenericCloud-9.9-20261116.x86_64.qcow2"
IMAGE_SHA256="50e428e36083531995df84302268b95f0bf30db1d5e6b931f73dc40642dd77bb"
IMAGE_URL="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/${IMAGE_NAME}"

usage() {
  cat <<'USAGE'
usage: vm.sh <command>
  create      download the pinned image, make the key, disks and cloud-init seed
  start       boot the VM and wait until SSH answers
  ssh [cmd]   run a command (or open a shell) as root in the VM
  put SRC DST copy a local file into the VM
  get SRC DST copy a file out of the VM
  forward PORT
              forward 127.0.0.1:PORT on this host to 127.0.0.1:PORT in the VM
              over SSH until stopped (the panel binds loopback only)
  status      say whether the VM is running and on which ports
  stop        power the VM off
  destroy     stop the VM and delete its disks, key and seed (keeps the image)
Environment: SIFRUNO_DEVVM_DIR (state directory), SIFRUNO_DEVVM_CPUS, SIFRUNO_DEVVM_MEM_MB
USAGE
}

need() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || { echo "vm.sh: missing program: $tool" >&2; exit 1; }
  done
}

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

running() {
  [ -f "$DIR/qemu.pid" ] && kill -0 "$(cat "$DIR/qemu.pid")" 2>/dev/null
}

ssh_base() {
  # shellcheck disable=SC1091
  . "$DIR/ports"
  # A ports file may name another host (VM_HOST=address, SSH_PORT=22): a
  # throwaway cloud server used in place of the local VM. ssh, put, get and
  # forward then reach it; create, start and stop stay QEMU-only.
  VM_HOST="${VM_HOST:-127.0.0.1}"
  SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$DIR/known_hosts"
    -o ConnectTimeout=30 -o ServerAliveInterval=30 -o BatchMode=yes -o LogLevel=ERROR
    -i "$DIR/id_ed25519")
}

cmd_create() {
  need curl sha256sum qemu-img cloud-localds ssh-keygen
  mkdir -p "$DIR"
  chmod 700 "$DIR"
  if [ ! -f "$DIR/base.qcow2" ]; then
    echo "Downloading $IMAGE_NAME"
    curl -fL --retry 3 -o "$DIR/base.qcow2.part" "$IMAGE_URL"
    echo "$IMAGE_SHA256  $DIR/base.qcow2.part" | sha256sum -c -
    mv "$DIR/base.qcow2.part" "$DIR/base.qcow2"
  fi
  if [ -f "$DIR/root.qcow2" ]; then
    echo "vm.sh: a VM already exists in $DIR; run 'vm.sh destroy' first" >&2
    exit 1
  fi
  [ -f "$DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C sifruno-devvm -f "$DIR/id_ed25519"
  # Root is the only login, so /home starts empty: the account broker needs a
  # homes directory that holds nothing but its own accounts. The second disk
  # becomes /home on XFS with user and group quota switched on at mount time,
  # which is the only moment XFS lets quota be enabled.
  cat > "$DIR/user-data" <<SEED
#cloud-config
hostname: sifruno-dev
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$DIR/id_ed25519.pub")
fs_setup:
  - device: /dev/vdb
    filesystem: xfs
    label: sifhome
    overwrite: false
mounts:
  - [/dev/vdb, /home, xfs, "defaults,uquota,gquota", "0", "0"]
SEED
  printf 'instance-id: sifruno-dev-%s\nlocal-hostname: sifruno-dev\n' "$(date +%s)" > "$DIR/meta-data"
  cloud-localds "$DIR/seed.iso" "$DIR/user-data" "$DIR/meta-data"
  qemu-img create -q -f qcow2 -F qcow2 -b "$DIR/base.qcow2" "$DIR/root.qcow2" 24G
  qemu-img create -q -f qcow2 "$DIR/home.qcow2" 8G
  echo "Created. Next: vm.sh start"
}

# boot_vm starts QEMU on the ports in $DIR/ports, with $accel and $cpu set.
boot_vm() {
  qemu-system-x86_64 -name sifruno-dev -machine q35 -accel "$accel" -cpu "$cpu" \
    -smp "$CPUS" -m "$MEM_MB" -display none -monitor none -serial "file:$DIR/console.log" \
    -drive "file=$DIR/root.qcow2,if=virtio,cache=unsafe" \
    -drive "file=$DIR/home.qcow2,if=virtio,cache=unsafe" \
    -drive "file=$DIR/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22,hostfwd=tcp:127.0.0.1:${HTTP_PORT}-:80,hostfwd=tcp:127.0.0.1:${HTTPS_PORT}-:443" \
    -device virtio-net-pci,netdev=n0 -device virtio-rng-pci \
    -daemonize -pidfile "$DIR/qemu.pid"
}

cmd_start() {
  need qemu-system-x86_64 python3 ssh
  [ -f "$DIR/root.qcow2" ] || { echo "vm.sh: no VM in $DIR; run 'vm.sh create' first" >&2; exit 1; }
  accel="tcg,thread=multi"
  cpu="max"
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    accel="kvm"
    cpu="host"
  fi
  if running; then
    echo "Already running"
  else
    printf 'SSH_PORT=%s\nHTTP_PORT=%s\nHTTPS_PORT=%s\n' "$(free_port)" "$(free_port)" "$(free_port)" > "$DIR/ports"
    # shellcheck disable=SC1091
    . "$DIR/ports"
    [ "$accel" = kvm ] || echo "No usable /dev/kvm: using software emulation. Expect the first boot to take a few minutes."
    boot_vm
  fi
  ssh_base
  echo "Waiting for SSH on 127.0.0.1:${SSH_PORT}"
  local boots=1
  for _ in $(seq 1 90); do
    if ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 'cloud-init status --wait >/dev/null 2>&1; true' 2>/dev/null; then
      echo "Up: ssh ${SSH_PORT}, http ${HTTP_PORT}, https ${HTTPS_PORT}"
      return 0
    fi
    running || { echo "vm.sh: QEMU exited; see $DIR/console.log" >&2; exit 1; }
    # Under software emulation on a busy host the guest's disks can appear
    # after its initramfs stopped waiting for the root filesystem (90 s);
    # the guest then sits in its emergency shell. Boot it again, a few times.
    if grep -aq 'Entering emergency mode' "$DIR/console.log" 2>/dev/null; then
      if [ "$boots" -ge 3 ]; then
        echo "vm.sh: the guest stopped in its emergency shell on $boots boots; see $DIR/console.log" >&2
        exit 1
      fi
      echo "The guest's initramfs gave up waiting for its disks (a slow boot under emulation); booting it again."
      kill "$(cat "$DIR/qemu.pid")" 2>/dev/null || true
      for _ in $(seq 1 15); do running || break; sleep 1; done
      mv -f "$DIR/console.log" "$DIR/console.boot$boots.log"
      boots=$((boots + 1))
      boot_vm
    fi
    sleep 10
  done
  echo "vm.sh: SSH did not answer in 15 minutes; see $DIR/console.log" >&2
  exit 1
}

cmd_ssh() {
  ssh_base
  exec ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" "root@$VM_HOST" "$@"
}

cmd_put() {
  [ $# -eq 2 ] || { usage >&2; exit 2; }
  ssh_base
  exec scp -q "${SSH_OPTS[@]}" -P "$SSH_PORT" "$1" "root@$VM_HOST:$2"
}

cmd_get() {
  [ $# -eq 2 ] || { usage >&2; exit 2; }
  ssh_base
  exec scp -q "${SSH_OPTS[@]}" -P "$SSH_PORT" "root@$VM_HOST:$1" "$2"
}

cmd_forward() {
  [ $# -eq 1 ] || { usage >&2; exit 2; }
  case "$1" in ''|*[!0-9]*) usage >&2; exit 2 ;; esac
  ssh_base
  exec ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" -N -o ExitOnForwardFailure=yes -L "127.0.0.1:$1:127.0.0.1:$1" "root@$VM_HOST"
}

cmd_status() {
  if running; then
    # shellcheck disable=SC1091
    . "$DIR/ports"
    echo "running: pid $(cat "$DIR/qemu.pid"), ssh ${SSH_PORT}, http ${HTTP_PORT}, https ${HTTPS_PORT}"
  else
    echo "stopped"
  fi
}

cmd_stop() {
  running || { echo "Not running"; return 0; }
  ssh_base
  ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 'systemctl poweroff' 2>/dev/null || true
  for _ in $(seq 1 30); do
    running || { echo "Stopped"; return 0; }
    sleep 2
  done
  kill "$(cat "$DIR/qemu.pid")" 2>/dev/null || true
  echo "Stopped (QEMU killed after the guest ignored poweroff)"
}

cmd_destroy() {
  cmd_stop
  # Named files only: this script never deletes by pattern.
  for name in root.qcow2 home.qcow2 seed.iso user-data meta-data ports qemu.pid console.log known_hosts id_ed25519 id_ed25519.pub; do
    [ -e "$DIR/$name" ] && rm -f -- "$DIR/$name"
  done
  echo "Destroyed. The base image stays in $DIR for the next create."
}

case "${1:-}" in
  create) cmd_create ;;
  start) cmd_start ;;
  ssh) shift; cmd_ssh "$@" ;;
  put) shift; cmd_put "$@" ;;
  get) shift; cmd_get "$@" ;;
  forward) shift; cmd_forward "$@" ;;
  status) cmd_status ;;
  stop) cmd_stop ;;
  destroy) cmd_destroy ;;
  *) usage; exit 2 ;;
esac
