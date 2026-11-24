#!/usr/bin/env bash
# Sifruno's installer for a fresh AlmaLinux 9 server (x86_64). Run it as root
# from the extracted release, where it sits next to bin/, ui/ and SHA256SUMS:
#
#   ./install.sh [--panel-host NAME] [--acme-email ADDR] [--no-start] [--dry-run]
#
# It checks the server first and changes nothing when a check fails. Running
# it again is safe: a second run changes nothing. It never changes the
# SELinux mode or the firewall. The dev VM's provisioning
# (scripts/devvm/provision.sh) runs this same file.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly PREFIX=/usr/local/lib/sifruno
readonly BIN_DIR="$PREFIX/bin"
readonly UI_DIR="$PREFIX/ui"
readonly PROGRAMS=(sifruno hostbroker hostsetup panelctl)
readonly BROKER_STATE=/var/lib/sifruno-broker
readonly BROKER_SOCKET=/run/sifruno-broker/control.sock
readonly HOMES=/home
readonly PANEL_USER=sifpanel
readonly PANEL_HOME=/var/lib/sifpanel
readonly PANEL_STATE="$PANEL_HOME/state"
readonly DB_ADMIN_CNF="$PANEL_HOME/db-admin.cnf"
readonly ACME_DIR=/var/lib/sifruno-acme
readonly PANEL_LISTEN=127.0.0.1:8080
readonly PANEL_HTTPS_LISTEN=0.0.0.0:8443
readonly LSWS=/usr/local/lsws
readonly OLS_CONF="$LSWS/conf/httpd_config.conf"
readonly NSSWITCH=/etc/nsswitch.conf
readonly SSHD_CONFIG=/etc/ssh/sshd_config
readonly SSHD_INCLUDE='Include /etc/ssh/sshd_config.d/*.conf'
readonly SSHD_DROPIN=/etc/ssh/sshd_config.d/40-sifruno.conf
readonly BROKER_UNIT=sifruno-broker.service
readonly PANEL_UNIT=sifruno.service
readonly UNIT_DIR=/etc/systemd/system
readonly PACKAGES=(openlitespeed
  lsphp83 lsphp83-common lsphp83-mysqlnd lsphp83-gd lsphp83-mbstring lsphp83-xml
  lsphp83-opcache lsphp83-intl lsphp83-zip lsphp83-process lsphp83-bcmath lsphp83-pdo
  mariadb-server podman openssh-clients rsync tar unzip policycoreutils-python-utils xfsprogs quota
  httpd httpd-tools)
# The broker runs this file only while its bytes match the sha512 pinned in
# internal/hostaccounts/wordpress_linux.go (WP-CLI 2.12.0's published one).
readonly WPCLI_VERSION=2.12.0
readonly WPCLI_SHA512=be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832
STAMP="$(date +%Y%m%d-%H%M)"
readonly STAMP

PANEL_HOST=""
ACME_EMAIL=""
START=yes
DRY_RUN=no
REFUSALS=0
PLAN_STEP=0
CHANGES=()
RESTART_NEEDED=no
UNITS_WRITTEN=no
NSS_BACKUP=""
SSHD_BACKUP=""
SSHD_CHANGE=unchanged
SSH_ADMIN=""
OLS_BACKUP=""

usage() {
  cat <<'USAGE'
usage: install.sh [--panel-host NAME] [--acme-email ADDR] [--no-start] [--dry-run]
  --panel-host NAME   also serve the panel over HTTPS on 0.0.0.0:8443 for this
                      host name or IP (several: comma-separated). Without it
                      the panel answers on 127.0.0.1:8080 only.
  --acme-email ADDR   contact address for Let's Encrypt. It turns on website
                      certificates and accepts the certificate authority's
                      terms of service.
  --no-start          install everything, but do not enable or start the two
                      Sifruno units.
  --dry-run           check the server and print the plan; change nothing.
USAGE
}

log() { printf '== %s %s\n' "$(date -u +%FT%TZ)" "$*"; }

# An error says what happened, why, and what to do next.
die() { # die WHAT WHY TODO
  printf '\ninstall.sh: %s\n  Why: %s\n  What to do: %s\n' "$1" "$2" "$3" >&2
  exit 1
}

refuse() { # refuse WHAT WHY TODO
  REFUSALS=$((REFUSALS + 1))
  printf 'REFUSED: %s\n  Why: %s\n  What to do: %s\n' "$1" "$2" "$3" >&2
}

changed() { CHANGES+=("$1"); }

step() { # step DESCRIPTION FUNCTION
  PLAN_STEP=$((PLAN_STEP + 1))
  if [ "$DRY_RUN" = yes ]; then
    printf '  %2d. %s\n' "$PLAN_STEP" "$1"
    return 0
  fi
  log "$1"
  "$2"
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --panel-host)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        PANEL_HOST="$2"
        shift 2
        ;;
      --acme-email)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        ACME_EMAIL="$2"
        shift 2
        ;;
      --no-start) START=no; shift ;;
      --dry-run) DRY_RUN=yes; shift ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
  done
  # Both values go into a unit file, so they admit only the characters a
  # host name, an IP address or an email address needs.
  if [ -n "$PANEL_HOST" ] && ! [[ "$PANEL_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.:-]*[A-Za-z0-9])?(,[A-Za-z0-9]([A-Za-z0-9.:-]*[A-Za-z0-9])?)*$ ]]; then
    die "--panel-host is not a host name or IP address: $PANEL_HOST" \
      "The value becomes the panel's --panel-host option in its systemd unit." \
      "Give a name such as panel.example.com or an IP address; separate several with commas."
  fi
  if [ -n "$ACME_EMAIL" ] && ! [[ "$ACME_EMAIL" =~ ^[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
    die "--acme-email is not an email address: $ACME_EMAIL" \
      "Let's Encrypt sends expiry and account notices to this address." \
      "Give an address such as admin@example.com."
  fi
}

# ---------------------------------------------------------------- preflight

# True when PATH is absent or an empty folder. A folder this user cannot
# read counts as not empty.
dir_fresh() {
  [ -e "$1" ] || return 0
  [ -d "$1" ] && [ -r "$1" ] || return 1
  [ -z "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]
}

# True when the broker has never run here.
broker_state_fresh() { dir_fresh "$BROKER_STATE"; }

sshd_policy() {
  # Deny by default: every login is SFTP-only and uses the key file the
  # broker writes, unless it is root or in wheel. An account the broker
  # forgot to classify therefore still cannot get a shell or forward a port.
  cat <<'SSHD'
# Managed by the Sifruno installer (install.sh). Hosting accounts are
# SFTP-only with broker-managed keys; root and wheel sign in as before,
# with a key.
AuthorizedKeysFile /etc/sifruno/ssh/authorized_keys/%u
ForceCommand internal-sftp
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserRC no

Match User root
    AuthorizedKeysFile .ssh/authorized_keys
    ForceCommand none
    AllowTcpForwarding yes
    AllowAgentForwarding yes
    PermitTTY yes

Match Group wheel
    AuthorizedKeysFile .ssh/authorized_keys
    ForceCommand none
    AllowTcpForwarding yes
    AllowAgentForwarding yes
    PermitTTY yes
SSHD
}

sshd_policy_current() { sshd_policy | cmp -s - "$SSHD_DROPIN" 2>/dev/null; }

# Builds, in a new private temporary folder, a copy of sshd's configuration
# as it will be with the Sifruno drop-in in place, and prints the folder.
# sshd checks and evaluates the copy (-t and -T with -f) before anything
# on the server changes. Fails when sshd_config does not include its
# drop-in folder the way AlmaLinux 9 does.
sshd_candidate() {
  local dir file ok=yes
  # Callers run this inside a condition, where set -e does not apply, so
  # each step is checked; on a failure the folder is removed again.
  grep -qxF "$SSHD_INCLUDE" "$SSHD_CONFIG" || return 1
  dir="$(mktemp -d)" || return 1
  mkdir "$dir/sshd_config.d" || ok=no
  for file in /etc/ssh/sshd_config.d/*.conf; do
    if [ "$ok" = yes ] && [ -e "$file" ] && [ "$file" != "$SSHD_DROPIN" ]; then
      cp -L -- "$file" "$dir/sshd_config.d/" || ok=no
    fi
  done
  if [ "$ok" = yes ] && sshd_policy > "$dir/sshd_config.d/${SSHD_DROPIN##*/}" &&
    awk -v inc="$SSHD_INCLUDE" -v new="Include $dir/sshd_config.d/*.conf" \
      '$0 == inc { print new; next } { print }' "$SSHD_CONFIG" > "$dir/sshd_config"; then
    printf '%s' "$dir"
    return 0
  fi
  rm -rf -- "$dir"
  return 1
}

# The connection sshd -T judges Match rules for: the SSH connection this
# installer runs in, when SSH_CONNECTION names one, so a Match Address or
# Match Host rule is judged for the admin's own way in. Prints the -C
# fields after user=, or nothing when there is no such connection.
ssh_connection_spec() {
  local client cport server sport
  read -r client cport server sport <<<"${SSH_CONNECTION:-}" || true
  if [[ "$client" =~ ^[0-9A-Fa-f.:]+$ && "$server" =~ ^[0-9A-Fa-f.:]+$ && "$sport" =~ ^[0-9]+$ && "$cport" =~ ^[0-9]+$ ]]; then
    printf 'host=%s,addr=%s,laddr=%s,lport=%s' "$client" "$client" "$server" "$sport"
  fi
}

# Whether the sshd configuration CONFIG, with the drop-ins next to it, has
# a Match rule that depends on where a connection comes from or arrives.
sshd_has_address_match() { # sshd_has_address_match CONFIG
  local files=("$1")
  local file
  for file in "$(dirname -- "$1")"/sshd_config.d/*.conf; do
    [ -e "$file" ] && files+=("$file")
  done
  grep -Eiqs '^[[:space:]]*Match[[:space:]].*\b(Address|Host|LocalAddress|LocalPort|RDomain)\b' -- "${files[@]}"
}

# The value sshd -T prints for KEYWORD, its lines joined by spaces.
sshd_value() {
  awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); out = out (out == "" ? "" : " ") $0 } END { print out }'
}

# Whether sshd, under StrictModes, reads the key file PATH of the user with
# UID and HOME: the file and every folder above it, up to HOME (or to / for
# a file outside HOME), belong to the user or root and are not writable by
# group or others. sshd checks the resolved path, so this does too.
key_file_secure() { # key_file_secure PATH UID HOME
  local path owner mode
  path="$(realpath -e -- "$1" 2>/dev/null)" || return 1
  while :; do
    read -r owner mode < <(stat -c '%u %a' -- "$path") || return 1
    [ "$owner" = "$2" ] || [ "$owner" = 0 ] || return 1
    [ $((8#$mode & 8#022)) -eq 0 ] || return 1
    if [ "$path" = "$3" ] || [ "$path" = / ]; then
      return 0
    fi
    path="$(dirname -- "$path")"
  done
}

# Whether USER can sign in over SSH with a key under the sshd configuration
# CONFIG, looking the user up in the local files only, as the server will
# once nsswitch names only files. That needs a login shell; public-key
# sign-in on, no ForceCommand and no AuthenticationMethods beyond a key;
# for root, a PermitRootLogin that allows keys; and a key file sshd accepts
# holding at least one valid key. AllowUsers, AllowGroups, DenyUsers and
# DenyGroups are read in their simplest form only: the user must be named
# in AllowUsers when it is set, and no group or deny rule may be set. Match
# rules are judged for the SSH connection the installer runs in; without
# one, a Match rule on addresses or hosts cannot be judged and fails this.
ssh_admin_ok() { # ssh_admin_ok CONFIG USER
  local config="$1" user="$2" entry uid home shell eff allow file files strict where
  entry="$(getent -s files passwd "$user")" || return 1
  IFS=: read -r _ _ uid _ _ home shell <<<"$entry"
  case "$shell" in "" | */nologin | */false) return 1 ;; esac
  grep -qxF "$shell" /etc/shells || return 1
  where="$(ssh_connection_spec)"
  if [ -z "$where" ]; then
    ! sshd_has_address_match "$config" || return 1
    where="host=localhost,addr=127.0.0.1"
  fi
  eff="$(sshd -T -f "$config" -C "user=$user,$where" 2>/dev/null)" || return 1
  [ "$(sshd_value pubkeyauthentication <<<"$eff")" = yes ] || return 1
  [ "$(sshd_value forcecommand <<<"$eff")" = none ] || return 1
  case "$(sshd_value authenticationmethods <<<"$eff")" in any | publickey) ;; *) return 1 ;; esac
  if [ "$user" = root ]; then
    case "$(sshd_value permitrootlogin <<<"$eff")" in yes | prohibit-password | without-password) ;; *) return 1 ;; esac
  fi
  [ -z "$(sshd_value denyusers <<<"$eff")$(sshd_value denygroups <<<"$eff")$(sshd_value allowgroups <<<"$eff")" ] || return 1
  allow="$(sshd_value allowusers <<<"$eff")"
  if [ -n "$allow" ] && [[ " $allow " != *" $user "* ]]; then
    return 1
  fi
  strict="$(sshd_value strictmodes <<<"$eff")"
  read -ra files <<<"$(sshd_value authorizedkeysfile <<<"$eff")"
  for file in "${files[@]}"; do
    file="${file//%%/$'\x01'}"
    file="${file//%u/$user}"
    file="${file//%U/$uid}"
    file="${file//%h/$home}"
    file="${file//$'\x01'/%}"
    [[ "$file" == /* ]] || file="$home/$file"
    if [ -f "$file" ] && ssh-keygen -l -f "$file" >/dev/null 2>&1 &&
      { [ "$strict" = no ] || key_file_secure "$file" "$uid" "$home"; }; then
      return 0
    fi
  done
  return 1
}

# Prints the first of root and wheel's members (as /etc/group lists them)
# who can sign in with a key under the sshd configuration CONFIG.
ssh_admin() { # ssh_admin CONFIG
  local user members
  members="$(getent -s files group wheel | cut -d: -f4)"
  for user in root ${members//,/ }; do
    if ssh_admin_ok "$1" "$user"; then
      printf '%s' "$user"
      return 0
    fi
  done
  return 1
}

# Local users with a login shell who are neither root, nor in wheel, nor a
# hosting account (home in $HOMES): the policy would make them SFTP-only.
other_login_users() {
  local wheel
  wheel=",$(getent -s files group wheel | cut -d: -f4),"
  getent -s files passwd | awk -F: -v homes="$HOMES/" -v wheel="$wheel" '
    $3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ && index($6, homes) != 1 && index(wheel, "," $1 ",") == 0 { print $1 }' |
    paste -sd ' '
}

# Checks the sshd policy before anything changes: sshd must accept the whole
# configuration with it, someone must still be able to sign in with a key,
# and no other local login may lose its shell. Prints why on refusal.
preflight_sshd() {
  local candidate others out
  if ! candidate="$(sshd_candidate)"; then
    refuse "$SSHD_CONFIG does not have the line '$SSHD_INCLUDE'." \
      "The installer's sshd policy is a drop-in in that folder, and it checks the policy on a copy of the full configuration before any change." \
      "Put that line back near the top of $SSHD_CONFIG, where AlmaLinux 9 has it, then run this again."
    return 0
  fi
  if ! out="$(sshd -t -f "$candidate/sshd_config" 2>&1)"; then
    printf '%s\n' "$out" | sed 's/^/  sshd: /' >&2
    refuse "sshd rejects its configuration with the installer's policy added." \
      "sshd checked a copy of its configuration with the drop-in $SSHD_DROPIN in place (lines above)." \
      "Run sshd -t, fix what it reports in the other files, then run this again."
  elif SSH_ADMIN="$(ssh_admin "$candidate/sshd_config")"; then
    echo "ok: $SSH_ADMIN can still sign in over SSH with a key once the policy is in place"
  else
    refuse "Nobody could sign in over SSH once the installer's policy is in place." \
      "The policy turns password sign-in off. No root or wheel member in /etc/passwd has a login shell, a valid key in a key file sshd accepts (owner and mode), and nothing in the way: PermitRootLogin no for root, a ForceCommand, AuthenticationMethods, an Allow or Deny rule, or a Match rule on addresses or hosts while the installer does not run over SSH." \
      "Add your public key to /root/.ssh/authorized_keys or a local wheel user's, sign in with it once in a second session, then run this again over SSH (with sudo, keep SSH_CONNECTION: sudo --preserve-env=SSH_CONNECTION ./install.sh). To see what sshd would apply: sshd -T -C user=root,host=localhost,addr=127.0.0.1"
  fi
  rm -rf -- "$candidate"
  others="$(other_login_users)"
  if [ -n "$others" ]; then
    refuse "These local users have a login shell but are neither root nor in wheel: $others." \
      "The installer's sshd policy makes such users SFTP-only and reads their keys from /etc/sifruno/ssh/authorized_keys, so their SSH access as it is now would stop." \
      "Add each one who needs a shell to wheel (usermod -aG wheel NAME), or give the others /usr/sbin/nologin, then run this again."
  fi
}

preflight() {
  local os_id os_version os_name arch home_fs home_opts home_meta home_entry selinux
  log "Preflight: nothing is changed until every check passes"

  if [ "$(id -u)" -ne 0 ]; then
    refuse "This is not running as root (you are $(id -un))." \
      "The installer adds packages, a system user, systemd units and host policy, which only root can do." \
      "Run it as root, for example: sudo ./install.sh"
  else
    echo "ok: running as root"
  fi

  # shellcheck disable=SC1091
  os_id="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")"
  # shellcheck disable=SC1091
  os_version="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")"
  # shellcheck disable=SC1091
  os_name="$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}")"
  if [ "$os_id" != almalinux ] || [ "${os_version%%.*}" != 9 ]; then
    refuse "This server runs ${os_name:-an unknown system}, not AlmaLinux 9." \
      "Sifruno's repositories, packages and host policy are built and tested for AlmaLinux 9 only." \
      "Install on a fresh AlmaLinux 9 server."
  else
    echo "ok: $os_name"
  fi

  arch="$(uname -m)"
  if [ "$arch" != x86_64 ]; then
    refuse "This machine is $arch, not x86_64." \
      "The release holds linux-amd64 programs and LiteSpeed's repository is x86_64." \
      "Use an x86_64 (amd64) server."
  else
    echo "ok: x86_64"
  fi

  home_fs="$(findmnt -n -o FSTYPE --mountpoint "$HOMES" 2>/dev/null | tail -n 1 || true)"
  home_opts="$(findmnt -n -o OPTIONS --mountpoint "$HOMES" 2>/dev/null | tail -n 1 || true)"
  if [ "$home_fs" != xfs ] || [[ ",$home_opts," != *,usrquota,* ]]; then
    if [ -z "$home_fs" ]; then
      home_fs="not a filesystem of its own"
    else
      home_fs="$home_fs, mounted with $home_opts"
    fi
    refuse "$HOMES is not an XFS filesystem with user quota enforced (it is $home_fs)." \
      "Each website's disk limit is an XFS user quota on $HOMES, and XFS turns quota on only when the filesystem is mounted." \
      "Put $HOMES on its own XFS filesystem, mount it with usrquota,grpquota in /etc/fstab, and run this again. docs/installation.md has the commands."
  else
    echo "ok: $HOMES is XFS with user quota enforced"
    # The broker takes an empty /home as its own on first start. Later runs
    # find its accounts there, which is as it should be.
    if broker_state_fresh; then
      home_meta="$(stat -c '%U:%G %a' "$HOMES")"
      home_entry="$(find "$HOMES" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)"
      if [ "$home_meta" != "root:root 755" ]; then
        refuse "$HOMES is $home_meta, not root:root 755." \
          "The account broker accepts only a root-owned $HOMES that others cannot write." \
          "Run: chown root:root $HOMES && chmod 0755 $HOMES"
      elif [ -n "$home_entry" ]; then
        refuse "$HOMES is not empty (it holds $home_entry)." \
          "On first start the account broker takes $HOMES as its own, so every home in it must be one the broker made." \
          "Move other users' homes out of $HOMES (for example: usermod -m -d /var/home/NAME NAME) or remove them, then run this again."
      else
        echo "ok: $HOMES is empty and root's"
      fi
    fi
  fi

  if ! sshd_policy_current; then
    if [ "$(id -u)" -ne 0 ]; then
      echo "not checked without root: who can still sign in over SSH once the policy is in place"
    else
      preflight_sshd
    fi
  fi

  if command -v getenforce >/dev/null 2>&1; then
    selinux="$(getenforce 2>/dev/null || true)"
    echo "SELinux is ${selinux:-unknown}; the installer leaves the SELinux mode as it is"
  fi
}

verify_release() {
  local listed present odd name
  log "Checking the release in $HERE against its SHA256SUMS"
  [ -f "$HERE/SHA256SUMS" ] || die "There is no SHA256SUMS next to install.sh in $HERE." \
    "The installer installs only files whose checksums it can verify." \
    "Run install.sh from the folder the release tarball unpacks to."
  odd="$(cd "$HERE" && find . ! -type f ! -type d -print -quit)"
  [ -z "$odd" ] || die "The release holds something that is neither a file nor a folder: $odd" \
    "A release has plain files only, so this copy was changed after it was built." \
    "Unpack the release tarball again and run its install.sh."
  if ! (cd "$HERE" && sha256sum --check --strict --quiet SHA256SUMS); then
    die "A file in the release does not match SHA256SUMS." \
      "The download or the copy is damaged, or a file was changed after the build." \
      "Check the tarball against its .sha256 file, unpack it again, and run its install.sh."
  fi
  listed="$(cut -c67- "$HERE/SHA256SUMS" | LC_ALL=C sort)"
  present="$(cd "$HERE" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort)"
  [ "$listed" = "$present" ] || die "The release holds files that SHA256SUMS does not list." \
    "Every file the installer copies must be a verified one." \
    "Unpack the release tarball into an empty folder and run its install.sh."
  for name in "${PROGRAMS[@]/#/bin/}" ui/index.html; do
    [ -f "$HERE/$name" ] || die "The release has no $name." \
      "The release is incomplete." \
      "Build it again with scripts/install/build-release.sh."
  done
  echo "ok: every file in the release matches SHA256SUMS"
}

# -------------------------------------------------------------------- tools

ensure_dir() { # ensure_dir OWNER GROUP MODE PATH
  local owner="$1" group="$2" mode="$3" path="$4"
  [ ! -L "$path" ] || die "$path is a symbolic link." \
    "The installer creates this folder itself and does not follow links." \
    "Remove the link, then run this again."
  if [ -d "$path" ] && [ "$(stat -c '%U:%G %a' "$path")" = "$owner:$group ${mode#0}" ]; then
    return 0
  fi
  install -d -o "$owner" -g "$group" -m "$mode" "$path"
  changed "folder $path set to $owner:$group $mode"
}

relabel() { # relabel PATH...: restore the default SELinux labels
  local out
  out="$(restorecon -v "$@" 2>&1)" || true
  if [ -n "$out" ]; then
    printf '%s\n' "$out"
    changed "SELinux labels restored on: $*"
  fi
}

# Copies PATH to PATH.bak-YYYYMMDD-HHMM and prints the backup's name. An
# earlier backup from the same minute is the older original, so it stays.
backup_file() {
  local backup="$1.bak-$STAMP"
  if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
    cp -a -- "$1" "$backup"
  fi
  printf '%s\n' "$backup"
}

latest_backup() { # the newest PATH.bak-* by name, or nothing
  local file last=""
  for file in "$1".bak-*; do
    if [ -e "$file" ] || [ -L "$file" ]; then
      last="$file"
    fi
  done
  printf '%s' "$last"
}

ols_user() {
  local user=""
  if [ -r "$OLS_CONF" ]; then
    user="$(awk '$1=="user"{print $2; exit}' "$OLS_CONF")"
  fi
  printf '%s' "${user:-nobody}"
}

# -------------------------------------------------------------------- steps

step_repositories() {
  if [ ! -f /etc/yum.repos.d/litespeed.repo ]; then
    # Same key and repositories LiteSpeed's own repo.litespeed.sh writes.
    curl -fsS -o /etc/pki/rpm-gpg/RPM-GPG-KEY-litespeed https://rpms.litespeedtech.com/centos/RPM-GPG-KEY-litespeed
    cat > /etc/yum.repos.d/litespeed.repo <<'REPO'
[litespeed]
name=LiteSpeed Tech Repository for CentOS 9 - x86_64
baseurl=http://rpms.litespeedtech.com/centos/9/x86_64/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-litespeed
[litespeed-update]
name=LiteSpeed Tech Update Repository for CentOS 9 - x86_64
baseurl=http://rpms.litespeedtech.com/centos/9/update/x86_64/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-litespeed
REPO
    changed "LiteSpeed repository added"
  fi
  if ! rpm -q epel-release >/dev/null 2>&1; then
    dnf -y -q install epel-release
    changed "EPEL repository added"
  fi
  if ! dnf -q repolist --enabled | awk '{print $1}' | grep -qx crb; then
    dnf config-manager --set-enabled crb
    changed "CRB repository enabled"
  fi
  # LiteSpeed's lsphp extension packages link against oniguruma, ICU and gd
  # builds that EL9 only gets from Remi. Without it the install fails with
  # "nothing provides libonig.so.105", so LiteSpeed's setup script adds it too.
  if ! rpm -q remi-release >/dev/null 2>&1; then
    dnf -y -q install https://rpms.remirepo.net/enterprise/remi-release-9.rpm
    changed "Remi repository added"
  fi
}

step_packages() {
  local package missing=()
  for package in "${PACKAGES[@]}"; do
    rpm -q "$package" >/dev/null 2>&1 || missing+=("$package")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    dnf -y -q module enable mariadb:10.11
    dnf -y -q install "${PACKAGES[@]}"
    changed "packages installed: ${missing[*]}"
  fi
  rpm -q openlitespeed lsphp83 mariadb-server podman httpd | sed 's/^/installed: /'
}

step_host_folders() {
  # A new XFS filesystem's top folder has no SELinux label of its own yet.
  relabel "$HOMES"
  # The controller is the unprivileged user the panel runs as. It is the
  # only peer the broker's socket admits. Its home stays root's, which
  # hostsetup requires of the folder above the panel's state: the panel
  # writes inside state/ only.
  if ! id "$PANEL_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$PANEL_HOME" --no-create-home --shell /usr/sbin/nologin "$PANEL_USER"
    changed "system user $PANEL_USER created"
  fi
  ensure_dir root root 0711 "$PANEL_HOME"
  ensure_dir root root 0755 /etc/sifruno
  ensure_dir root root 0755 /etc/sifruno/ssh
  # 0711: sshd, running as the account, can open its own key file by name
  # but cannot list the folder; the broker requires exactly this mode.
  ensure_dir root root 0711 /etc/sifruno/ssh/authorized_keys
  relabel "$PANEL_HOME" /etc/sifruno /etc/sifruno/ssh /etc/sifruno/ssh/authorized_keys
}

# The broker accepts local files as the only passwd, group and shadow
# authority: each of the three is named once and says exactly "files".
nss_files_only() {
  awk '
    { line = $0; sub(/#.*/, "", line) }
    line ~ /^[[:space:]]*(passwd|group|shadow)[[:space:]]*:/ {
      key = line; sub(/:.*/, "", key); gsub(/[[:space:]]/, "", key)
      value = substr(line, index(line, ":") + 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      seen[key]++
      if (value != "files") bad = 1
    }
    END { exit !(seen["passwd"] == 1 && seen["group"] == 1 && seen["shadow"] == 1 && !bad) }
  ' "$1"
}

nss_rewrite() {
  awk '
    /^[[:space:]]*(passwd|group|shadow)[[:space:]]*:/ {
      key = $0; sub(/:.*/, "", key); gsub(/[[:space:]]/, "", key)
      if (!(key in done)) { printf "%s:     files\n", key; done[key] = 1 }
      next
    }
    { print }
    END {
      n = split("passwd group shadow", want, " ")
      for (i = 1; i <= n; i++) if (!(want[i] in done)) printf "%s:     files\n", want[i]
    }
  ' "$1"
}

step_nsswitch() {
  local new
  # A stock AlmaLinux 9 lists sss and systemd too, which the broker refuses.
  # A link (authselect makes one) is replaced too: the broker reads a
  # regular file only.
  if [ ! -L "$NSSWITCH" ] && nss_files_only "$NSSWITCH"; then
    return 0
  fi
  # cp -a keeps a symbolic link a link, so the backup is what was there.
  NSS_BACKUP="$(backup_file "$NSSWITCH")"
  new="$(mktemp "$NSSWITCH.XXXXXX")"
  nss_rewrite "$NSSWITCH" > "$new"
  chown root:root "$new"
  chmod 0644 "$new"
  if ! nss_files_only "$new"; then
    rm -f -- "$new"
    die "$NSSWITCH could not be rewritten to name only files for passwd, group and shadow." \
      "Its layout is not one the installer knows. Nothing was changed; a copy is in $NSS_BACKUP." \
      "Edit the three lines by hand so each reads 'files', then run this again."
  fi
  # The label is set before the move and checked after it: under SELinux
  # enforcing, sshd and others confined cannot read a mislabelled file,
  # which the lookups below, run as unconfined root, would not notice.
  if ! restorecon "$new"; then
    rm -f -- "$new"
    die "The new $NSSWITCH could not be given its SELinux label." \
      "Confined services such as sshd could not read it. Nothing was changed." \
      "Run restorecon -v $NSSWITCH to see the error, fix it, then run this again."
  fi
  mv -f -- "$new" "$NSSWITCH"
  # SSH_ADMIN is the user preflight found able to sign in with a key; it was
  # looked up in the local files only, so it must resolve now too.
  if ! restorecon "$NSSWITCH" || ! getent passwd root >/dev/null || ! getent group root >/dev/null ||
    ! getent passwd "$PANEL_USER" >/dev/null || { [ -n "$SSH_ADMIN" ] && ! getent passwd "$SSH_ADMIN" >/dev/null; }; then
    # cp -a keeps the backup's own label, which was the original's.
    cp -a -- "$NSS_BACKUP" "$NSSWITCH"
    die "After the change to $NSSWITCH, its SELinux label could not be set or the system could not look up root, $PANEL_USER or ${SSH_ADMIN:-root} (who signs in over SSH)." \
      "The new file was rejected and the previous one was put back from $NSS_BACKUP." \
      "Check that root, $PANEL_USER and your SSH admin are in /etc/passwd and /etc/group, and that restorecon -v $NSSWITCH works, then run this again."
  fi
  changed "$NSSWITCH: passwd, group and shadow set to files (backup: $NSS_BACKUP)"
}

sshd_put_back() {
  if [ -n "$SSHD_BACKUP" ]; then
    cp -a -- "$SSHD_BACKUP" "$SSHD_DROPIN"
  else
    rm -f -- "$SSHD_DROPIN"
  fi
}

step_sshd() {
  local candidate admin
  if sshd_policy_current; then
    return 0
  fi
  sshd -t || die "sshd's configuration is already invalid, before any change by the installer." \
    "The installer checks its own change with sshd -t, which needs a valid starting point." \
    "Run sshd -t, fix what it reports, then run this again."
  # The whole configuration as it will be is checked on a copy first, so a
  # run cut short after the move below leaves only a policy sshd accepts and
  # an admin can sign in under.
  candidate="$(sshd_candidate)" || die "$SSHD_CONFIG does not have the line '$SSHD_INCLUDE'." \
    "The policy is a drop-in in that folder and is checked on a copy of the full configuration. Nothing was changed." \
    "Put that line back near the top of $SSHD_CONFIG, then run this again."
  if ! sshd -t -f "$candidate/sshd_config" || ! admin="$(ssh_admin "$candidate/sshd_config")"; then
    rm -rf -- "$candidate"
    die "With the new policy, sshd would reject its configuration or nobody could sign in with a key." \
      "The installer checked a copy of the configuration with $SSHD_DROPIN in place. Nothing was changed." \
      "Run this again to see the preflight's reason, or run sshd -T -C user=root,host=localhost,addr=127.0.0.1"
  fi
  install -o root -g root -m 0600 -- "$candidate/sshd_config.d/${SSHD_DROPIN##*/}" "$SSHD_DROPIN.new"
  rm -rf -- "$candidate"
  # Labelled before the move and checked after it, as for nsswitch.conf:
  # sshd cannot read a mislabelled drop-in under SELinux enforcing.
  if ! restorecon "$SSHD_DROPIN.new"; then
    rm -f -- "$SSHD_DROPIN.new"
    die "The new $SSHD_DROPIN could not be given its SELinux label." \
      "sshd could not read it. Nothing was changed." \
      "Run restorecon -v /etc/ssh/sshd_config.d to see the error, fix it, then run this again."
  fi
  if [ -e "$SSHD_DROPIN" ]; then
    SSHD_BACKUP="$(backup_file "$SSHD_DROPIN")"
    SSHD_CHANGE=replaced
  else
    SSHD_CHANGE=created
  fi
  mv -f -- "$SSHD_DROPIN.new" "$SSHD_DROPIN"
  # The live files again, before applying: they are what a reload loads.
  # Reload rather than restart, so the session running this script stays up.
  if ! restorecon "$SSHD_DROPIN" || ! sshd -t || ! ssh_admin_ok "$SSHD_CONFIG" "$admin"; then
    sshd_put_back
    die "The new policy in $SSHD_DROPIN could not be labelled for SELinux, sshd rejected it, or $admin could no longer sign in with a key under it." \
      "The change was undone and sshd was not reloaded, so sign-in works as before." \
      "Run sshd -t and sshd -T -C user=$admin,host=localhost,addr=127.0.0.1 to see what sshd applies, then run this again."
  fi
  echo "ok: $admin can sign in over SSH with a key under the new policy"
  if ! systemctl reload sshd; then
    sshd_put_back
    systemctl reload sshd || true
    die "sshd did not reload with the new policy in $SSHD_DROPIN." \
      "The change was undone and sshd was asked to reload once more with the earlier files." \
      "Check systemctl status sshd, and keep this session open until a second sign-in works."
  fi
  changed "sshd policy $SSHD_DROPIN $SSHD_CHANGE and sshd reloaded"
}

step_openlitespeed() {
  local include="include $LSWS/conf/sifruno.conf"
  # The broker writes conf/sifruno.conf and the vhosts but never edits the
  # server-wide file; the installer adds the include once. A vhost's
  # namespace setting applies only when the server-level one is not 0.
  if grep -qxF "$include" "$OLS_CONF"; then
    return 0
  fi
  OLS_BACKUP="$(backup_file "$OLS_CONF")"
  if grep -qE '^namespace[[:space:]]' "$OLS_CONF"; then
    sed -i -E 's/^namespace[[:space:]].*/namespace                 1/' "$OLS_CONF"
  else
    printf '%s\n' 'namespace                 1' >> "$OLS_CONF"
  fi
  touch "$LSWS/conf/sifruno.conf"
  chown --reference="$OLS_CONF" "$LSWS/conf/sifruno.conf"
  chmod 0600 "$LSWS/conf/sifruno.conf"
  printf '%s\n' "$include" >> "$OLS_CONF"
  changed "OpenLiteSpeed: Sifruno's include and namespace isolation added (backup: $OLS_BACKUP)"
}

step_wpcli() {
  local target="$PREFIX/wp-cli.phar" tmp
  ensure_dir root root 0755 "$PREFIX"
  if [ "$(sha512sum "$target" 2>/dev/null | cut -d' ' -f1)" = "$WPCLI_SHA512" ]; then
    return 0
  fi
  tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar"
  if [ "$(sha512sum "$tmp" | cut -d' ' -f1)" != "$WPCLI_SHA512" ]; then
    rm -f -- "$tmp"
    die "The WP-CLI ${WPCLI_VERSION} download does not match its pinned sha512." \
      "The broker runs only the exact WP-CLI file it was built for, so a different file is never installed." \
      "Check the server's connection to github.com and run this again."
  fi
  install -o root -g root -m 0644 "$tmp" "$target"
  rm -f -- "$tmp"
  changed "WP-CLI ${WPCLI_VERSION} installed at $target"
}

step_services() {
  local unit
  for unit in mariadb lsws; do
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null || ! systemctl is-active --quiet "$unit"; then
      systemctl enable --now "$unit"
      changed "$unit enabled and started"
    fi
  done
  systemctl is-active mariadb lsws | sed 's/^/service: /'
}

step_db_admin() {
  local dbadmin_password
  # The panel runs as sifpanel and creates site databases through dbhost
  # with this option file. The password is made here, goes to MariaDB on
  # stdin and into the 0600 file, and is never a command argument. Kept
  # once made.
  if [ ! -s "$DB_ADMIN_CNF" ]; then
    dbadmin_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
    mysql --protocol=socket -uroot <<SQL
CREATE USER IF NOT EXISTS 'sifpanel_dbadmin'@'localhost' IDENTIFIED BY '$dbadmin_password';
ALTER USER 'sifpanel_dbadmin'@'localhost' IDENTIFIED BY '$dbadmin_password';
GRANT ALL PRIVILEGES ON *.* TO 'sifpanel_dbadmin'@'localhost' WITH GRANT OPTION;
SQL
    install -o "$PANEL_USER" -g "$PANEL_USER" -m 0600 /dev/null "$DB_ADMIN_CNF"
    printf '[client]\nuser=sifpanel_dbadmin\npassword=%s\n' "$dbadmin_password" > "$DB_ADMIN_CNF"
    unset dbadmin_password
    changed "MariaDB admin user for the panel created, with its option file $DB_ADMIN_CNF"
  fi
  stat -c 'panel database option file: %U %a %n' "$DB_ADMIN_CNF"
}

step_acme() {
  # The panel (sifpanel) writes each challenge token here and every vhost
  # the broker renders serves /.well-known/acme-challenge/ from it. One
  # folder outside every home is safe to share: tokens are random. It keeps
  # /var/lib's SELinux label, which OpenLiteSpeed may read.
  ensure_dir "$PANEL_USER" "$PANEL_USER" 0755 "$ACME_DIR"
  relabel "$ACME_DIR"
  stat -c 'ACME challenge folder: %U %a %n' "$ACME_DIR"
}

step_programs() {
  local name
  ensure_dir root root 0755 "$PREFIX"
  ensure_dir root root 0755 "$BIN_DIR"
  for name in "${PROGRAMS[@]}"; do
    if cmp -s "$HERE/bin/$name" "$BIN_DIR/$name" && [ "$(stat -c '%U:%G %a' "$BIN_DIR/$name")" = "root:root 755" ]; then
      continue
    fi
    # install unlinks the old file first, so a running program keeps its
    # copy until the unit restarts.
    install -o root -g root -m 0755 "$HERE/bin/$name" "$BIN_DIR/$name"
    changed "program $BIN_DIR/$name installed"
    RESTART_NEEDED=yes
  done
  if [ ! -d "$UI_DIR" ] || ! diff -rq "$HERE/ui" "$UI_DIR" >/dev/null 2>&1; then
    # Built asset names change with every build, so the folder is swapped
    # whole instead of copied over.
    rm -rf -- "$UI_DIR.new" "$UI_DIR.old"
    cp -R -- "$HERE/ui" "$UI_DIR.new"
    chown -R root:root "$UI_DIR.new"
    chmod -R u=rwX,go=rX "$UI_DIR.new"
    if [ -e "$UI_DIR" ]; then
      mv -- "$UI_DIR" "$UI_DIR.old"
    fi
    mv -- "$UI_DIR.new" "$UI_DIR"
    rm -rf -- "$UI_DIR.old"
    changed "panel UI installed in $UI_DIR"
    RESTART_NEEDED=yes
  fi
  relabel -R "$PREFIX"
}

step_check_host() {
  local report
  if ! report="$("$BIN_DIR/hostbroker" --check-host)"; then
    die "The account broker does not accept this host's account policy." \
      "It needs its account tools, files-only nsswitch and the stock useradd defaults; one of them is not as it expects." \
      "Read the report below, put the refused item right, then run this again.
  Technical details: $report"
  fi
  echo "host policy: supported"
}

step_layout() {
  local uid report
  uid="$(id -u "$PANEL_USER")"
  # hostsetup admits a fresh layout only: every folder absent or empty. Once
  # the broker or the panel has run, the layout exists and is left alone;
  # the broker checks its own folders at every start.
  if broker_state_fresh && dir_fresh "$PANEL_STATE"; then
    if ! report="$("$BIN_DIR/hostsetup" --apply --state "$BROKER_STATE" --socket "$BROKER_SOCKET" \
      --homes "$HOMES" --controller-state "$PANEL_STATE" --controller-uid "$uid")"; then
      die "hostsetup refused to prepare the broker's and the panel's folders." \
        "It prepares only a fresh layout: $BROKER_STATE, $(dirname "$BROKER_SOCKET") and $PANEL_STATE absent or empty, and an empty root-owned $HOMES." \
        "Read the report below; the refused check or folder names what to put right. Then run this again.
  Technical details: $report"
    fi
    case "$report" in
      *'"action":"created"'*) changed "hostsetup created the broker's and the panel's folders" ;;
    esac
    echo "hostsetup: layout ready"
  else
    echo "The broker or the panel already has state; hostsetup prepares a fresh layout only, so the folders are left as they are."
  fi
  # The panel's unit needs its state folder whichever way the layout came
  # about. This is the owner and mode hostsetup gives it.
  if [ ! -d "$PANEL_STATE" ]; then
    install -d -o "$PANEL_USER" -g root -m 0700 "$PANEL_STATE"
    changed "folder $PANEL_STATE created"
  fi
}

broker_unit() { # broker_unit CONTROLLER_UID WEB_USER
  cat <<UNIT
# Written by the Sifruno installer (install.sh); a new run rewrites it.
[Unit]
Description=Sifruno account broker (root; the panel's only way to change the host)
After=local-fs.target
RequiresMountsFor=$HOMES $BROKER_STATE
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$BIN_DIR/hostbroker --state $BROKER_STATE --socket $BROKER_SOCKET --homes $HOMES --controller-uid $1 --web-user $2
# systemd makes /run/sifruno-broker (root, 0755) at start and removes it at
# stop, so a socket left by a crash never blocks the next start.
RuntimeDirectory=sifruno-broker
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=5
# The broker runs useradd, xfs_quota, OpenLiteSpeed's config test and WP-CLI,
# and writes /etc, $HOMES and OpenLiteSpeed's config, so its file system
# view, capabilities and SELinux transitions stay as they are. These options
# only close kernel interfaces it never uses.
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
}

panel_unit() {
  local remote=""
  if [ -n "$PANEL_HOST" ]; then
    remote="$remote --https-listen $PANEL_HTTPS_LISTEN --panel-host $PANEL_HOST"
  fi
  if [ -n "$ACME_EMAIL" ]; then
    remote="$remote --acme-email $ACME_EMAIL"
  fi
  cat <<UNIT
# Written by the Sifruno installer (install.sh); a new run rewrites it.
[Unit]
Description=Sifruno panel
After=network.target mariadb.service $BROKER_UNIT
Wants=$BROKER_UNIT
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=$PANEL_USER
Group=$PANEL_USER
WorkingDirectory=$PANEL_STATE
ExecStart=$BIN_DIR/sifruno --listen $PANEL_LISTEN --sites-listen= --state $PANEL_STATE --ui $UI_DIR --accounts-socket $BROKER_SOCKET --db-defaults-file $DB_ADMIN_CNF$remote
Restart=on-failure
RestartSec=5
# The panel reaches the host only through the broker's socket. It writes its
# own state and the ACME challenge folder and nothing else.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$PANEL_STATE $ACME_DIR
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
}

write_unit() { # write_unit NAME CONTENT
  local path="$UNIT_DIR/$1"
  printf '%s\n' "$2" > "$path.new"
  chmod 0644 "$path.new"
  if cmp -s "$path.new" "$path"; then
    rm -f -- "$path.new"
    return 0
  fi
  mv -f -- "$path.new" "$path"
  restorecon "$path"
  changed "$path written"
  UNITS_WRITTEN=yes
}

step_units() {
  local uid web_user
  uid="$(id -u "$PANEL_USER")"
  web_user="$(ols_user)"
  id "$web_user" >/dev/null 2>&1 || die "OpenLiteSpeed's user '$web_user' (from $OLS_CONF) is not a user on this server." \
    "The broker gives exactly that user read access to each website's files." \
    "Check the 'user' line in $OLS_CONF, then run this again."
  write_unit "$BROKER_UNIT" "$(broker_unit "$uid" "$web_user")"
  write_unit "$PANEL_UNIT" "$(panel_unit)"
  if [ "$UNITS_WRITTEN" = yes ]; then
    systemctl daemon-reload
    RESTART_NEEDED=yes
  fi
}

unit_failed() { # unit_failed UNIT WHAT
  die "$2" \
    "The unit did not come up in time. Its last log lines are below." \
    "Read them (journalctl -u $1), put the cause right, then run this again.
  Technical details:
$(journalctl -u "$1" -n 20 --no-pager 2>&1 | sed 's/^/    /')"
}

start_unit() { # start_unit UNIT
  if ! systemctl is-enabled --quiet "$1" 2>/dev/null; then
    systemctl enable "$1"
    changed "$1 enabled"
  fi
  if ! systemctl is-active --quiet "$1"; then
    systemctl start "$1" || unit_failed "$1" "$1 did not start."
    changed "$1 started"
  elif [ "$RESTART_NEEDED" = yes ]; then
    systemctl restart "$1" || unit_failed "$1" "$1 did not restart."
    changed "$1 restarted with the new files"
  fi
}

step_start() {
  local uid report
  uid="$(id -u "$PANEL_USER")"
  # The startup check admits a fresh setup only, and reads the same paths
  # the broker is about to take. A broker that has run keeps state, and
  # then its own start is the check.
  if ! systemctl is-active --quiet "$BROKER_UNIT" && broker_state_fresh && [ ! -e "$BROKER_SOCKET" ]; then
    if ! report="$("$BIN_DIR/hostbroker" --check-startup --state "$BROKER_STATE" --socket "$BROKER_SOCKET" \
      --homes "$HOMES" --controller-uid "$uid")"; then
      die "The account broker's startup check refused this server." \
        "The broker starts only when its user, tools, policy files and folders are exactly as it expects." \
        "Read the report below; the refused check names what to put right. Then run this again.
  Technical details: $report"
    fi
    echo "broker startup check: supported"
  else
    echo "broker startup check: not run (it admits a fresh setup only; this broker is running or has state)"
  fi

  # A unit that gave up (five failed starts) ends the wait early.
  start_unit "$BROKER_UNIT"
  for _ in $(seq 1 120); do
    [ -S "$BROKER_SOCKET" ] && break
    systemctl is-failed --quiet "$BROKER_UNIT" && break
    sleep 1
  done
  [ -S "$BROKER_SOCKET" ] || unit_failed "$BROKER_UNIT" "The account broker's socket $BROKER_SOCKET did not appear."

  start_unit "$PANEL_UNIT"
  for _ in $(seq 1 90); do
    curl -fsS -o /dev/null "http://$PANEL_LISTEN/" 2>/dev/null && break
    systemctl is-failed --quiet "$PANEL_UNIT" && break
    sleep 2
  done
  curl -fsS -o /dev/null "http://$PANEL_LISTEN/" || unit_failed "$PANEL_UNIT" "The panel did not answer on http://$PANEL_LISTEN/."
  echo "the panel answers on http://$PANEL_LISTEN/"
}

# ------------------------------------------------------------------ summary

print_units() {
  local uid web_user
  uid="$(id -u "$PANEL_USER" 2>/dev/null || true)"
  web_user="$(ols_user)"
  [ -r "$OLS_CONF" ] || web_user="<OpenLiteSpeed's user>"
  printf '\n%s\n' "--- $UNIT_DIR/$BROKER_UNIT"
  broker_unit "${uid:-<user ID of $PANEL_USER>}" "$web_user"
  printf '\n%s\n' "--- $UNIT_DIR/$PANEL_UNIT"
  panel_unit
}

print_first_run() {
  cat <<TEXT

First run
  1. The panel answers on this server only, at http://$PANEL_LISTEN/
     To reach it from your own computer, forward the port over SSH and open
     that same address there:
       ssh -L 8080:$PANEL_LISTEN root@THIS_SERVER
  2. Open Websites. The panel asks for the operator access key, then for a
     username, a password and an authenticator app. The key is in this file,
     which only root and $PANEL_USER can read. Open it on the server; do not
     paste it into chat, tickets or screenshots:
       $PANEL_STATE/operator/access.key
TEXT
  if [ -n "$PANEL_HOST" ]; then
    cat <<TEXT
  3. After that, sign in from anywhere at https://${PANEL_HOST%%,*}:${PANEL_HTTPS_LISTEN##*:}/
     The certificate is self-signed. Compare the fingerprint your browser
     shows with the one the panel logged:
       journalctl -u $PANEL_UNIT | grep SHA-256
     Open TCP ${PANEL_HTTPS_LISTEN##*:} for the panel and 80 and 443 for websites in your
     firewall. The installer does not change firewall rules.
TEXT
  else
    cat <<TEXT
  3. Websites need TCP 80 and 443 open in your firewall. The installer does
     not change firewall rules. To sign in to the panel from other machines
     without an SSH forward, run this again with --panel-host NAME.
TEXT
  fi
  if [ "$START" = no ]; then
    cat <<TEXT

The two units are installed but not enabled or started (--no-start). Start
them with:
  systemctl enable --now $BROKER_UNIT $PANEL_UNIT
TEXT
  fi
}

print_rollback() {
  local nss_backup="$NSS_BACKUP" ols_backup="$OLS_BACKUP" sshd_backup="$SSHD_BACKUP"
  [ -n "$nss_backup" ] || nss_backup="$(latest_backup "$NSSWITCH")"
  [ -n "$ols_backup" ] || ols_backup="$(latest_backup "$OLS_CONF")"
  [ -n "$sshd_backup" ] || sshd_backup="$(latest_backup "$SSHD_DROPIN")"
  cat <<TEXT

Rollback
  Before you close this SSH session, open a second one and check that you
  can still sign in.
  1. Sifruno's units, first: the broker does not run without the nsswitch
     change.
       systemctl disable --now $PANEL_UNIT $BROKER_UNIT
       rm $UNIT_DIR/$PANEL_UNIT $UNIT_DIR/$BROKER_UNIT
       systemctl daemon-reload
  2. sshd policy: $SSHD_DROPIN ($SSHD_CHANGE in this run)
       rm $SSHD_DROPIN
TEXT
  if [ -n "$sshd_backup" ]; then
    echo "       (or put the earlier copy back: cp -a $sshd_backup $SSHD_DROPIN)"
  fi
  echo "       sshd -t && systemctl reload sshd"
  echo "  3. nsswitch: $NSSWITCH"
  if [ -n "$nss_backup" ]; then
    echo "       cp -a $nss_backup $NSSWITCH"
  else
    echo "       No backup found: the installer has not changed this file."
  fi
  echo "  4. OpenLiteSpeed: $OLS_CONF"
  if [ -n "$ols_backup" ]; then
    echo "       cp -a $ols_backup $OLS_CONF && systemctl restart lsws"
  else
    echo "       No backup found: the installer has not changed this file."
  fi
  cat <<TEXT
  Packages, the $PANEL_USER user, websites and databases stay. Remove them by
  hand if you want them gone.
TEXT
}

main() {
  parse_args "$@"
  preflight
  if [ "$REFUSALS" -gt 0 ] && [ "$DRY_RUN" = no ]; then
    printf '\ninstall.sh: %d check(s) refused this server. Nothing was changed.\n' "$REFUSALS" >&2
    exit 1
  fi
  verify_release

  if [ "$DRY_RUN" = yes ]; then
    printf '\nPlan (dry run: none of this is done now)\n'
  fi
  step "Add the LiteSpeed, EPEL, CRB and Remi repositories" step_repositories
  step "Install OpenLiteSpeed, LSPHP 8.3, MariaDB 10.11, Podman and Apache (for the Compat tier; left off)" step_packages
  step "Label $HOMES, create the system user $PANEL_USER and Sifruno's folders in /etc and /var/lib" step_host_folders
  step "Set passwd, group and shadow in $NSSWITCH to files (backup, check, automatic rollback)" step_nsswitch
  step "Write the sshd policy $SSHD_DROPIN (backup, sshd -t, automatic rollback, reload)" step_sshd
  step "Add Sifruno's include and namespace isolation to OpenLiteSpeed's config (backup)" step_openlitespeed
  step "Install WP-CLI $WPCLI_VERSION in $PREFIX, checked against its pinned sha512" step_wpcli
  step "Enable and start MariaDB and OpenLiteSpeed" step_services
  step "Create the panel's MariaDB admin user and its 0600 option file $DB_ADMIN_CNF" step_db_admin
  step "Create the ACME challenge folder $ACME_DIR" step_acme
  step "Install the programs in $BIN_DIR and the panel UI in $UI_DIR" step_programs
  step "Check the host policy with hostbroker --check-host" step_check_host
  step "Prepare the broker's and the panel's folders with hostsetup --apply" step_layout
  step "Write $BROKER_UNIT and $PANEL_UNIT in $UNIT_DIR" step_units
  if [ "$START" = yes ]; then
    step "Run the broker's startup check, enable and start both units, wait for the panel to answer" step_start
  elif [ "$DRY_RUN" = yes ]; then
    echo "   -- --no-start: the two units are not enabled or started"
  fi

  if [ "$DRY_RUN" = yes ]; then
    print_units
    print_first_run
    print_rollback
    if [ "$REFUSALS" -gt 0 ]; then
      printf '\nDry run: nothing was changed. A real run stops at the %d refused check(s) above.\n' "$REFUSALS"
      exit 1
    fi
    printf '\nDry run: nothing was changed. The checks pass, so a real run would go ahead.\n'
    exit 0
  fi

  log "Sifruno is installed"
  if [ "${#CHANGES[@]}" -eq 0 ]; then
    echo "Changed in this run: nothing"
  else
    echo "Changed in this run:"
    printf '  - %s\n' "${CHANGES[@]}"
  fi
  print_first_run
  print_rollback
}

# The dev VM's installer-sshd proof loads the functions alone, to check the
# sshd pre-checks without installing anything.
[ "${SIFRUNO_INSTALL_FUNCTIONS_ONLY:-}" = 1 ] || main "$@"
