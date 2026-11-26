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
# sifruno-files is the file manager's helper: the broker runs it as a site's
# own user and checks it before each run (root's, 0755, one link, in these
# root-owned folders).
readonly PROGRAMS=(sifruno hostbroker hostsetup panelctl sifruno-files)
readonly BROKER_STATE=/var/lib/sifruno-broker
readonly BROKER_SOCKET=/run/sifruno-broker/control.sock
readonly HOMES=/home
readonly PANEL_USER=sifpanel
readonly PANEL_HOME=/var/lib/sifpanel
readonly PANEL_STATE="$PANEL_HOME/state"
readonly DB_ADMIN_CNF="$PANEL_HOME/db-admin.cnf"
readonly ACME_DIR=/var/lib/sifruno-acme
# Each live site's LSCache store, CACHE_DIR/sifruno-u<id> (olsweb.CacheRoot).
readonly CACHE_DIR=/var/lib/sifruno-lscache
readonly PANEL_LISTEN=127.0.0.1:8080
readonly PANEL_HTTPS_LISTEN=0.0.0.0:8443
# phpMyAdmin's own origin: the panel's host names and certificate on the
# next port, so a phpMyAdmin page can never act on the panel's API.
readonly PMA_HTTPS_LISTEN=0.0.0.0:8444
readonly LSWS=/usr/local/lsws
readonly OLS_CONF="$LSWS/conf/httpd_config.conf"
# OpenLiteSpeed's WebAdmin console. Sifruno writes OpenLiteSpeed's config
# itself, so the console listens on loopback only.
readonly OLS_ADMIN_CONF="$LSWS/admin/conf/admin_config.conf"
# MariaDB listens on loopback only. The installer owns this drop-in; its
# name sorts after the package's mariadb-server.cnf, so it is read later.
readonly MARIADB_DROPIN=/etc/my.cnf.d/sifruno.cnf
readonly NSSWITCH=/etc/nsswitch.conf
readonly SSHD_CONFIG=/etc/ssh/sshd_config
readonly SSHD_INCLUDE='Include /etc/ssh/sshd_config.d/*.conf'
readonly SSHD_DROPIN=/etc/ssh/sshd_config.d/40-sifruno.conf
readonly BROKER_UNIT=sifruno-broker.service
readonly PANEL_UNIT=sifruno.service
readonly UNIT_DIR=/etc/systemd/system
readonly LIMITS_FILE=/etc/security/limits.d/90-sifruno-accounts.conf
readonly PACKAGES=(openlitespeed
  lsphp83 lsphp83-common lsphp83-mysqlnd lsphp83-gd lsphp83-mbstring lsphp83-xml
  lsphp83-opcache lsphp83-intl lsphp83-zip lsphp83-process lsphp83-bcmath lsphp83-pdo
  mariadb-server podman openssh-clients rsync tar unzip bzip2 policycoreutils-python-utils xfsprogs quota
  cronie httpd httpd-tools)
# The broker runs this file only while its bytes match the sha512 pinned in
# internal/hostaccounts/wordpress_linux.go (WP-CLI 2.12.0's published one).
readonly WPCLI_VERSION=2.12.0
# restic for website backups. The download is checked against the sha256 in
# the release's SHA256SUMS; the decompressed binary against the one pinned in
# internal/hostaccounts/backup.go, which the broker checks before every run.
readonly RESTIC_VERSION=0.20.0
readonly RESTIC_BZ2_SHA256=0ccd9fa7885074a24603b051e01bf9bd8b5e45d6a1791e9d9887e9e9372107f7
readonly RESTIC_SHA256=c109579d3a1a4d26094bef5400ac5645fceb1043414c05f51b8fb48272001c72
readonly WPCLI_SHA512=be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832
# phpMyAdmin for the panel's one-click sign-in. 5.2.3 is the release of
# 2025-10-08 and fixes every advisory up to PMASA-2025-3. The pins below are
# the trust root, as for restic and WP-CLI: the installer checks the
# download against PMA_TARBALL_SHA256 and the unpacked tree, without setup/
# and examples/, against PMA_TREE_SHA256 (pma_tree_sha256). It runs no gpg.
#
# The pins were made on 2026-11-24 from a tarball whose OpenPGP signature
# was verified then. The signer is Isaac Bennetch, phpMyAdmin's release
# manager, primary key fingerprint 3D06A59ECE730EB71B511C17CE752F178259BD92.
# To check the pins again, in an empty folder:
#   base=https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-english.tar.gz
#   curl -fsSLO "$base" && curl -fsSLO "$base.asc" && curl -fsSLO "$base.sha256"
#   curl -fsSL -o phpmyadmin.keyring https://files.phpmyadmin.net/phpmyadmin.keyring
#   gpg --import phpmyadmin.keyring
#   gpg --verify phpMyAdmin-5.2.3-english.tar.gz.asc phpMyAdmin-5.2.3-english.tar.gz
#     (expect "Good signature from Isaac Bennetch" and the fingerprint above)
#   sha256sum phpMyAdmin-5.2.3-english.tar.gz; cat phpMyAdmin-5.2.3-english.tar.gz.sha256
#     (both must equal PMA_TARBALL_SHA256)
#   mkdir tree && tar -xzf phpMyAdmin-5.2.3-english.tar.gz -C tree --strip-components=1 --no-same-owner --no-same-permissions
#   rm -rf tree/setup tree/examples
#   (cd tree && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
#     (must equal PMA_TREE_SHA256)
readonly PMA_VERSION=5.2.3
readonly PMA_TARBALL_SHA256=03de2640bb25c9a6f96bc94eae316080b5fd5bd58d769e1318ba9dd94c83364c
readonly PMA_TREE_SHA256=dd0f2c288f080c4bdd1468e178f6f5f49ee8227187bd017d7a4f2459444fcdb8
readonly PMA_DIR="$PREFIX/phpmyadmin"
readonly PMA_USER=sifpma
readonly PMA_STATE=/var/lib/sifruno-phpmyadmin
readonly PMA_ETC=/etc/sifruno/phpmyadmin
readonly PMA_LISTEN=127.0.0.1:8090
readonly PMA_VHOST=sifruno_phpmyadmin
readonly PMA_OLS_CONF="$LSWS/conf/sifruno-phpmyadmin.conf"
readonly PMA_VHCONF_DIR="$LSWS/conf/vhosts/$PMA_VHOST"
readonly PMA_LOG_DIR="$LSWS/logs/$PMA_VHOST"
# systemd makes it for the panel (RuntimeDirectory); phpMyAdmin's sign-in
# script redeems its codes on the socket inside.
readonly PANEL_RUN=/run/sifruno-panel
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
OLS_ADMIN_BACKUP=""
MARIADB_BACKUP=""
MARIADB_CHANGE=unchanged

usage() {
  cat <<'USAGE'
usage: install.sh [--panel-host NAME] [--acme-email ADDR] [--no-start] [--dry-run]
  --panel-host NAME   also serve the panel over HTTPS on 0.0.0.0:8443 for this
                      host name or IP (several: comma-separated), and
                      phpMyAdmin on 0.0.0.0:8444. Without it the panel
                      answers on 127.0.0.1:8080 only, without phpMyAdmin.
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

warn() { # warn WHAT WHY TODO: something to know; the install goes on
  printf 'WARNING: %s\n  Why: %s\n  What to do: %s\n' "$1" "$2" "$3" >&2
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

# The --panel-host names the panel asks Let's Encrypt for, comma-separated:
# with --acme-email, the DNS names (lower case, two labels or more, each a
# plain label) outside the names kept for tests, examples and local
# networks, once each, as panelcert.PublicNames picks them. The broker
# serves them on port 80 for the panel's certificate challenge only. An IP
# address is left out: it keeps the self-signed certificate, and no vhost
# maps it.
panel_cert_names() {
  local h out="" label ok
  local -a hosts labels
  [ -n "$ACME_EMAIL" ] || return 0
  IFS=, read -r -a hosts <<<"$PANEL_HOST"
  for h in "${hosts[@]}"; do
    h="${h,,}"
    [[ "$h" == *.* && ! "$h" =~ ^[0-9.]+$ && "$h" != *:* ]] || continue
    case "$h" in
      *.test | *.example | *.invalid | *.localhost | *.local | *.onion | *.arpa | *.internal) continue ;;
      example.com | *.example.com | example.net | *.example.net | example.org | *.example.org) continue ;;
    esac
    ok=yes
    IFS=. read -r -a labels <<<"$h"
    for label in "${labels[@]}"; do
      [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || ok=no
    done
    [[ "$ok" = yes && ",$out," != *",$h,"* ]] && out="${out:+$out,}$h"
  done
  printf '%s' "$out"
}

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
  preflight_panel_host
}

# preflight_panel_host warns when a --panel-host name is already a
# website's domain (or its www. form), as the web server's Sifruno config
# maps it. The panel refuses new websites and domains with its own name,
# but one made before stays the website's.
preflight_panel_host() {
  local conf="$LSWS/conf/sifruno.conf" h vhost domain
  local -a hosts
  [ -n "$PANEL_HOST" ] && [ -r "$conf" ] || return 0
  IFS=, read -r -a hosts <<<"${PANEL_HOST,,}"
  # Each map line is "map VHOST d1, d2, ..."; sifruno-panel is the panel's
  # own challenge vhost. A name and its www. form are one to the web server.
  while read -r vhost domain; do
    for h in "${hosts[@]}"; do
      [ "${h#www.}" = "$domain" ] || continue
      warn "--panel-host $h is also the domain of a website on this server (OpenLiteSpeed vhost $vhost)." \
        "The website keeps that name on ports 80 and 443, so the name opens the website there and the panel only on port ${PANEL_HTTPS_LISTEN##*:}. The panel refuses new websites with its own name for this reason." \
        "Give the panel a name of its own, such as panel.${h#www.}, and run this again with it; or move the website to another domain. The install goes on."
    done
  done < <(awk '$1 == "map" && $2 != "sifruno-panel" { for (i = 3; i <= NF; i++) { d = $i; sub(/,$/, "", d); sub(/^www\./, "", d); print $2, d } }' "$conf" | LC_ALL=C sort -u)
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
  for name in "${PROGRAMS[@]/#/bin/}" ui/index.html phpmyadmin/config.inc.php phpmyadmin/sifruno-signon.php; do
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

# The server-level cache module block exactly as the openlitespeed 1.9.4
# package's httpd_config.conf ships it: the module on, nothing cached by
# default. Each Sifruno vhost has its own block over it (its own store, or
# the module off while suspended); the WordPress plugin asks for each page.
ols_cache_module() {
  cat <<'BLOCK'

module cache {
    ls_enabled          1

    checkPrivateCache   1
    checkPublicCache    1
    maxCacheObjSize     10000000
    maxStaleAge         200
    qsCache             1
    reqCookieCache      1
    respCookieCache     1
    ignoreReqCacheCtrl  1
    ignoreRespCacheCtrl 0

    enableCache         0
    expireInSeconds     3600
    enablePrivateCache  0
    privateExpireInSeconds 3600

}
BLOCK
}

step_openlitespeed() {
  local include="include $LSWS/conf/sifruno.conf" has_include=no has_cache=no
  # The broker writes conf/sifruno.conf and the vhosts but never edits the
  # server-wide file; the installer adds the include once, and the cache
  # module block when the file has none. A vhost's namespace setting
  # applies only when the server-level one is not 0.
  if grep -qxF "$include" "$OLS_CONF"; then
    has_include=yes
  fi
  if grep -qE '^[[:space:]]*module[[:space:]]+cache[[:space:]]*\{[[:space:]]*$' "$OLS_CONF"; then
    has_cache=yes
  fi
  if [ "$has_include" = yes ] && [ "$has_cache" = yes ]; then
    return 0
  fi
  OLS_BACKUP="$(backup_file "$OLS_CONF")"
  if [ "$has_cache" = no ]; then
    ols_cache_module >> "$OLS_CONF"
    changed "OpenLiteSpeed: the stock cache module block added for LSCache (backup: $OLS_BACKUP)"
  fi
  if [ "$has_include" = yes ]; then
    return 0
  fi
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

# Prints OpenLiteSpeed's config (file $1) with "cgroups 1" in its CGIRLimit
# block: a "cgroups 0" line (OpenLiteSpeed's default, disallowed) replaced
# where it is, a line added before the block's closing brace (indented or
# not) when there is none, or a block appended when there is no block. Any
# other value an administrator set stays as it is. Read from the OpenLiteSpeed
# 1.9.4 source, not yet run: the server value is 0 disallowed, 1 allowed and
# off unless a vhost turns it on, 2 allowed and on (serverprocessconfig.h:48-50,
# cgidworker.cpp:409-416); a vhost's 2 turns it on when the server's is not 0
# (httpvhost.cpp:3401-3405), as the broker's vhosts do. lscgid then puts the
# site's PHP in its account's user-<uid>.slice (lscgid.cpp:471-529), under
# the limits the broker writes there.
ols_with_cgroups() {
  awk '
    /^[[:space:]]*CGIRLimit[[:space:]]*\{/ { inblock = 1; seen = 1; print; next }
    inblock && /^[[:space:]]*cgroups[[:space:]]/ {
      if (!done && $2 == "0") { print "  cgroups                 1"; done = 1; next }
      done = 1; print; next
    }
    inblock && /^[[:space:]]*\}/ { if (!done) print "  cgroups                 1"; done = 1; inblock = 0; print; next }
    { print }
    END { if (!seen) { print ""; print "CGIRLimit  {"; print "  cgroups                 1"; print "}" } }
  ' "$1"
}

# The cgroups value in the CGIRLimit block of the config on stdin.
ols_cgroups_value() {
  awk '
    /^[[:space:]]*CGIRLimit[[:space:]]*\{/ { inblock = 1; next }
    inblock && /^[[:space:]]*\}/ { inblock = 0 }
    inblock && $1 == "cgroups" { print $2; exit }
  '
}

# The [ERROR] lines of `openlitespeed -t`, without their time and process
# ID, sorted, so two runs compare. -t exits 1 after a warning and 2 after an
# error, which is not a failure here.
ols_test_errors() {
  local out
  out="$("$LSWS/bin/openlitespeed" -t 2>&1)" || true
  printf '%s\n' "$out" | awk '{ for (i = 1; i <= NF; i++) if ($i == "[ERROR]") { line = ""; for (j = i + 2; j <= NF; j++) line = line " " $j; print line; break } }' | sort -u
}

step_ols_cgroups() {
  local next value before after added
  next="$(ols_with_cgroups "$OLS_CONF")"
  value="$(printf '%s\n' "$next" | ols_cgroups_value)"
  if [ "$value" != 1 ] && [ "$value" != 2 ]; then
    log "Note: OpenLiteSpeed's CGIRLimit has cgroups $value, which the installer leaves as it is; with it, each site's PHP runs outside its account's user slice. Set it to 1 to put it there, then run this again."
  fi
  if [ "$next" = "$(cat "$OLS_CONF")" ]; then
    return 0
  fi
  [ -n "$OLS_BACKUP" ] || OLS_BACKUP="$(backup_file "$OLS_CONF")"
  # `openlitespeed -t` reads only the server root's conf/httpd_config.conf
  # (it takes no file argument), so the new file goes in place and is tested
  # before OpenLiteSpeed is reloaded; a new [ERROR] puts the old one back.
  before="$(ols_test_errors)"
  cp -a -- "$OLS_CONF" "$OLS_CONF.old"
  printf '%s\n' "$next" > "$OLS_CONF.new"
  chown --reference="$OLS_CONF" "$OLS_CONF.new"
  chmod --reference="$OLS_CONF" "$OLS_CONF.new"
  mv -f -- "$OLS_CONF.new" "$OLS_CONF"
  relabel "$OLS_CONF"
  after="$(ols_test_errors)"
  added="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
  if [ -n "$added" ]; then
    mv -f -- "$OLS_CONF.old" "$OLS_CONF"
    relabel "$OLS_CONF"
    printf '%s\n' "$added" | sed 's/^/  openlitespeed -t:/' >&2
    die "OpenLiteSpeed's config test reports a new error with cgroups 1 in CGIRLimit, so the installer put the old $OLS_CONF back." \
      "The installer changes the server-wide file only when OpenLiteSpeed accepts the result; the errors are above." \
      "Fix what they name in $OLS_CONF, check it with $LSWS/bin/openlitespeed -t, then run this again."
  fi
  rm -f -- "$OLS_CONF.old"
  # A running OpenLiteSpeed reads it at its graceful restart.
  if systemctl is-active --quiet lsws; then
    systemctl reload lsws
  fi
  changed "OpenLiteSpeed: cgroups 1 in CGIRLimit, so each site's PHP runs in its account's user slice (backup: $OLS_BACKUP)"
}

# Prints the WebAdmin console's config (file $1) with every listener's
# address on 127.0.0.1, at the same port. The package's listener is
# "adminListener{" on *:7080. Every other line stays as it is.
ols_admin_loopback() {
  awk '
    tolower($1) == "listener" { inblock = 1; print; next }
    inblock && /^[[:space:]]*\}/ { inblock = 0 }
    inblock && tolower($1) == "address" && NF == 2 {
      port = $2
      sub(/^.*:/, "", port)
      if (port ~ /^[0-9]+$/ && $2 != "127.0.0.1:" port) {
        sub(/[^[:space:]]+[[:space:]]*$/, "127.0.0.1:" port)
      }
    }
    { print }
  ' "$1"
}

# Prints OpenLiteSpeed's config (file $1) without the package's sample site:
# the "virtualHost Example" block, the "listener Default" block that serves
# it on *:8088, and the "listeners Default" line of each vhTemplate block.
# Without that last part OpenLiteSpeed logs "Listener [Default] does not
# exist" as an [ERROR] for each of the two stock templates at every start,
# which openlitespeed -t does not show. Everything else stays as it is.
ols_without_example() {
  awk '
    function depth(s,   open) { open = gsub(/\{/, "", s); return open - gsub(/\}/, "", s) }
    skip { level += depth($0); if (level <= 0) skip = 0; next }
    {
      key = tolower($1)
      name = $2
      sub(/\{$/, "", name)
    }
    (key == "listener" && name == "Default") || (key == "virtualhost" && name == "Example") {
      level = depth($0)
      skip = level > 0
      next
    }
    key == "vhtemplate" { template = 1 }
    template && /^[[:space:]]*\}/ { template = 0 }
    template && key == "listeners" && NF == 2 && $2 == "Default" { next }
    { print }
  ' "$1"
}

# What a running OpenLiteSpeed still serves from before the change below:
# its TCP listeners, not on 127.0.0.1, on a WebAdmin console port or on
# 8088, the sample site's port.
ols_old_listeners() {
  local ports
  ports="$(awk 'tolower($1) == "address" { p = $2; sub(/^.*:/, "", p); if (p ~ /^[0-9]+$/) print p }' "$OLS_ADMIN_CONF" | paste -sd '|')"
  ss -Hltnp | awk -v want="^(${ports:+$ports|}8088)\$" '
    /"litespeed"/ { port = $4; sub(/^.*:/, "", port); if (port ~ want && $4 !~ /^127\.0\.0\.1:/) print $4 }
  ' | sort -u
}

# A listener that moves or goes needs OpenLiteSpeed stopped and started
# again. Its graceful restart (systemctl reload lsws; also systemctl
# restart lsws, as the package's unit stops it gracefully with
# KillMode=none and its start then finds the old server still running)
# starts the new server while the old one still holds the old address; the
# new one exits with "Address already in use" and the old one keeps serving
# the old listeners, even though systemctl answers success. Seen with
# openlitespeed 1.9.4 on AlmaLinux 9. The websites are down for the few
# seconds it takes.
ols_stop_start() {
  local waited=0
  systemctl stop lsws
  # The old processes end once their requests are done.
  while pgrep -x litespeed >/dev/null && [ "$waited" -lt 60 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if pgrep -x litespeed >/dev/null; then
    # As lswsctrl's own restart does when the server does not come back.
    log "OpenLiteSpeed's processes did not end within 60 s of the stop; ending them"
    pkill -TERM -x litespeed || true
    sleep 5
    pkill -KILL -x litespeed || true
    sleep 1
  fi
  if ! systemctl start lsws; then
    unit_failed lshttpd "OpenLiteSpeed did not start again after the installer stopped it to put the WebAdmin console on 127.0.0.1 and remove the sample site on 8088; the websites are down."
  fi
  # The unit says started before the server has read its listeners; one
  # that cannot listen exits a moment later.
  sleep 3
  waited=0
  while ! systemctl is-active --quiet lsws && [ "$waited" -lt 30 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  systemctl is-active --quiet lsws || unit_failed lshttpd "OpenLiteSpeed did not stay up after its start with the listeners on loopback; the websites are down."
}

# Puts CONTENT in place of the OpenLiteSpeed config FILE, with its owner and
# mode, and keeps the old one as FILE.old.
ols_replace() { # ols_replace FILE CONTENT
  cp -a -- "$1" "$1.old"
  printf '%s\n' "$2" > "$1.new"
  chown --reference="$1" "$1.new"
  chmod --reference="$1" "$1.new"
  mv -f -- "$1.new" "$1"
  relabel "$1"
}

step_ols_listeners() {
  local conf_next admin_next before after added name old wrote=no
  local replaced=()
  conf_next="$(ols_without_example "$OLS_CONF")"
  admin_next="$(ols_admin_loopback "$OLS_ADMIN_CONF")"
  if [ "$conf_next" != "$(cat "$OLS_CONF")" ] || [ "$admin_next" != "$(cat "$OLS_ADMIN_CONF")" ]; then
    before="$(ols_test_errors)"
    # The new files go in place before the test, which reads the server
    # root's own files only; a new [ERROR] puts the old ones back.
    if [ "$conf_next" != "$(cat "$OLS_CONF")" ]; then
      [ -n "$OLS_BACKUP" ] || OLS_BACKUP="$(backup_file "$OLS_CONF")"
      ols_replace "$OLS_CONF" "$conf_next"
      replaced+=("$OLS_CONF")
    fi
    if [ "$admin_next" != "$(cat "$OLS_ADMIN_CONF")" ]; then
      OLS_ADMIN_BACKUP="$(backup_file "$OLS_ADMIN_CONF")"
      ols_replace "$OLS_ADMIN_CONF" "$admin_next"
      replaced+=("$OLS_ADMIN_CONF")
    fi
    after="$(ols_test_errors)"
    added="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
    if [ -n "$added" ]; then
      for name in "${replaced[@]}"; do
        mv -f -- "$name.old" "$name"
        relabel "$name"
      done
      printf '%s\n' "$added" | sed 's/^/  openlitespeed -t:/' >&2
      die "OpenLiteSpeed's config test reports a new error without the sample site or with the WebAdmin console on 127.0.0.1, so the installer put the old files back." \
        "The installer changes OpenLiteSpeed's config only when OpenLiteSpeed accepts the result; the errors are above." \
        "Fix what they name in $OLS_CONF or $OLS_ADMIN_CONF, check with $LSWS/bin/openlitespeed -t, then run this again."
    fi
    for name in "${replaced[@]}"; do
      rm -f -- "$name.old"
    done
    wrote=yes
  fi
  # A running OpenLiteSpeed that still serves the old listeners (after this
  # change, or after a run that stopped before the start) starts again once.
  old=""
  if systemctl is-active --quiet lsws; then
    old="$(ols_old_listeners)"
  fi
  if [ -n "$old" ]; then
    ols_stop_start
    if [ -n "$(ols_old_listeners)" ]; then
      die "OpenLiteSpeed still listens beyond loopback after its restart: $(ols_old_listeners | paste -sd ' ')." \
        "Its config files have the WebAdmin console on 127.0.0.1 and no sample site, yet the running server listens elsewhere too." \
        "Check $OLS_CONF, $OLS_ADMIN_CONF and ss -ltnp, put the cause right, then run this again."
    fi
  fi
  if [ "$wrote" = yes ]; then
    changed "OpenLiteSpeed: the WebAdmin console on 127.0.0.1 only, and the package's sample site (virtualHost Example and its listener Default on *:8088) removed (backups: $(printf '%s\n' "$OLS_BACKUP" "$OLS_ADMIN_BACKUP" | sed '/^$/d' | paste -sd ' '))"
  fi
  if [ -n "$old" ]; then
    changed "OpenLiteSpeed stopped and started to drop its old listeners on $(printf '%s' "$old" | paste -sd ' ')"
  fi
}

# A backstop for every hosting account's UID (the broker allocates 20000 to

# A backstop for every hosting account's UID (the broker allocates 20000 to
# 60000) in any PAM session: SFTP, cron, su or runuser. pam_limits sets
# RLIMIT_NPROC, which the kernel counts over all of the UID's tasks on the
# host. Each account's own bound is its plan's TasksMax on its user slice,
# which the broker writes and which covers PAM sessions too (pam_systemd puts
# them in that slice), so this file is the largest plan the broker allows,
# 4096: it never cuts below a plan and still stops a fork loop that runs
# outside the slice. A per-account file would count the same tasks a second
# time under a second limit that had to follow every plan change.
limits_policy() {
  cat <<'POLICY'
# Written by Sifruno's installer: a backstop of 4096 processes (threads
# count) for each hosting account's UID in every PAM session, the largest
# plan Sifruno allows. Each account's own limit is its user slice's TasksMax,
# which the account broker writes from the account's plan.
20000:60000  soft  nproc  4096
20000:60000  hard  nproc  4096
POLICY
}

step_limits() {
  if limits_policy | cmp -s - "$LIMITS_FILE" 2>/dev/null; then
    return 0
  fi
  limits_policy > "$LIMITS_FILE.new"
  chown root:root "$LIMITS_FILE.new"
  chmod 0644 "$LIMITS_FILE.new"
  mv -f -- "$LIMITS_FILE.new" "$LIMITS_FILE"
  relabel "$LIMITS_FILE"
  changed "process limit for hosting accounts written to $LIMITS_FILE (new sessions get it)"
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

step_restic() {
  local target="$PREFIX/restic" work
  ensure_dir root root 0755 "$PREFIX"
  if [ "$(sha256sum "$target" 2>/dev/null | cut -d' ' -f1)" = "$RESTIC_SHA256" ] &&
    [ "$(stat -c '%U:%G %a' "$target")" = "root:root 755" ]; then
    return 0
  fi
  work="$(mktemp -d)"
  curl -fsSL -o "$work/restic.bz2" \
    "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_amd64.bz2"
  if [ "$(sha256sum "$work/restic.bz2" | cut -d' ' -f1)" != "$RESTIC_BZ2_SHA256" ]; then
    rm -rf -- "$work"
    die "The restic ${RESTIC_VERSION} download does not match the sha256 its release publishes." \
      "Backups run only the exact restic the panel was built for, so a different file is never installed." \
      "Check the server's connection to github.com and run this again."
  fi
  bunzip2 -c -- "$work/restic.bz2" > "$work/restic"
  if [ "$(sha256sum "$work/restic" | cut -d' ' -f1)" != "$RESTIC_SHA256" ]; then
    rm -rf -- "$work"
    die "The decompressed restic ${RESTIC_VERSION} does not match its pinned sha256." \
      "The broker runs only the exact restic binary it was built for." \
      "Run this again; if it fails the same way, report it with the installer's output."
  fi
  install -o root -g root -m 0755 "$work/restic" "$target"
  rm -rf -- "$work"
  changed "restic ${RESTIC_VERSION} installed at $target"
}

# ---------------------------------------------------------------- phpMyAdmin

# The sha256 of phpMyAdmin's own files in DIR, Sifruno's config.inc.php and
# sign-in script left out: the sorted sha256sum list of every file, hashed.
pma_tree_sha256() { # pma_tree_sha256 DIR
  (cd "$1" && find . \( -path ./config.inc.php -o -path ./sifruno-signon.php \) -prune -o -type f -print0 |
    LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

# put_file OWNER GROUP MODE SOURCE TARGET: puts SOURCE at TARGET unless TARGET
# already has those bytes, that owner and mode, and is not a link. Answers
# true when it wrote.
put_file() {
  local owner="$1" group="$2" mode="$3" source="$4" target="$5"
  if [ ! -L "$target" ] && cmp -s "$source" "$target" &&
    [ "$(stat -c '%U:%G %a' "$target")" = "$owner:$group ${mode#0}" ]; then
    return 1
  fi
  install -o "$owner" -g "$group" -m "$mode" "$source" "$target.new"
  mv -f -- "$target.new" "$target"
  return 0
}

# Sifruno's two files in phpMyAdmin's folder DIR: its configuration, which
# only root and phpMyAdmin's user can read, and the sign-in script.
pma_own_files() { # pma_own_files DIR
  local wrote=no
  if put_file root "$PMA_USER" 0640 "$HERE/phpmyadmin/config.inc.php" "$1/config.inc.php"; then wrote=yes; fi
  if put_file root root 0644 "$HERE/phpmyadmin/sifruno-signon.php" "$1/sifruno-signon.php"; then wrote=yes; fi
  [ "$wrote" = yes ]
}

pma_user() {
  local uid
  if ! id "$PMA_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$PMA_STATE" --no-create-home --shell /usr/sbin/nologin "$PMA_USER"
    changed "system user $PMA_USER created for phpMyAdmin's PHP"
  fi
  uid="$(id -u "$PMA_USER")"
  if [ "$uid" -eq 0 ] || { [ "$uid" -ge 20000 ] && [ "$uid" -le 60000 ]; } || [ "$(id -G "$PMA_USER")" != "$(id -g "$PMA_USER")" ]; then
    die "The user $PMA_USER (ID $uid, groups: $(id -Gn "$PMA_USER")) cannot run phpMyAdmin." \
      "phpMyAdmin's PHP runs as its own system user: not root, outside the hosting accounts' IDs 20000 to 60000, and in no other group, so it can open no website's files." \
      "Remove that user, or give it only its own group, then run this again."
  fi
}

# phpMyAdmin's files: root's, read-only, exactly the pinned release.
pma_files() {
  local work
  ensure_dir root root 0755 "$PREFIX"
  if [ -d "$PMA_DIR" ] && [ ! -L "$PMA_DIR" ] && [ "$(pma_tree_sha256 "$PMA_DIR")" = "$PMA_TREE_SHA256" ] &&
    [ -z "$(find "$PMA_DIR" \( -type l -o ! -user root -o -perm /022 \) -print -quit)" ]; then
    if pma_own_files "$PMA_DIR"; then
      changed "phpMyAdmin's config.inc.php and sign-in script written in $PMA_DIR"
    fi
    return 0
  fi
  work="$(mktemp -d)"
  curl -fsSL -o "$work/phpmyadmin.tar.gz" \
    "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-english.tar.gz"
  if [ "$(sha256sum "$work/phpmyadmin.tar.gz" | cut -d' ' -f1)" != "$PMA_TARBALL_SHA256" ]; then
    rm -rf -- "$work"
    die "The phpMyAdmin ${PMA_VERSION} download does not match the sha256 phpmyadmin.net publishes." \
      "The panel serves only the exact phpMyAdmin release it was built for, so a different file is never installed." \
      "Check the server's connection to files.phpmyadmin.net and run this again."
  fi
  mkdir -- "$work/tree"
  tar -xzf "$work/phpmyadmin.tar.gz" -C "$work/tree" --strip-components=1 --no-same-owner --no-same-permissions
  # The setup wizard and the examples (an example sign-in page among them)
  # are never served.
  rm -rf -- "$work/tree/setup" "$work/tree/examples"
  if [ "$(pma_tree_sha256 "$work/tree")" != "$PMA_TREE_SHA256" ] || [ -n "$(find "$work/tree" ! -type f ! -type d -print -quit)" ]; then
    rm -rf -- "$work"
    die "The unpacked phpMyAdmin ${PMA_VERSION} does not match its pinned list of files." \
      "The panel serves only the exact files it was built for." \
      "Run this again; if it fails the same way, report it with the installer's output."
  fi
  rm -rf -- "$PMA_DIR.new" "$PMA_DIR.old"
  mv -- "$work/tree" "$PMA_DIR.new"
  rm -rf -- "$work"
  chown -R root:root "$PMA_DIR.new"
  chmod -R u=rwX,go=rX "$PMA_DIR.new"
  # The configuration goes in before the folder is swapped in, so phpMyAdmin
  # never runs without it.
  pma_own_files "$PMA_DIR.new" || true
  if [ -e "$PMA_DIR" ]; then
    mv -- "$PMA_DIR" "$PMA_DIR.old"
  fi
  mv -- "$PMA_DIR.new" "$PMA_DIR"
  rm -rf -- "$PMA_DIR.old"
  relabel -R "$PMA_DIR"
  changed "phpMyAdmin ${PMA_VERSION} installed in $PMA_DIR (root's, read-only)"
}

# The blowfish secret, made once, and phpMyAdmin's private folders.
pma_settings() {
  local secret target="$PMA_ETC/secret.inc.php"
  ensure_dir root "$PMA_USER" 0750 "$PMA_ETC"
  if [ ! -s "$target" ] || [ -L "$target" ]; then
    # 32 random bytes as hex. printf is bash's own, so the secret is never
    # a command argument.
    secret="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
    rm -f -- "$target.new"
    install -o root -g "$PMA_USER" -m 0640 /dev/null "$target.new"
    printf "<?php\n// Made by Sifruno's installer: phpMyAdmin's blowfish secret. Root and %s only.\n\$cfg['blowfish_secret'] = hex2bin('%s');\n" "$PMA_USER" "$secret" > "$target.new"
    unset secret
    mv -f -- "$target.new" "$target"
    changed "phpMyAdmin's blowfish secret made in $target"
  elif [ "$(stat -c '%U:%G %a' "$target")" != "root:$PMA_USER 640" ]; then
    chown root:"$PMA_USER" "$target"
    chmod 0640 "$target"
    changed "$target set to root:$PMA_USER 640"
  fi
  ensure_dir root root 0755 "$PMA_STATE"
  ensure_dir "$PMA_USER" "$PMA_USER" 0700 "$PMA_STATE/sessions"
  ensure_dir "$PMA_USER" "$PMA_USER" 0700 "$PMA_STATE/tmp"
  # PHP's errors go to a log here, which only sifpma can write (and root read).
  ensure_dir "$PMA_USER" "$PMA_USER" 0700 "$PMA_STATE/logs"
  relabel "$PMA_ETC" "$target" "$PMA_STATE" "$PMA_STATE/sessions" "$PMA_STATE/tmp" "$PMA_STATE/logs"
}

# The server-level fragment httpd_config.conf includes: phpMyAdmin's vhost
# and a listener on loopback only. Its names have no "sifruno-" prefix, so
# the broker, which owns every sifruno-* vhost, never touches them.
pma_ols_server() {
  cat <<CONF
# Written by Sifruno's installer (install.sh); a new run puts it back.
# phpMyAdmin for the panel, whose phpMyAdmin origin (HTTPS on its own
# port) proxies to this loopback listener for a browser it admitted.

virtualhost $PMA_VHOST {
  vhRoot                  $PMA_DIR/
  configFile              $PMA_VHCONF_DIR/vhconf.conf
  allowSymbolLink         0
  enableScript            1
  restrained              1
  setUIDMode              2
  user                    $PMA_USER
  group                   $PMA_USER
}

listener $PMA_VHOST {
  address                 $PMA_LISTEN
  secure                  0
  map                     $PMA_VHOST *
}
CONF
}

# phpMyAdmin's vhost: its own lsphp 8.3 run as $PMA_USER through the CGI
# daemon, PHP held to phpMyAdmin's folders and its errors logged to a file
# only $PMA_USER writes (never shown on a page), no access log (a sign-in link's
# code is in its query string), and phpMyAdmin at the root without its
# libraries, templates, vendor code or dot files, and nothing under /api
# (the panel's API path on the panel's own port).
pma_ols_vhost() {
  cat <<CONF
# Written by Sifruno's installer (install.sh); a new run puts it back.
docRoot                   $PMA_DIR/

index  {
  useServer               0
  indexFiles              index.php
  autoIndex               0
}

errorlog $PMA_LOG_DIR/error.log {
  useServer               0
  logLevel                WARN
  rollingSize             10M
  keepDays                30
}

accesslog $PMA_LOG_DIR/access.log {
  useServer               2
}

extprocessor $PMA_VHOST {
  type                    lsapi
  address                 uds://tmp/lshttpd/$PMA_VHOST.sock
  maxConns                4
  env                     PHP_LSAPI_CHILDREN=4
  env                     LSAPI_AVOID_FORK=200M
  initTimeout             60
  retryTimeout            0
  persistConn             1
  respBuffer              0
  autoStart               2
  path                    $LSWS/lsphp83/bin/lsphp
  backlog                 100
  instances               1
  runOnStartUp            0
  extUser                 $PMA_USER
  extGroup                $PMA_USER
  priority                0
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           500
  procHardLimit           500
}

scripthandler  {
  add                     lsapi:$PMA_VHOST php
}

phpIniOverride  {
php_admin_value open_basedir "$PMA_DIR/:$PMA_STATE/:$PMA_ETC/:$PANEL_RUN/:/var/lib/mysql/mysql.sock"
php_admin_value session.save_path "$PMA_STATE/sessions"
php_admin_value upload_tmp_dir "$PMA_STATE/tmp"
php_admin_value sys_temp_dir "$PMA_STATE/tmp"
php_admin_flag mysqli.allow_local_infile off
php_admin_flag allow_url_fopen off
php_admin_value upload_max_filesize 64M
php_admin_value post_max_size 64M
php_admin_value max_execution_time 600
php_admin_flag display_errors off
php_admin_flag display_startup_errors off
php_admin_flag log_errors on
php_admin_value error_log "$PMA_STATE/logs/php-error.log"
}

rewrite  {
  enable                  1
  autoLoadHtaccess        0
  rules                   <<<END_rules
RewriteRule ^/?api(/|$) - [F,L,NC]
RewriteRule (^|/)\. - [F,L]
RewriteRule ^/?(libraries|templates|vendor|sql|setup|examples|test)(/|$) - [F,L]
RewriteRule ^/?(config\.inc\.php|composer\.(json|lock)|package\.json|yarn\.lock|babel\.config\.json|ChangeLog|README|LICENSE|CONTRIBUTING\.md|RELEASE-DATE-.*)$ - [F,L]
  END_rules
}
CONF
}

# phpMyAdmin's OpenLiteSpeed config: the fragment, its vhost, the include
# line in httpd_config.conf (backup first), a config test that puts the old
# files back on a new error, and a graceful reload.
pma_openlitespeed() {
  local include="include $PMA_OLS_CONF" conf_owner log_owner work before after added name has_include=no
  conf_owner="$(stat -c '%U %G' "$LSWS/conf")"
  log_owner="$(stat -c '%U %G' "$LSWS/logs")"
  # Folders as the broker makes a site's: the owner of their parent, 0750.
  ensure_dir "${conf_owner% *}" "${conf_owner#* }" 0750 "$PMA_VHCONF_DIR"
  ensure_dir "${log_owner% *}" "${log_owner#* }" 0750 "$PMA_LOG_DIR"
  grep -qxF "$include" "$OLS_CONF" && has_include=yes
  work="$(mktemp -d)"
  pma_ols_server > "$work/server.conf"
  pma_ols_vhost > "$work/vhconf.conf"
  if [ ! -L "$PMA_OLS_CONF" ] && [ ! -L "$PMA_VHCONF_DIR/vhconf.conf" ] &&
    cmp -s "$work/server.conf" "$PMA_OLS_CONF" && cmp -s "$work/vhconf.conf" "$PMA_VHCONF_DIR/vhconf.conf" && [ "$has_include" = yes ]; then
    rm -rf -- "$work"
    return 0
  fi
  before="$(ols_test_errors)"
  for name in "$PMA_OLS_CONF" "$PMA_VHCONF_DIR/vhconf.conf"; do
    if [ -e "$name" ]; then cp -a -- "$name" "$name.old"; fi
  done
  [ -n "$OLS_BACKUP" ] || OLS_BACKUP="$(backup_file "$OLS_CONF")"
  cp -a -- "$OLS_CONF" "$OLS_CONF.old"
  install -o "${conf_owner% *}" -g "${conf_owner#* }" -m 0600 "$work/server.conf" "$PMA_OLS_CONF.new"
  install -o "${conf_owner% *}" -g "${conf_owner#* }" -m 0600 "$work/vhconf.conf" "$PMA_VHCONF_DIR/vhconf.conf.new"
  rm -rf -- "$work"
  mv -f -- "$PMA_OLS_CONF.new" "$PMA_OLS_CONF"
  mv -f -- "$PMA_VHCONF_DIR/vhconf.conf.new" "$PMA_VHCONF_DIR/vhconf.conf"
  if [ "$has_include" = no ]; then
    printf '%s\n' "$include" >> "$OLS_CONF"
  fi
  relabel "$PMA_OLS_CONF" "$PMA_VHCONF_DIR" "$PMA_VHCONF_DIR/vhconf.conf" "$PMA_LOG_DIR" "$OLS_CONF"
  after="$(ols_test_errors)"
  added="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
  if [ -n "$added" ]; then
    mv -f -- "$OLS_CONF.old" "$OLS_CONF"
    for name in "$PMA_OLS_CONF" "$PMA_VHCONF_DIR/vhconf.conf"; do
      if [ -e "$name.old" ]; then mv -f -- "$name.old" "$name"; else rm -f -- "$name"; fi
    done
    relabel "$OLS_CONF"
    printf '%s\n' "$added" | sed 's/^/  openlitespeed -t:/' >&2
    die "OpenLiteSpeed's config test reports a new error with phpMyAdmin's vhost, so the installer put the old files back." \
      "The installer changes OpenLiteSpeed's config only when OpenLiteSpeed accepts the result; the errors are above." \
      "Fix what they name, check with $LSWS/bin/openlitespeed -t, then run this again."
  fi
  rm -f -- "$OLS_CONF.old" "$PMA_OLS_CONF.old" "$PMA_VHCONF_DIR/vhconf.conf.old"
  if systemctl is-active --quiet lsws; then
    systemctl reload lsws
  fi
  changed "OpenLiteSpeed: phpMyAdmin's vhost and its listener on $PMA_LISTEN ($PMA_OLS_CONF, included from $OLS_CONF; backup: $OLS_BACKUP)"
}

step_phpmyadmin() {
  pma_user
  pma_files
  pma_settings
  pma_openlitespeed
}

# MariaDB's drop-in. Every client of MariaDB is on this server: the websites
# connect to 127.0.0.1 over TCP (a site's PHP runs in an OpenLiteSpeed
# namespace container, which does not see the socket), and the panel's
# dbhost, the broker's backups, restores and migration imports and
# phpMyAdmin use the socket. bind-address, not skip-networking, keeps the
# websites' loopback TCP.
mariadb_policy() {
  cat <<'CNF'
# Managed by the Sifruno installer (install.sh); a new run puts it back.
# MariaDB answers on loopback only. The websites reach it at 127.0.0.1, and
# the panel, the broker and phpMyAdmin through its socket, all on this server.
[mysqld]
bind-address=127.0.0.1
CNF
}

# The bind-address mariadbd starts with: the last one its option files set,
# or nothing when none does (then it listens on every address).
mariadb_bind_address() {
  my_print_defaults --mysqld | sed -n 's/^--bind[-_]address=//p' | tail -n 1
}

# The addresses a running mariadbd listens on over TCP, one per line, that
# are not 127.0.0.1.
mariadb_public_listeners() {
  ss -Hltnp | awk '/"mariadbd"/ && $4 !~ /^127\.0\.0\.1:/ { print $4 }'
}

mariadb_put_back() {
  if [ -n "$MARIADB_BACKUP" ]; then
    cp -a -- "$MARIADB_BACKUP" "$MARIADB_DROPIN"
  else
    rm -f -- "$MARIADB_DROPIN"
  fi
}

step_mariadb() {
  local policy bind public
  policy="$(mktemp)"
  mariadb_policy > "$policy"
  if [ -L "$MARIADB_DROPIN" ] || ! cmp -s "$policy" "$MARIADB_DROPIN" ||
    [ "$(stat -c '%U:%G %a' "$MARIADB_DROPIN")" != "root:root 644" ]; then
    if [ -e "$MARIADB_DROPIN" ] || [ -L "$MARIADB_DROPIN" ]; then
      MARIADB_BACKUP="$(backup_file "$MARIADB_DROPIN")"
      MARIADB_CHANGE=replaced
    else
      MARIADB_CHANGE=created
    fi
    put_file root root 0644 "$policy" "$MARIADB_DROPIN" || true
    relabel "$MARIADB_DROPIN"
  fi
  rm -f -- "$policy"
  bind="$(mariadb_bind_address)"
  if [ "$bind" != 127.0.0.1 ]; then
    [ "$MARIADB_CHANGE" = unchanged ] || changed "MariaDB: $MARIADB_DROPIN $MARIADB_CHANGE${MARIADB_BACKUP:+ (backup: $MARIADB_BACKUP)}"
    warn "MariaDB would listen on ${bind:-every address}, not on 127.0.0.1 only, so the installer did not restart it." \
      "An option file MariaDB reads after $MARIADB_DROPIN sets bind-address (my_print_defaults --mysqld lists what MariaDB starts with)." \
      "Take that bind-address line out, then run this again."
    return 0
  fi
  # bind-address is read at start only. A running MariaDB that still
  # listens beyond loopback restarts once: after this change, or after a
  # run that stopped before its restart.
  public=""
  if systemctl is-active --quiet mariadb; then
    public="$(mariadb_public_listeners)"
  fi
  if [ -z "$public" ]; then
    [ "$MARIADB_CHANGE" = unchanged ] || changed "MariaDB: bind-address 127.0.0.1 in $MARIADB_DROPIN ($MARIADB_CHANGE${MARIADB_BACKUP:+; backup: $MARIADB_BACKUP}), read when MariaDB starts"
    return 0
  fi
  if ! systemctl restart mariadb; then
    mariadb_put_back
    systemctl restart mariadb || true
    die "MariaDB did not start again with bind-address 127.0.0.1 from $MARIADB_DROPIN." \
      "The installer put the earlier file back and started MariaDB once more." \
      "Read journalctl -u mariadb, put the cause right, then run this again."
  fi
  if [ -n "$(mariadb_public_listeners)" ]; then
    die "MariaDB still listens beyond loopback after its restart: $(mariadb_public_listeners | paste -sd ' ')." \
      "MariaDB's option files give bind-address 127.0.0.1, yet the running server listens elsewhere too." \
      "Check what my_print_defaults --mysqld and ss -ltnp show, put the cause right, then run this again."
  fi
  changed "MariaDB: bind-address 127.0.0.1 in $MARIADB_DROPIN ($MARIADB_CHANGE${MARIADB_BACKUP:+; backup: $MARIADB_BACKUP}); restarted, it now listens on loopback only (it listened on $(printf '%s' "$public" | paste -sd ' '))"
}

step_services() {
  local unit
  # crond runs the sites' scheduled jobs, which the broker writes to
  # /var/spool/cron as each site's own user.
  for unit in mariadb lsws crond; do
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null || ! systemctl is-active --quiet "$unit"; then
      systemctl enable --now "$unit"
      changed "$unit enabled and started"
    fi
  done
  systemctl is-active mariadb lsws crond | sed 's/^/service: /'
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

step_lscache() {
  # OpenLiteSpeed makes each site's store here as root when it loads the
  # config and gives that folder alone to its user (2770). It never changes
  # this folder, unlike its own cachedata, which it gives to its user at
  # every start. So the folder stays root's and the broker can remove a
  # deleted site's store in it without following a link. 0711 lets
  # OpenLiteSpeed's user reach a store by name but not list them; a folder
  # OpenLiteSpeed made itself would be 0750, which its user cannot cross.
  # It keeps /var/lib's SELinux label: OpenLiteSpeed runs as
  # unconfined_service_t, which may write it.
  ensure_dir root root 0711 "$CACHE_DIR"
  relabel "$CACHE_DIR"
  stat -c 'LSCache stores folder: %U %a %n' "$CACHE_DIR"
  remove_old_cache_stores
}

# Earlier releases kept each site's store in OpenLiteSpeed's own cachedata,
# which belongs to OpenLiteSpeed's user. A store there that no config names
# any more is removed as that user, never as root, so a link put in its
# place reaches nothing that user could not delete anyway. A store a vhost
# still names is in use until the next website change rewrites every vhost
# with its store in CACHE_DIR; a later run removes it. The stores are listed
# before the config is read, so a store made meanwhile is left alone.
remove_old_cache_stores() {
  local old="$LSWS/cachedata" web_user named store
  local stores=() kept=0 removed=0 failed=0
  [ -d "$old" ] && [ ! -L "$old" ] || return 0
  for store in "$old"/sifruno-u*; do
    if [[ "${store##*/}" =~ ^sifruno-u[0-9a-f]{31}$ ]]; then
      stores+=("$store")
    fi
  done
  [ "${#stores[@]}" -gt 0 ] || return 0
  web_user="$(ols_user)"
  if ! id "$web_user" >/dev/null 2>&1; then
    log "Note: ${#stores[@]} cache store(s) of earlier releases are left in $old, because OpenLiteSpeed's user '$web_user' (from $OLS_CONF) is not a user on this server and they are removed only as that user. Fix the 'user' line in $OLS_CONF, then run this again."
    return 0
  fi
  # Every storagePath in OpenLiteSpeed's config, as an absolute path. A
  # config that cannot be read removes nothing: a store it names may be in
  # use.
  if ! named="$(find "$LSWS/conf" -type f -name '*.conf' -exec awk -v root="$LSWS" '
    $1 == "storagePath" {
      p = $2; sub(/^\$SERVER_ROOT/, root, p)
      if (p !~ /^\//) p = root "/" p
      sub(/\/+$/, "", p); print p
    }' {} +)"; then
    log "Note: ${#stores[@]} cache store(s) of earlier releases are left in $old, because OpenLiteSpeed's config in $LSWS/conf could not be read to see which are still in use (the error is above). Fix that, then run this again."
    return 0
  fi
  for store in "${stores[@]}"; do
    if printf '%s\n' "$named" | grep -qxF -- "$store"; then
      kept=$((kept + 1))
    elif (cd / && setpriv --reuid="$web_user" --regid="$(id -g "$web_user")" --clear-groups \
      --no-new-privs --inh-caps=-all --bounding-set=-all -- /usr/bin/rm -rf --one-file-system -- "$store"); then
      removed=$((removed + 1))
    else
      failed=$((failed + 1))
    fi
  done
  if [ "$removed" -gt 0 ]; then
    changed "$removed cache store(s) of deleted or moved sites removed from $old (as $web_user)"
  fi
  if [ "$kept" -gt 0 ]; then
    log "Note: $kept site(s) still use their cache store in $old. Their stores move to $CACHE_DIR at the next website change (any site's settings, a new site or a delete). Run this again after it to remove the old ones."
  fi
  if [ "$failed" -gt 0 ]; then
    log "Note: $failed cache store(s) in $old could not be removed as $web_user (the errors are above). They hold only cached pages of sites no config names. Check that $old and the stores belong to $web_user, then run this again."
  fi
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
  label_programs
  relabel -R "$PREFIX"
}

# label_programs gives the programs' folder the SELinux type bin_t. Under
# /usr/local/lib they would be lib_t, which has no domain transition, so
# systemd would run both units as init_t, its own domain. init_t may not
# set a process group (an AVC for setpgid), which the broker does before
# every command it runs, so groupadd and useradd never started and every
# account create answered 503. As bin_t the units run as
# unconfined_service_t, like OpenLiteSpeed and MariaDB.
label_programs() {
  local spec="$BIN_DIR(/.*)?"
  command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || return 0
  if ! semanage fcontext -l -C 2>/dev/null | awk '{print $1}' | grep -qxF -- "$spec"; then
    semanage fcontext -a -t bin_t "$spec"
    changed "SELinux file type bin_t recorded for $BIN_DIR"
    # Running units keep the domain they started in until they restart.
    RESTART_NEEDED=yes
  fi
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
  local panel names
  # The names the panel asks Let's Encrypt for: the broker answers their
  # HTTP-01 challenge on port 80, and nothing else at them there.
  names="$(panel_cert_names)"
  panel="${names:+ --panel-host $names}"
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
ExecStart=$BIN_DIR/hostbroker --state $BROKER_STATE --socket $BROKER_SOCKET --homes $HOMES --controller-uid $1 --web-user $2$panel
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

panel_unit() { # panel_unit PHPMYADMIN_UID
  local remote=""
  if [ -n "$PANEL_HOST" ]; then
    # phpMyAdmin needs an HTTPS origin of its own, so it comes with the
    # panel's HTTPS listener.
    remote="$remote --https-listen $PANEL_HTTPS_LISTEN --panel-host $PANEL_HOST --phpmyadmin-listen $PMA_HTTPS_LISTEN --phpmyadmin-upstream $PMA_LISTEN --phpmyadmin-uid $1"
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
# With phpMyAdmin on, its sign-in script redeems one-time codes on a socket
# here; the panel answers only phpMyAdmin's user (ID $1) on it.
RuntimeDirectory=${PANEL_RUN#/run/}
RuntimeDirectoryMode=0755
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
  local uid web_user pma_uid
  uid="$(id -u "$PANEL_USER")"
  pma_uid="$(id -u "$PMA_USER")"
  web_user="$(ols_user)"
  id "$web_user" >/dev/null 2>&1 || die "OpenLiteSpeed's user '$web_user' (from $OLS_CONF) is not a user on this server." \
    "The broker gives exactly that user read access to each website's files." \
    "Check the 'user' line in $OLS_CONF, then run this again."
  write_unit "$BROKER_UNIT" "$(broker_unit "$uid" "$web_user")"
  write_unit "$PANEL_UNIT" "$(panel_unit "$pma_uid")"
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
  local uid web_user pma_uid
  uid="$(id -u "$PANEL_USER" 2>/dev/null || true)"
  pma_uid="$(id -u "$PMA_USER" 2>/dev/null || true)"
  web_user="$(ols_user)"
  [ -r "$OLS_CONF" ] || web_user="<OpenLiteSpeed's user>"
  printf '\n%s\n' "--- $UNIT_DIR/$BROKER_UNIT"
  broker_unit "${uid:-<user ID of $PANEL_USER>}" "$web_user"
  printf '\n%s\n' "--- $UNIT_DIR/$PANEL_UNIT"
  panel_unit "${pma_uid:-<user ID of $PMA_USER>}"
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
  local cert_names
  cert_names="$(panel_cert_names)"
  if [ -n "$cert_names" ]; then
    cat <<TEXT
  3. After that, sign in from anywhere at https://${PANEL_HOST%%,*}:${PANEL_HTTPS_LISTEN##*:}/
     Once it runs, the panel asks Let's Encrypt for a certificate for
     ${cert_names//,/, } over port 80 and renews it by itself. Until it has one, and
     for an IP address, the certificate is self-signed. How it went:
       journalctl -u $PANEL_UNIT | grep 'Panel certificate:'
     With a self-signed certificate, compare the fingerprint your browser
     shows with the one the panel logged:
       journalctl -u $PANEL_UNIT | grep SHA-256
TEXT
  elif [ -n "$PANEL_HOST" ]; then
    cat <<TEXT
  3. After that, sign in from anywhere at https://${PANEL_HOST%%,*}:${PANEL_HTTPS_LISTEN##*:}/
     The certificate is self-signed. Compare the fingerprint your browser
     shows with the one the panel logged:
       journalctl -u $PANEL_UNIT | grep SHA-256
TEXT
  fi
  if [ -n "$PANEL_HOST" ]; then
    cat <<TEXT
     Open TCP ${PANEL_HTTPS_LISTEN##*:} for the panel, ${PMA_HTTPS_LISTEN##*:} for phpMyAdmin (its own
     address, https://${PANEL_HOST%%,*}:${PMA_HTTPS_LISTEN##*:}/, which each website's
     Databases page opens) and 80 and 443 for websites and Let's Encrypt in
     your firewall. The installer does not change firewall rules.
TEXT
  else
    cat <<TEXT
  3. Websites need TCP 80 and 443 open in your firewall. The installer does
     not change firewall rules. To sign in to the panel from other machines
     without an SSH forward, and to use phpMyAdmin (it opens on the panel's
     HTTPS address, on port ${PMA_HTTPS_LISTEN##*:}), run this again with --panel-host NAME.
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
  local admin_backup="$OLS_ADMIN_BACKUP" mariadb_backup="$MARIADB_BACKUP"
  [ -n "$nss_backup" ] || nss_backup="$(latest_backup "$NSSWITCH")"
  [ -n "$ols_backup" ] || ols_backup="$(latest_backup "$OLS_CONF")"
  [ -n "$sshd_backup" ] || sshd_backup="$(latest_backup "$SSHD_DROPIN")"
  [ -n "$admin_backup" ] || admin_backup="$(latest_backup "$OLS_ADMIN_CONF")"
  [ -n "$mariadb_backup" ] || mariadb_backup="$(latest_backup "$MARIADB_DROPIN")"
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
  5. Process limit for hosting accounts in PAM sessions: $LIMITS_FILE
       rm $LIMITS_FILE
     The broker's per-account slice limits are in
     $UNIT_DIR/user-<uid>.slice.d/50-sifruno-limits.conf; with the broker
     stopped, remove those files and run systemctl daemon-reload.
  6. phpMyAdmin: take the line "include $PMA_OLS_CONF" out of $OLS_CONF
     (step 4's backup is from before it), then
       rm -f $PMA_OLS_CONF && rm -rf $PMA_VHCONF_DIR $PMA_DIR $PMA_ETC
       systemctl reload lsws
     The panel drops its temporary database users (SifrunoPMA_...) within
     the hour while it runs.
  7. MariaDB on loopback only: $MARIADB_DROPIN ($MARIADB_CHANGE in this run)
       rm $MARIADB_DROPIN
TEXT
  if [ -n "$mariadb_backup" ]; then
    echo "       (or put the earlier copy back: cp -a $mariadb_backup $MARIADB_DROPIN)"
  fi
  echo "       systemctl restart mariadb"
  echo "  8. OpenLiteSpeed's WebAdmin console on loopback only: $OLS_ADMIN_CONF"
  if [ -n "$admin_backup" ]; then
    echo "       cp -a $admin_backup $OLS_ADMIN_CONF"
    echo "     then stop and start OpenLiteSpeed (a restart keeps the console where it is):"
    echo "       systemctl stop lsws; while pgrep -x litespeed >/dev/null; do sleep 1; done; systemctl start lsws"
  else
    echo "       No backup found: the installer has not changed this file."
  fi
  cat <<TEXT
  Packages, the $PANEL_USER and $PMA_USER users, websites and databases
  stay. Remove them by hand if you want them gone.
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
  step "Install OpenLiteSpeed, LSPHP 8.3, MariaDB 10.11, Podman, cronie and Apache (for the Compat tier; left off)" step_packages
  step "Label $HOMES, create the system user $PANEL_USER and Sifruno's folders in /etc and /var/lib" step_host_folders
  step "Set passwd, group and shadow in $NSSWITCH to files (backup, check, automatic rollback)" step_nsswitch
  step "Write the sshd policy $SSHD_DROPIN (backup, sshd -t, automatic rollback, reload)" step_sshd
  step "Add Sifruno's include, namespace isolation and the cache module to OpenLiteSpeed's config (backup)" step_openlitespeed
  step "Let each site's PHP run in its account's user slice: cgroups 1 in OpenLiteSpeed's CGIRLimit (backup, config test)" step_ols_cgroups
  step "Bound each hosting account to 4096 processes, the largest plan, in PAM sessions: $LIMITS_FILE" step_limits
  step "Install WP-CLI $WPCLI_VERSION in $PREFIX, checked against its pinned sha512" step_wpcli
  step "Install restic $RESTIC_VERSION in $PREFIX for backups, checked against its pinned sha256" step_restic
  step "Install phpMyAdmin $PMA_VERSION in $PMA_DIR (pinned sha256), its user $PMA_USER, and its OpenLiteSpeed vhost on $PMA_LISTEN (backup, config test)" step_phpmyadmin
  # After phpMyAdmin's step: on a new server its loopback listener is the
  # only one left for OpenLiteSpeed's vhosts until the broker writes the
  # websites' listeners, and with no listener at all OpenLiteSpeed's
  # workers exit at start ("No listener is available, stop server!").
  step "Put OpenLiteSpeed's WebAdmin console on 127.0.0.1 and remove the package's sample site on 8088 (backups, config test; a stop and start when a listener moves)" step_ols_listeners
  step "Keep MariaDB on loopback: bind-address 127.0.0.1 in $MARIADB_DROPIN (backup; a running MariaDB that listens beyond loopback restarts once)" step_mariadb
  step "Enable and start MariaDB, OpenLiteSpeed and crond" step_services
  step "Create the panel's MariaDB admin user and its 0600 option file $DB_ADMIN_CNF" step_db_admin
  step "Create the ACME challenge folder $ACME_DIR" step_acme
  step "Create the LSCache stores folder $CACHE_DIR and remove unused stores earlier releases left in $LSWS/cachedata (as OpenLiteSpeed's user)" step_lscache
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
