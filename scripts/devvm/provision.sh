#!/usr/bin/env bash
# Runs inside the dev VM as root. Installs the Phase 1 stack and prepares the
# host policy the account broker expects. Safe to run again.
#
# This is the dev VM's stand-in for the one-command installer of Phase 1. It
# shows what that installer has to do; it is not that installer.
set -euo pipefail

log() { printf '== %s %s\n' "$(date -u +%FT%TZ)" "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "provision.sh: run as root" >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "almalinux" ] || [ "${VERSION_ID%%.*}" != "9" ]; then
  echo "provision.sh: AlmaLinux 9 only" >&2
  exit 1
fi

log "repositories"
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
fi
rpm -q epel-release >/dev/null 2>&1 || dnf -y -q install epel-release
dnf config-manager --set-enabled crb
# LiteSpeed's lsphp extension packages link against oniguruma, ICU and gd
# builds that EL9 only gets from Remi. Without it the install fails with
# "nothing provides libonig.so.105", so LiteSpeed's setup script adds it too.
rpm -q remi-release >/dev/null 2>&1 || dnf -y -q install https://rpms.remirepo.net/enterprise/remi-release-9.rpm

log "packages"
dnf -y -q module enable mariadb:10.11
dnf -y -q install openlitespeed \
  lsphp83 lsphp83-common lsphp83-mysqlnd lsphp83-gd lsphp83-mbstring lsphp83-xml \
  lsphp83-opcache lsphp83-intl lsphp83-zip lsphp83-process lsphp83-bcmath lsphp83-pdo \
  mariadb-server podman openssh-clients rsync tar unzip policycoreutils-python-utils xfsprogs quota \
  httpd httpd-tools
rpm -q openlitespeed lsphp83 mariadb-server podman httpd | sed 's/^/installed: /'

log "Apache for the Compat tier"
# Apache serves the sites whose .htaccess OpenLiteSpeed would not honour. It
# stays off port 80, which belongs to OpenLiteSpeed, and is not enabled at
# boot here: the proofs start it when they need it.
if grep -q '^Listen 80$' /etc/httpd/conf/httpd.conf; then
  cp -p /etc/httpd/conf/httpd.conf "/etc/httpd/conf/httpd.conf.bak-$(date +%Y%m%d-%H%M)"
  sed -i 's/^Listen 80$/Listen 127.0.0.1:8080/' /etc/httpd/conf/httpd.conf
fi
apachectl configtest

log "/home on XFS with quota"
# vm.sh mounts the second disk at /home with uquota,gquota through cloud-init.
findmnt -n -o FSTYPE,OPTIONS /home | grep -q '^xfs .*usrquota' || { echo "provision.sh: /home is not XFS with user quota" >&2; exit 1; }
restorecon -R /home

log "account broker host policy"
# The broker accepts local files as the only passwd/group/shadow authority and
# refuses to change that itself. A stock AlmaLinux 9 lists sss and systemd too.
if ! grep -Eq '^passwd:[[:space:]]+files[[:space:]]*$' /etc/nsswitch.conf; then
  cp -p /etc/nsswitch.conf "/etc/nsswitch.conf.bak-$(date +%Y%m%d-%H%M)"
  sed -i -E 's/^(passwd|group|shadow):.*/\1:     files/' /etc/nsswitch.conf
fi
# The controller is the unprivileged user the panel runs as. It is the only
# peer the broker's socket admits.
id sifpanel >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/sifpanel --create-home --shell /usr/sbin/nologin sifpanel
install -d -o root -g root -m 0755 /etc/sifruno /etc/sifruno/ssh /run/sifruno-broker
# 0711: sshd, running as the account, can open its own key file by name but
# cannot list the directory; the broker requires exactly this mode.
install -d -o root -g root -m 0711 /etc/sifruno/ssh/authorized_keys
restorecon -R /etc/sifruno

log "sshd: hosting accounts are SFTP-only with broker-managed keys"
# Deny by default: every login is SFTP-only and uses the key file the broker
# writes, unless it is root or in wheel. An account the broker forgot to
# classify therefore still cannot get a shell or forward a port.
cat > /etc/ssh/sshd_config.d/40-sifruno.conf.new <<'SSHD'
# Managed by Sifruno provisioning.
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
if ! cmp -s /etc/ssh/sshd_config.d/40-sifruno.conf.new /etc/ssh/sshd_config.d/40-sifruno.conf 2>/dev/null; then
  mv /etc/ssh/sshd_config.d/40-sifruno.conf.new /etc/ssh/sshd_config.d/40-sifruno.conf
  chmod 0600 /etc/ssh/sshd_config.d/40-sifruno.conf
  restorecon /etc/ssh/sshd_config.d/40-sifruno.conf
  # Validate before applying, and reload rather than restart so the session
  # running this script stays up if the new policy is wrong.
  if ! sshd -t; then
    mv /etc/ssh/sshd_config.d/40-sifruno.conf /root/40-sifruno.conf.rejected
    echo "provision.sh: sshd rejected the new policy; it was moved to /root/40-sifruno.conf.rejected" >&2
    exit 1
  fi
  systemctl reload sshd
else
  rm -f /etc/ssh/sshd_config.d/40-sifruno.conf.new
fi

log "OpenLiteSpeed: Sifruno config fragment and namespace isolation"
# The broker writes conf/sifruno.conf and the vhosts but never edits the
# server-wide file; the installer adds the include once. A vhost's namespace
# setting applies only when the server-level one is not 0.
conf=/usr/local/lsws/conf/httpd_config.conf
if ! grep -q '^include /usr/local/lsws/conf/sifruno.conf$' "$conf"; then
  cp -a "$conf" "$conf.bak-$(date +%Y%m%d-%H%M)"
  if grep -qE '^namespace[[:space:]]' "$conf"; then
    sed -i -E 's/^namespace[[:space:]].*/namespace                 1/' "$conf"
  else
    printf '%s\n' 'namespace                 1' >> "$conf"
  fi
  touch /usr/local/lsws/conf/sifruno.conf
  chown --reference="$conf" /usr/local/lsws/conf/sifruno.conf
  chmod 0600 /usr/local/lsws/conf/sifruno.conf
  printf '%s\n' 'include /usr/local/lsws/conf/sifruno.conf' >> "$conf"
fi

log "services"
systemctl enable --now mariadb
systemctl enable --now lsws
systemctl is-active mariadb lsws | sed 's/^/service: /'

log "done"
