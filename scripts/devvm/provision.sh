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

log "WP-CLI for the broker's WordPress install"
# The broker runs this file only while its bytes match the sha512 pinned in
# internal/hostaccounts/wordpress_linux.go (WP-CLI 2.12.0's published one).
wpcli_version=2.12.0
wpcli_sha512=be928f6b8ca1e8dfb9d2f4b75a13aa4aee0896f8a9a0a1c45cd5d2c98605e6172e6d014dda2e27f88c98befc16c040cbb2bd1bfa121510ea5cdf5f6a30fe8832
install -d -o root -g root -m 0755 /usr/local/lib/sifruno
if [ "$(sha512sum /usr/local/lib/sifruno/wp-cli.phar 2>/dev/null | cut -d' ' -f1)" != "$wpcli_sha512" ]; then
  wpcli_tmp="$(mktemp)"
  curl -fsSL -o "$wpcli_tmp" "https://github.com/wp-cli/wp-cli/releases/download/v${wpcli_version}/wp-cli-${wpcli_version}.phar"
  if [ "$(sha512sum "$wpcli_tmp" | cut -d' ' -f1)" != "$wpcli_sha512" ]; then
    rm -f "$wpcli_tmp"
    echo "provision.sh: WP-CLI download does not match its pinned sha512" >&2
    exit 1
  fi
  install -o root -g root -m 0644 "$wpcli_tmp" /usr/local/lib/sifruno/wp-cli.phar
  rm -f "$wpcli_tmp"
fi

log "services"
systemctl enable --now mariadb
systemctl enable --now lsws
systemctl is-active mariadb lsws | sed 's/^/service: /'

log "MariaDB admin option file for the panel (--db-defaults-file)"
# The panel runs as sifpanel and creates site databases through dbhost with
# this option file. The password is made here, goes to MariaDB on stdin and
# into the 0600 file, and is never a command argument. Kept once made.
dbadmin_cnf=/var/lib/sifpanel/db-admin.cnf
if [ ! -s "$dbadmin_cnf" ]; then
  dbadmin_password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  mysql --protocol=socket -uroot <<SQL
CREATE USER IF NOT EXISTS 'sifpanel_dbadmin'@'localhost' IDENTIFIED BY '$dbadmin_password';
ALTER USER 'sifpanel_dbadmin'@'localhost' IDENTIFIED BY '$dbadmin_password';
GRANT ALL PRIVILEGES ON *.* TO 'sifpanel_dbadmin'@'localhost' WITH GRANT OPTION;
SQL
  install -o sifpanel -g sifpanel -m 0600 /dev/null "$dbadmin_cnf"
  printf '[client]\nuser=sifpanel_dbadmin\npassword=%s\n' "$dbadmin_password" > "$dbadmin_cnf"
  unset dbadmin_password
fi
stat -c 'panel database option file: %U %a %n' "$dbadmin_cnf"

log "ACME HTTP-01 challenge folder"
# The panel (sifpanel) writes each challenge token here and every vhost the
# broker renders serves /.well-known/acme-challenge/ from it. One folder
# outside every home is safe to share: tokens are random. It keeps
# /var/lib's SELinux label, which OpenLiteSpeed may read.
install -d -o sifpanel -g sifpanel -m 0755 /var/lib/sifruno-acme
restorecon -R /var/lib/sifruno-acme
stat -c 'ACME challenge folder: %U %a %n' /var/lib/sifruno-acme

log "Pebble test CA for the HTTPS proof (proof only, off at boot)"
# Let's Encrypt's Pebble and its DNS test server, from the release archives.
# Each archive must match the sha256 GitHub publishes for that release
# asset, and the binary in it the one pinned here, which also tells an
# installed copy is this release.
pebble_version=2.10.1
install_pebble() { # install_pebble NAME ARCHIVE_SHA256 BINARY_SHA256
  local name="$1" archive_sha="$2" binary_sha="$3" tmp
  [ "$(sha256sum "/usr/local/bin/$name" 2>/dev/null | cut -d' ' -f1)" = "$binary_sha" ] && return 0
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$name.tar.gz" "https://github.com/letsencrypt/pebble/releases/download/v${pebble_version}/${name}-linux-amd64.tar.gz"
  if [ "$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)" != "$archive_sha" ]; then
    rm -rf -- "$tmp"
    echo "provision.sh: the $name download does not match its pinned sha256" >&2
    exit 1
  fi
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp" "${name}-linux-amd64/linux/amd64/$name"
  if [ "$(sha256sum "$tmp/${name}-linux-amd64/linux/amd64/$name" | cut -d' ' -f1)" != "$binary_sha" ]; then
    rm -rf -- "$tmp"
    echo "provision.sh: the $name binary does not match its pinned sha256" >&2
    exit 1
  fi
  install -o root -g root -m 0755 "$tmp/${name}-linux-amd64/linux/amd64/$name" "/usr/local/bin/$name"
  rm -rf -- "$tmp"
}
install_pebble pebble \
  4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed \
  4e35cad137f20f62a8e71fd104b98417daa592e901bb01ab4227074ee1990e3c
install_pebble pebble-challtestsrv \
  e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92 \
  00ec0f9680d5eecb23cb4073868a547db635775a52ba14e0392ed15c8004f1ed
restorecon /usr/local/bin/pebble /usr/local/bin/pebble-challtestsrv
# dig, for checking what challtestsrv answers.
rpm -q bind-utils >/dev/null 2>&1 || dnf -y -q install bind-utils

# Pebble serves its ACME API over HTTPS only. Its repository's test
# certificate comes with a published key, so this VM makes its own: a CA
# (api-ca.pem, which the panel trusts with --acme-ca-file) signs a
# certificate for 127.0.0.1 and localhost, and the CA key is then deleted.
# This is not the CA Pebble issues site certificates from; that one is new
# at every Pebble start, and the proof fetches it from /roots/0.
install -d -o root -g root -m 0755 /etc/pebble
if [ ! -s /etc/pebble/api-ca.pem ] || [ ! -s /etc/pebble/api-cert.pem ] || [ ! -s /etc/pebble/api-key.pem ]; then
  pebble_tmp="$(mktemp -d)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3650 \
    -subj "/CN=Sifruno dev VM Pebble API CA" -keyout "$pebble_tmp/ca.key" -out "$pebble_tmp/ca.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3650 \
    -CA "$pebble_tmp/ca.pem" -CAkey "$pebble_tmp/ca.key" -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "extendedKeyUsage=serverAuth" -keyout "$pebble_tmp/api-key.pem" -out "$pebble_tmp/api-cert.pem"
  install -o root -g root -m 0600 "$pebble_tmp/api-key.pem" /etc/pebble/api-key.pem
  install -o root -g root -m 0644 "$pebble_tmp/api-cert.pem" /etc/pebble/api-cert.pem
  install -o root -g root -m 0644 "$pebble_tmp/ca.pem" /etc/pebble/api-ca.pem
  rm -rf -- "$pebble_tmp"
fi
openssl verify -CAfile /etc/pebble/api-ca.pem /etc/pebble/api-cert.pem

# Validation goes to port 80 (HTTP-01) and 443 (TLS-ALPN-01) of whatever
# challtestsrv answers, which is 127.0.0.1 for every name. The key and
# certificate reach the service as systemd credentials, so the key stays
# root-only and Pebble runs as a throwaway user.
pebble_changed=no
put_file() { # put_file PATH < content
  cat > "$1.new"
  if cmp -s "$1.new" "$1"; then
    rm -f -- "$1.new"
  else
    mv -- "$1.new" "$1"
    chmod 0644 "$1"
    restorecon "$1"
    pebble_changed=yes
  fi
}
put_file /etc/pebble/pebble-config.json <<'JSON'
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "/run/credentials/pebble.service/api-cert.pem",
    "privateKey": "/run/credentials/pebble.service/api-key.pem",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": [],
    "retryAfter": {
      "authz": 3,
      "order": 5
    },
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {
        "description": "90-day certificates, as Let's Encrypt issues",
        "validityPeriod": 7776000
      }
    }
  }
}
JSON
# No [Install] section: the proof starts these, and they never start at boot.
put_file /etc/systemd/system/pebble-challtestsrv.service <<'UNIT'
[Unit]
Description=Pebble DNS test server for the dev VM's HTTPS proof (every name is 127.0.0.1)
Documentation=https://github.com/letsencrypt/pebble

[Service]
DynamicUser=yes
ExecStart=/usr/local/bin/pebble-challtestsrv -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -defaultIPv4 127.0.0.1 -defaultIPv6= -http01= -https01= -tlsalpn01= -doh=
UNIT
put_file /etc/systemd/system/pebble.service <<'UNIT'
[Unit]
Description=Pebble test ACME CA for the dev VM's HTTPS proof
Documentation=https://github.com/letsencrypt/pebble
Requires=pebble-challtestsrv.service
After=pebble-challtestsrv.service

[Service]
DynamicUser=yes
LoadCredential=api-cert.pem:/etc/pebble/api-cert.pem
LoadCredential=api-key.pem:/etc/pebble/api-key.pem
Environment=PEBBLE_VA_NOSLEEP=1
ExecStart=/usr/local/bin/pebble -config /etc/pebble/pebble-config.json -dnsserver 127.0.0.1:8053
UNIT
if [ "$pebble_changed" = yes ]; then
  systemctl daemon-reload
fi
/usr/local/bin/pebble -version 2>&1 | head -1 | sed 's/^/installed: /'
{ systemctl is-enabled pebble-challtestsrv pebble 2>&1 || true; } | sed 's/^/at boot: /'

log "done"
