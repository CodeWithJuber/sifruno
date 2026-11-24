#!/usr/bin/env bash
# Runs inside the dev VM as root. Installs Sifruno with the real installer
# (scripts/install/install.sh, from a release tarball) and then adds what
# only the proofs need. Safe to run again.
#
#   SIFRUNO_RELEASE          the release tarball, with its .sha256 beside it,
#                            or a folder a release was unpacked to. Default:
#                            /root/sifruno-linux-amd64.tar.gz
#   SIFRUNO_INSTALL_START=1  let the installer enable and start the two
#                            Sifruno units. Off by default, because the
#                            proofs start their own broker and panel.
set -euo pipefail

log() { printf '== %s %s\n' "$(date -u +%FT%TZ)" "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "provision.sh: run as root" >&2; exit 1; }

RELEASE="${SIFRUNO_RELEASE:-/root/sifruno-linux-amd64.tar.gz}"
# A tarball is unpacked here, replacing the last one, so the installer can
# be run again by hand: /root/sifruno-release/sifruno-linux-amd64/install.sh
UNPACKED=/root/sifruno-release

log "Sifruno installer"
if [ -d "$RELEASE" ]; then
  release_dir="$RELEASE"
else
  if [ ! -f "$RELEASE" ] || [ ! -f "$RELEASE.sha256" ]; then
    cat >&2 <<TEXT
provision.sh: there is no release at $RELEASE with its .sha256 beside it.
  Why: provisioning installs Sifruno with the real installer, which comes in the release.
  What to do: on the host, build the release and copy both files in, then run this again:
    scripts/install/build-release.sh
    scripts/devvm/vm.sh put artifacts/release/sifruno-linux-amd64.tar.gz /root/sifruno-linux-amd64.tar.gz
    scripts/devvm/vm.sh put artifacts/release/sifruno-linux-amd64.tar.gz.sha256 /root/sifruno-linux-amd64.tar.gz.sha256
TEXT
    exit 1
  fi
  if [ "$(sha256sum "$RELEASE" | cut -d' ' -f1)" != "$(cut -d' ' -f1 "$RELEASE.sha256")" ]; then
    echo "provision.sh: $RELEASE does not match the sha256 in $RELEASE.sha256; copy both files in again" >&2
    exit 1
  fi
  rm -rf -- "$UNPACKED"
  install -d -o root -g root -m 0700 "$UNPACKED"
  tar -xzf "$RELEASE" -C "$UNPACKED"
  release_dir="$UNPACKED/sifruno-linux-amd64"
fi
[ -f "$release_dir/install.sh" ] || { echo "provision.sh: there is no install.sh in $release_dir" >&2; exit 1; }
# The installer does the product's part: its own checks of this machine,
# the repositories and packages, the sifpanel user, nsswitch, sshd,
# OpenLiteSpeed's include, WP-CLI, MariaDB's admin option file, the ACME
# folder, the programs, hostsetup and the two units.
if [ "${SIFRUNO_INSTALL_START:-0}" = 1 ]; then
  bash "$release_dir/install.sh"
else
  bash "$release_dir/install.sh" --no-start
fi

# Everything below is for the proofs only. A real server gets none of it.

log "Apache on loopback for the Compat tier proof"
# The installer installs Apache and leaves it off. The migrate-verify proof
# starts it next to OpenLiteSpeed, which owns port 80, so here it moves to
# loopback. The installed panel listens on 127.0.0.1:8080 too: stop it
# (systemctl stop sifruno) before that proof if the units are running.
if grep -q '^Listen 80$' /etc/httpd/conf/httpd.conf; then
  cp -p /etc/httpd/conf/httpd.conf "/etc/httpd/conf/httpd.conf.bak-$(date +%Y%m%d-%H%M)"
  sed -i 's/^Listen 80$/Listen 127.0.0.1:8080/' /etc/httpd/conf/httpd.conf
fi
apachectl configtest

log "proof folder"
# proof.sh copies each proof's programs and guest script here.
install -d -o root -g root -m 0755 /opt/sifruno-proof
restorecon -R /opt/sifruno-proof

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
