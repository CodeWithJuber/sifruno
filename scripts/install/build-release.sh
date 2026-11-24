#!/usr/bin/env bash
# Builds the release that scripts/install/install.sh installs on a fresh
# AlmaLinux 9 server:
#
#   artifacts/release/sifruno-linux-amd64.tar.gz
#   artifacts/release/sifruno-linux-amd64.tar.gz.sha256
#
# The tarball unpacks to sifruno-linux-amd64/ with bin/ (sifruno, hostbroker,
# hostsetup, panelctl), ui/ (the built panel), install.sh and a SHA256SUMS of
# those files. Set SIFRUNO_RELEASE_OUT to write somewhere else.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${SIFRUNO_RELEASE_OUT:-$REPO/artifacts/release}"
NAME=sifruno-linux-amd64

die() {
  echo "build-release.sh: $*" >&2
  exit 1
}

for tool in go npm tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || die "missing program: $tool"
done
if [ ! -d "$REPO/node_modules" ] || [ ! -d "$REPO/web/node_modules" ]; then
  die "the npm packages are not installed. Run these in $REPO first:
  npm ci --ignore-scripts --no-audit --no-fund
  npm --prefix web ci --ignore-scripts --no-audit --no-fund"
fi

stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT
root="$stage/$NAME"
mkdir -p "$root/bin"

echo "Building the programs (linux/amd64, CGO off, -trimpath)"
for program in sifruno hostbroker hostsetup panelctl; do
  (cd "$REPO" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -mod=readonly -trimpath -buildvcs=false -o "$root/bin/$program" "./cmd/$program")
done

echo "Building the panel UI"
(cd "$REPO" && npm run --silent panel:build)
[ -f "$REPO/web/dist/index.html" ] || die "npm run panel:build left no web/dist/index.html"
cp -R -- "$REPO/web/dist" "$root/ui"
cp -- "$HERE/install.sh" "$root/install.sh"

# Fixed modes, whatever the build machine's umask or checkout made them.
chmod -R u=rwX,go=rX "$root"
chmod 0755 "$root/install.sh" "$root"/bin/*
find "$root/ui" -type f -exec chmod 0644 {} +

(cd "$root" && find bin ui install.sh -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)

mkdir -p "$OUT"
# Root owns every file in the archive, so unpacking as root on the server
# does not hand them to whatever user ID built the release.
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")

echo "Built from $(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo 'an unversioned tree')"
echo "Release: $OUT/$NAME.tar.gz"
echo "SHA-256: $(cut -d' ' -f1 "$OUT/$NAME.tar.gz.sha256")  (also in $NAME.tar.gz.sha256)"
