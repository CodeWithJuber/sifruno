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
usage: proof.sh broker-sftp [extra-accounts] | wordpress-ols | migrate-verify | broker-web | broker-wordpress | broker-site-actions | site-domains | files | backups | broker-isolation | account-limits | site-tools | wordpress-wizard | phpmyadmin | whmcs-module | panel-shell | customer-login | installer-sshd
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
  broker-web    The broker's web operation: OpenLiteSpeed may read the home,
                a quota is set, the vhost is rendered, tested and reloaded,
                a rejected config changes nothing, a symlinked public_html is
                refused, and delete takes the site out first.
  broker-wordpress
                The WordPress install: dbhost creates the site's database,
                the broker runs WP-CLI as the site user with the passwords
                on stdin, and the site serves WordPress.
  broker-site-actions
                The site page's changes at the broker: PHP 8.3 to 8.4 (it
                installs LSPHP 8.4 if missing), suspend (403 from the broker's
                own empty folder, no /home path in the vhost), a second
                suspend, resume, and delete.
  site-domains  A site's other domains and redirects: an alias and another
                registered domain serve the site, a path redirect answers 301
                with its Location, www redirects to the bare domain with its
                path kept (ACME challenges excepted), another account cannot
                take a domain, config-injection attempts are refused, one
                certificate from Pebble names every domain that points here
                (a domain left out of /etc/hosts stays http), a suspended
                site answers 403 and redirects nothing, and a removed alias
                leaves the listener and the next certificate.
  files         The file manager at the broker: the helper runs as the site's
                user in its slice with no new privileges, an upload lands
                owned by that user and counts against its quota (an upload
                over it is refused, leaving nothing), a link to /etc/shadow
                is listed but never read, an edit of index.php changes what
                the site serves (a stale save is refused), and deleting a
                folder with links inside leaves their targets alone.
  backups       Website backups with restic, off the server: an SFTP user
                on the VM stands in for the storage server (a wrong host
                key is refused), a WordPress site is backed up, its files
                deleted and a table dropped, both restored, the site serves
                its title again, the restore drill passes, and no password
                is in any process's arguments.
  broker-isolation
                A tenant renames its own public_html: only its account is
                marked; another account still changes PHP (8.4, installed if
                missing), is suspended and resumed, also when its change
                rewrites the tenant's vhost; the operator suspends the tenant
                (403), uses its new public_html (a link is refused), resumes
                it, and deletes it after the tenant changed its home's mode.
  account-limits
                Per-account process, memory and CPU limits: this release's
                installer steps (pam_limits nproc for the account UIDs,
                OpenLiteSpeed cgroups 1), the broker's slice drop-in at
                create and plan change (also of an active slice), a runuser
                session in the user slice with TasksMax set, a tenant's fork
                loop stopping at the limit, the site's lsphp in its slice
                with its rlimits read from /proc, and the delete of an
                active site while a fork loop runs.
  site-tools    A site's scheduled jobs, logs and usage at the broker: a job
                the broker writes runs as the site's user, in its user slice,
                under the limits.d nproc, within two minutes, and a job with
                % is refused; the access log tail shows a request just made;
                disk use grows after the user writes a file and traffic after
                requests; delete takes the crontab and the traffic counter.
  wordpress-wizard
                The New website wizard end to end: the panel runs as sifpanel
                with the broker and the MariaDB option file, a browser on this
                host signs in and creates a WordPress site, follows the job to
                the last screen, and the VM checks the site it made, over
                https with a certificate from the VM's Pebble test CA. Needs
                Node, Playwright's Chromium (or SIFRUNO_PROOF_CHROME) and the
                web packages.
  phpmyadmin    One-click phpMyAdmin: this release's installer step runs twice
                (the second changes nothing) and OpenLiteSpeed serves
                phpMyAdmin on 127.0.0.1:8090 only; the panel (a proof build
                whose temporary users last 2 minutes) runs as sifpanel with
                its HTTPS listener and phpMyAdmin's own HTTPS origin on
                another port; a browser on this host makes two PHP sites with
                a database each, clicks Open phpMyAdmin on the first one's
                Databases tab and lands in phpMyAdmin on its own origin,
                signed in, listing that site's database and not the other's;
                the panel no longer serves phpMyAdmin and refuses its API to
                phpMyAdmin's origin; the used link is refused; the admission
                cookie alone works until the temporary user expires; the VM
                checks the user's grants, that its password is in no process
                argument or log, and that the sweeper drops it. Needs
                Node, Playwright's Chromium (or SIFRUNO_PROOF_CHROME) and the
                web packages, and files.phpmyadmin.net from the VM.
  whmcs-module  The WHMCS module (integrations/whmcs) with the VM's lsphp
                CLI against the real panel and broker: the panel also serves
                HTTPS with its self-signed certificate, an API token is made
                through the session API, and the module tests the connection
                (a wrong token and no certificate file are refused), creates a
                WordPress site whose service login signs in, suspends it
                (403), unsuspends and terminates it; no token or password is
                in its log.
  panel-shell   Phase 1 panel shell and admin sign-in: the panel runs in the VM
                with throwaway state and a browser on this host drives it
                (first-run admin setup with 2FA, sign-in, code replay and rate
                limits, menu, page URLs, Ctrl+K, Websites to Files, phone
                width, public preview), and over the HTTPS listener as
                another machine would (admin-only, certificate fingerprint). Needs Node, the repo's npm packages and Playwright's
                Chromium, or a Chrome binary in SIFRUNO_PROOF_CHROME.
  customer-login
                Customer logins end to end: the panel runs as sifpanel with
                the broker and also serves HTTPS for panel.sifruno.test; a
                browser on this host signs in as the admin, has the wizard
                make two PHP sites, gives a customer a login for one, and the
                customer, over HTTPS, finishes setup from the link with an
                authenticator code, signs in, sees only its site, and is
                refused the other by address and by API; the admin views the
                panel as the customer (banner, customer's menu) and goes
                back; turning the login off signs the customer out. Needs
                Node, Playwright's Chromium (or SIFRUNO_PROOF_CHROME) and the
                web packages.
  installer-sshd
                The installer's sshd pre-checks: on copies of the VM's sshd
                configuration, someone must still be able to sign in with a
                key once passwords are off, and each way that would fail
                (PermitRootLogin no, a comment-only key file, loose modes, a
                Match rule on the admin's address) is refused. Live sshd is
                not changed.
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
  installer-sshd)
    "$HERE/vm.sh" ssh 'install -d -m 0755 /opt/sifruno-proof'
    "$HERE/vm.sh" put "$REPO/scripts/install/install.sh" /opt/sifruno-proof/install.sh
    "$HERE/vm.sh" put "$HERE/proofs/installer-sshd.guest.sh" /opt/sifruno-proof/installer-sshd.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/install.sh /opt/sifruno-proof/installer-sshd.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/installer-sshd-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/installer-sshd.guest.sh | tee "$transcript" || status=$?
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
  broker-web)
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
    "$HERE/vm.sh" put "$HERE/proofs/broker-web.guest.sh" /opt/sifruno-proof/broker-web.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/hostaccounts.test /opt/sifruno-proof/broker-web.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/broker-web-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/broker-web.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  broker-site-actions)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/broker-site-actions.guest.sh" /opt/sifruno-proof/broker-site-actions.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/broker-site-actions.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/broker-site-actions-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/broker-site-actions.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  site-domains)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/site-domains.guest.sh" /opt/sifruno-proof/site-domains.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/site-domains.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/site-domains-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/site-domains.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  files)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    build "$stage/sifruno-files" ./cmd/sifruno-files
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive sifruno-files; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/files.guest.sh" /opt/sifruno-proof/files.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/sifruno-files /opt/sifruno-proof/files.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/files-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/files.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  broker-isolation)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/broker-isolation.guest.sh" /opt/sifruno-proof/broker-isolation.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/broker-isolation.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/broker-isolation-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/broker-isolation.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  account-limits)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    # The guest runs this release's two installer steps from install.sh.
    "$HERE/vm.sh" put "$REPO/scripts/install/install.sh" /opt/sifruno-proof/install.sh
    "$HERE/vm.sh" put "$HERE/proofs/account-limits.guest.sh" /opt/sifruno-proof/account-limits.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/install.sh /opt/sifruno-proof/account-limits.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/account-limits-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/account-limits.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  site-tools)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    # A broker left running by an earlier proof holds its binary open.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/site-tools.guest.sh" /opt/sifruno-proof/site-tools.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/site-tools.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/site-tools-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/site-tools.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  broker-wordpress)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    build "$stage/dbdrive" ./scripts/devvm/dbdrive
    # A broker left running by an earlier proof holds its binary open, so
    # stop it before the copy replaces the file. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive dbdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/broker-wordpress.guest.sh" /opt/sifruno-proof/broker-wordpress.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/dbdrive /opt/sifruno-proof/broker-wordpress.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/broker-wordpress-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/broker-wordpress.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  backups)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    build "$stage/hostbroker" ./cmd/hostbroker
    build "$stage/brokerdrive" ./scripts/devvm/brokerdrive
    build "$stage/dbdrive" ./scripts/devvm/dbdrive
    # Stop a broker an earlier proof left running before its binary is
    # replaced. Its state stays on disk.
    "$HERE/vm.sh" ssh 'systemctl stop sifruno-broker-proof 2>/dev/null; install -d -m 0755 /opt/sifruno-proof'
    for file in hostbroker brokerdrive dbdrive; do
      "$HERE/vm.sh" put "$stage/$file" "/opt/sifruno-proof/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/backups.guest.sh" /opt/sifruno-proof/backups.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/brokerdrive /opt/sifruno-proof/dbdrive /opt/sifruno-proof/backups.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/backups-$(date -u +%Y%m%dT%H%M%SZ).txt"
    status=0
    "$HERE/vm.sh" ssh /opt/sifruno-proof/backups.guest.sh | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  wordpress-wizard)
    stage="$(mktemp -d)"
    tunnel=""
    trap 'if [ -n "$tunnel" ]; then kill "$tunnel" 2>/dev/null; fi; rm -rf -- "$stage"' EXIT
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/var/lib/sifpanel/wizard-$stamp"
    port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
    build "$stage/sifruno" ./cmd/sifruno
    build "$stage/hostbroker" ./cmd/hostbroker
    (cd "$REPO" && npm run --silent panel:build >/dev/null)
    # Seed the state here so the browser can read its operator key from a
    # file; a few seconds is enough to create it.
    timeout 5 "$stage/sifruno" --listen 127.0.0.1:0 --sites-listen "" --state "$stage/state" --ui "$REPO/web/dist" >/dev/null 2>&1 || true
    test -s "$stage/state/operator/access.key"
    tar -czf "$stage/dist.tgz" -C "$REPO/web" dist
    tar -czf "$stage/state.tgz" -C "$stage" state
    "$HERE/vm.sh" ssh "systemctl stop sifruno-broker-proof 2>/dev/null; pkill -x sifruno; install -d -m 0755 /opt/sifruno-proof; install -d -o sifpanel -g sifpanel -m 0700 $guest" || true
    "$HERE/vm.sh" put "$stage/hostbroker" /opt/sifruno-proof/hostbroker
    for file in sifruno dist.tgz state.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/wordpress-wizard.guest.sh" /opt/sifruno-proof/wordpress-wizard.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/wordpress-wizard.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    run="$OUT/wordpress-wizard-$stamp"
    transcript="$run.txt"
    domain="wiz$(date +%s | tail -c 6).proof.test"
    # The panel binds the guest's loopback only; reach it through SSH on the
    # same port number, so the browser's Origin matches the panel's address.
    "$HERE/vm.sh" forward "$port" &
    tunnel=$!
    # Steps run inside the pipe to tee (a subshell), so a failure leaves a
    # marker file rather than a variable.
    {
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/wordpress-wizard.guest.sh start $guest $port" || touch "$stage/failed"
      for _ in $(seq 30); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 1; done
      (cd "$REPO" && node scripts/devvm/proofs/wordpress-wizard.qa.mjs "http://127.0.0.1:$port" "$stage/state" "$run" "$domain" \
        "$HERE/vm.sh" "$guest/state/wizard/jobs.json" "${SIFRUNO_PROOF_CHROME:-}") || touch "$stage/failed"
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/wordpress-wizard.guest.sh check $guest $domain" || touch "$stage/failed"
      # The browser run also made a PHP site with a database at php-<domain>.
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/wordpress-wizard.guest.sh check-php $guest php-$domain" || touch "$stage/failed"
    } 2>&1 | tee "$transcript"
    echo "Transcript: $transcript (screenshots in $run/)"
    [ ! -e "$stage/failed" ]
    ;;
  phpmyadmin)
    stage="$(mktemp -d)"
    tunnels=()
    trap 'kill "${tunnels[@]}" 2>/dev/null; rm -rf -- "$stage"' EXIT
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/var/lib/sifpanel/phpmyadmin-$stamp"
    # Three free ports: the panel's loopback address (first-run setup), its
    # HTTPS listener for panel.proof.test, and phpMyAdmin's own HTTPS origin.
    read -r port panel pma < <(python3 -c 'import socket
s = [socket.socket() for _ in range(3)]
for x in s: x.bind(("127.0.0.1", 0))
print(*[x.getsockname()[1] for x in s])')
    # The panel is a proof build: only the sifruno_proof tag gives it
    # --phpmyadmin-test-login-ttl, which a release binary does not have.
    (cd "$REPO" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags sifruno_proof -o "$stage/sifruno" ./cmd/sifruno)
    build "$stage/hostbroker" ./cmd/hostbroker
    (cd "$REPO" && npm run --silent panel:build >/dev/null)
    # Seed the state here so the browser can read its operator key from a
    # file; a few seconds is enough to create it.
    timeout 5 "$stage/sifruno" --listen 127.0.0.1:0 --sites-listen "" --state "$stage/state" --ui "$REPO/web/dist" >/dev/null 2>&1 || true
    test -s "$stage/state/operator/access.key"
    tar -czf "$stage/dist.tgz" -C "$REPO/web" dist
    tar -czf "$stage/state.tgz" -C "$stage" state
    "$HERE/vm.sh" ssh "systemctl stop sifruno-broker-proof 2>/dev/null; pkill -x sifruno; install -d -m 0755 /opt/sifruno-proof /opt/sifruno-proof/install /opt/sifruno-proof/install/phpmyadmin; install -d -o sifpanel -g sifpanel -m 0700 $guest" || true
    "$HERE/vm.sh" put "$stage/hostbroker" /opt/sifruno-proof/hostbroker
    for file in sifruno dist.tgz state.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    # The installer's step reads its phpmyadmin/ files from beside install.sh.
    "$HERE/vm.sh" put "$REPO/scripts/install/install.sh" /opt/sifruno-proof/install/install.sh
    for file in config.inc.php sifruno-signon.php; do
      "$HERE/vm.sh" put "$REPO/scripts/install/phpmyadmin/$file" "/opt/sifruno-proof/install/phpmyadmin/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/phpmyadmin.guest.sh" /opt/sifruno-proof/phpmyadmin.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/install/install.sh /opt/sifruno-proof/phpmyadmin.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    run="$OUT/phpmyadmin-$stamp"
    transcript="$run.txt"
    domain="pma$(date +%s | tail -c 6).proof.test"
    # The guest listens on 127.0.0.1 only; each port is forwarded as itself,
    # so every Origin the browser sends matches the panel's own.
    for p in "$port" "$panel" "$pma"; do
      "$HERE/vm.sh" forward "$p" &
      tunnels+=("$!")
    done
    # Steps run inside the pipe to tee (a subshell), so a failure leaves a
    # marker file rather than a variable.
    {
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/phpmyadmin.guest.sh install" || touch "$stage/failed"
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/phpmyadmin.guest.sh start $guest $port $panel $pma" || touch "$stage/failed"
      for _ in $(seq 30); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 1; done
      (cd "$REPO" && node scripts/devvm/proofs/phpmyadmin.qa.mjs "http://127.0.0.1:$port" "https://panel.proof.test:$panel" "https://panel.proof.test:$pma" "$stage/state" "$run" "$domain" \
        "$HERE/vm.sh" "$guest" "${SIFRUNO_PROOF_CHROME:-}") || touch "$stage/failed"
    } 2>&1 | tee "$transcript"
    echo "Transcript: $transcript (screenshots in $run/)"
    [ ! -e "$stage/failed" ]
    ;;
  whmcs-module)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/var/lib/sifpanel/whmcs-$stamp"
    build "$stage/sifruno" ./cmd/sifruno
    build "$stage/hostbroker" ./cmd/hostbroker
    tar -czf "$stage/whmcs.tgz" -C "$REPO/integrations/whmcs" modules tests/stubs.php -C "$HERE/proofs" whmcs-module.drive.php
    "$HERE/vm.sh" ssh "systemctl stop sifruno-broker-proof 2>/dev/null; pkill -x sifruno; install -d -m 0755 /opt/sifruno-proof; install -d -o sifpanel -g sifpanel -m 0700 $guest" || true
    "$HERE/vm.sh" put "$stage/hostbroker" /opt/sifruno-proof/hostbroker
    for file in sifruno whmcs.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/whmcs-module.guest.sh" /opt/sifruno-proof/whmcs-module.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/whmcs-module.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    transcript="$OUT/whmcs-module-$stamp.txt"
    domain="whmcs$(date +%s | tail -c 6).proof.test"
    status=0
    "$HERE/vm.sh" ssh "/opt/sifruno-proof/whmcs-module.guest.sh $guest $domain" | tee "$transcript" || status=$?
    echo "Transcript: $transcript"
    exit "$status"
    ;;
  customer-login)
    stage="$(mktemp -d)"
    tunnel_web=""
    tunnel_tls=""
    trap 'if [ -n "$tunnel_web" ]; then kill "$tunnel_web" 2>/dev/null; fi; if [ -n "$tunnel_tls" ]; then kill "$tunnel_tls" 2>/dev/null; fi; rm -rf -- "$stage"' EXIT
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/var/lib/sifpanel/customers-$stamp"
    free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
    port="$(free_port)"
    tls_port="$(free_port)"
    build "$stage/sifruno" ./cmd/sifruno
    build "$stage/hostbroker" ./cmd/hostbroker
    (cd "$REPO" && npm run --silent panel:build >/dev/null)
    # Seed the state here so the browser can read its operator key from a
    # file; a few seconds is enough to create it.
    timeout 5 "$stage/sifruno" --listen 127.0.0.1:0 --sites-listen "" --state "$stage/state" --ui "$REPO/web/dist" >/dev/null 2>&1 || true
    test -s "$stage/state/operator/access.key"
    tar -czf "$stage/dist.tgz" -C "$REPO/web" dist
    tar -czf "$stage/state.tgz" -C "$stage" state
    "$HERE/vm.sh" ssh "systemctl stop sifruno-broker-proof 2>/dev/null; pkill -x sifruno; install -d -m 0755 /opt/sifruno-proof; install -d -o sifpanel -g sifpanel -m 0700 $guest" || true
    "$HERE/vm.sh" put "$stage/hostbroker" /opt/sifruno-proof/hostbroker
    for file in sifruno dist.tgz state.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/customer-login.guest.sh" /opt/sifruno-proof/customer-login.guest.sh
    "$HERE/vm.sh" ssh 'chmod 0755 /opt/sifruno-proof/hostbroker /opt/sifruno-proof/customer-login.guest.sh; restorecon -R /opt/sifruno-proof'
    mkdir -p "$OUT"
    run="$OUT/customer-login-$stamp"
    transcript="$run.txt"
    domain="cl$(date +%s | tail -c 6).proof.test"
    # The panel binds the guest's loopback only; reach both listeners through
    # SSH on the same port numbers, so Origins and the setup link match.
    "$HERE/vm.sh" forward "$port" &
    tunnel_web=$!
    "$HERE/vm.sh" forward "$tls_port" &
    tunnel_tls=$!
    {
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/customer-login.guest.sh start $guest $port $tls_port" || touch "$stage/failed"
      for _ in $(seq 30); do curl -fs -o /dev/null "http://127.0.0.1:$port/" && break; sleep 1; done
      (cd "$REPO" && node scripts/devvm/proofs/customer-login.qa.mjs "http://127.0.0.1:$port" "$stage/state/operator/access.key" "$run" "make:$domain" \
        "${SIFRUNO_PROOF_CHROME:-}" "https://panel.sifruno.test:$tls_port") || touch "$stage/failed"
      "$HERE/vm.sh" ssh "/opt/sifruno-proof/customer-login.guest.sh check $guest" || touch "$stage/failed"
    } 2>&1 | tee "$transcript"
    echo "Transcript: $transcript (screenshots in $run/)"
    [ ! -e "$stage/failed" ]
    ;;
  panel-shell)
    stage="$(mktemp -d)"
    trap 'rm -rf -- "$stage"' EXIT
    # shellcheck disable=SC1091
    . "${SIFRUNO_DEVVM_DIR:-$HOME/.cache/sifruno-devvm}/ports"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    guest="/opt/sifruno-proof/panel-$stamp"
    build "$stage/sifruno" ./cmd/sifruno
    (cd "$REPO" && npm run --silent panel:build >/dev/null)
    # Seed the state here so the browser checks can read its operator key
    # without the key ever leaving a file. A few seconds is enough to create it.
    timeout 5 "$stage/sifruno" --listen 127.0.0.1:0 --sites-listen "" --state "$stage/state" --ui "$REPO/web/dist" >/dev/null 2>&1 || true
    test -s "$stage/state/operator/access.key"
    tar -czf "$stage/dist.tgz" -C "$REPO/web" dist
    tar -czf "$stage/state.tgz" -C "$stage" state
    # Each run gets its own directory in the disposable VM; stop the last one.
    "$HERE/vm.sh" ssh "pkill -x sifruno; if [ -f /opt/sifruno-proof/relay.pid ]; then kill \$(cat /opt/sifruno-proof/relay.pid) 2>/dev/null; fi; install -d -m 0700 $guest" || true
    for file in sifruno dist.tgz state.tgz; do
      "$HERE/vm.sh" put "$stage/$file" "$guest/$file"
    done
    "$HERE/vm.sh" put "$HERE/proofs/panel-relay.py" /opt/sifruno-proof/panel-relay.py
    # The panel accepts browser writes only from its own origin, so it listens
    # on the same port number QEMU forwards from this host to guest port 80.
    "$HERE/vm.sh" ssh "set -e; cd $guest; tar -xzf dist.tgz; tar -xzf state.tgz; chmod 0755 sifruno; restorecon -R /opt/sifruno-proof; \
      (nohup ./sifruno --listen 127.0.0.1:$HTTP_PORT --sites-listen 127.0.0.1:8082 --state ./state --ui ./dist --https-listen 0.0.0.0:443 --panel-host panel.sifruno.test > panel.log 2>&1 &); \
      nohup /usr/bin/python3 /opt/sifruno-proof/panel-relay.py $HTTP_PORT > relay.log 2>&1 & echo \$! > /opt/sifruno-proof/relay.pid"
    # Python starts slowly under software emulation; wait for the relay.
    for _ in $(seq 90); do curl -fs -o /dev/null "http://127.0.0.1:$HTTP_PORT/" && break; sleep 2; done
    # The guest also serves HTTPS on 443 (QEMU forwards HTTPS_PORT to it) for
    # panel.sifruno.test with a self-signed certificate; the browser checks
    # that it serves the fingerprint the panel printed at start.
    fingerprint="$("$HERE/vm.sh" ssh "grep -o 'SHA-256 [0-9A-F:]*' $guest/panel.log | head -1 | cut -d' ' -f2")"
    mkdir -p "$OUT"
    run="$OUT/panel-shell-$stamp"
    transcript="$run.txt"
    status=0
    {
      # shellcheck disable=SC2016 # expands in the guest
      "$HERE/vm.sh" ssh 'echo "guest: $(cat /etc/almalinux-release), kernel $(uname -r), SELinux $(getenforce)"'
      (cd "$REPO" && node scripts/devvm/proofs/panel-shell.qa.mjs "http://127.0.0.1:$HTTP_PORT" "$stage/state" "$run" "${SIFRUNO_PROOF_CHROME:-}" "https://panel.sifruno.test:$HTTPS_PORT" "$fingerprint")
    } | tee "$transcript" || status=$?
    echo "Transcript: $transcript (screenshots in $run/)"
    exit "$status"
    ;;
  *)
    usage
    exit 2
    ;;
esac
