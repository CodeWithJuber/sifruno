#!/usr/bin/env bash
# Proof 3 rehearsal (Phase 0 item 9 of the product plan), guest side. Runs
# as root in the dev VM after provision.sh, with the installed Sifruno units
# off: it starts its own broker on their socket, as the other broker proofs do.
#
# The real proof copies a HostLelo cPanel site over root SSH; that needs the
# owner's server. This rehearsal uses the same tools on a stand-in: an
# Apache site with a password folder and a denied file plays the old cPanel
# site, and two copies play the new server:
#   - a website the broker makes on OpenLiteSpeed (the Native tier), which
#     ignores .htaccess access rules
#   - a second Apache vhost (the Compat tier), which honours them
# It shows that the pre-flight scan sends this site to Compat, that the
# scan's access rules become verify probes, that the gate stays closed
# against the Native copy because the password folder opens there, and that
# it opens against the Compat copy.
#
# Every check prints PASS or FAIL. The exit status is the number of FAILs.
set -uo pipefail

BIN=/opt/sifruno-proof
RUN="/srv/proof3-$(date +%s)"
OLD="$RUN/old"
COMPAT="$RUN/compat"
WORK="$RUN/work"
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
UNIT=sifruno-broker-proof
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
NATIVE_USER="pv${RUNID}"
NATIVE_DOMAIN="${NATIVE_USER}.proof.test"
NATIVE_DOCROOT="/home/$NATIVE_USER/public_html"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
status_of() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
native_status() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $NATIVE_DOMAIN" "http://127.0.0.1$1"; }
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
# A change answers either the account or {"account": ...}.
revision() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('account', d)['revision'])"; }

echo "# Proof 3 rehearsal: verify catches a protected folder that opens on the new server"
echo "# $(date -u +%FT%TZ)  $(rpm -q httpd openlitespeed | paste -sd ' ')"

echo
echo "## The old site (Apache, as on cPanel)"
mkdir -p "$OLD/private" "$OLD/blog" "$WORK"
cat > "$OLD/index.html" <<'HTML'
<!doctype html><title>Proof shop</title>
<a href="/about.html">About</a> <a href="/blog/">Blog</a> <a href="/contact.html">Contact</a>
HTML
printf '<!doctype html><title>About us</title><p>About</p>\n' > "$OLD/about.html"
printf '<!doctype html><title>Contact</title><p>Mail us</p>\n' > "$OLD/contact.html"
printf '<!doctype html><title>Blog</title><a href="/blog/first.html">First</a>\n' > "$OLD/blog/index.html"
printf '<!doctype html><title>First post</title><p>Hello</p>\n' > "$OLD/blog/first.html"
printf '<!doctype html><title>Staff only</title><p>Payroll</p>\n' > "$OLD/private/index.html"
printf '%s\n' "<?php define('DB_NAME', 'proof_backup_copy');" > "$OLD/wp-config.php.bak"
htpasswd -bcB "$RUN/.htpasswd" staff proof-only-password >/dev/null 2>&1
chmod 0644 "$RUN/.htpasswd"
cat > "$OLD/private/.htaccess" <<HT
AuthType Basic
AuthName "Staff"
AuthUserFile $RUN/.htpasswd
Require valid-user
HT
cat > "$OLD/.htaccess" <<'HT'
<Files "wp-config.php.bak">
    Require all denied
</Files>
HT
cp -a "$OLD" "$COMPAT"
chcon -R -t httpd_sys_content_t "$RUN"
cat > /etc/httpd/conf.d/proof3.conf <<CONF
Listen 127.0.0.1:8081
Listen 127.0.0.1:8082
<VirtualHost 127.0.0.1:8081>
    DocumentRoot $OLD
    <Directory $OLD>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
<VirtualHost 127.0.0.1:8082>
    DocumentRoot $COMPAT
    <Directory $COMPAT>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
CONF
semanage port -a -t http_port_t -p tcp 8081 2>/dev/null || true
semanage port -a -t http_port_t -p tcp 8082 2>/dev/null || true
if apachectl configtest >/dev/null 2>&1; then
  systemctl restart httpd
else
  fail "Apache accepts the proof vhosts"
fi
check "old site answers 200 on /" curl -fsS -o /dev/null http://127.0.0.1:8081/
check "old site closes /private/ with 401" test "$(status_of http://127.0.0.1:8081/private/)" = 401
check "old site closes wp-config.php.bak with 403" test "$(status_of http://127.0.0.1:8081/wp-config.php.bak)" = 403

echo
echo "## Pre-flight: scan the old site's .htaccess files"
"$BIN/panelctl" htaccess scan --root "$OLD" --layout single | tee "$WORK/scan.txt" | sed -n '1,12p'
"$BIN/panelctl" htaccess scan --root "$OLD" --layout single --json --details > "$WORK/scan.json"
verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sites"][0]["verdict"])' "$WORK/scan.json")"
echo "site verdict: $verdict"
check "the scan sends this site to the Compat tier" test "$verdict" = compat
# The scan's access rules become verify probes. Only rules the scan could
# promise a status for (expect_status 401 or 403) become probes.
python3 - "$WORK/scan.json" "$WORK/probes.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
probes = []
for site in report.get("sites", []):
    for f in site.get("files", []):
        for rule in f.get("access_rules") or []:
            status = rule.get("expect_status", 0)
            if status not in (401, 403) or rule.get("url_regex"):
                continue  # a Redirect pattern names no single URL to probe
            kind = "auth" if status == 401 else "deny"
            path = rule.get("path") or rule.get("url_path") or "/"
            name = rule.get("files", "")
            if rule.get("files_regex"):
                continue  # a pattern names no single URL to probe
            probes.append({"path": path + name if name else path, "kind": kind})
json.dump(probes, open(sys.argv[2], "w"), indent=1)
print("probes:", json.dumps(probes))
PY
check "probes cover the password folder" grep -q '"/private/"' "$WORK/probes.json"
# The scan promises a status only for whole-directory rules. A <Files> rule is
# reported without one, so the operator adds its probe, as an admin would.
check "the scan reports the <Files> deny rule for wp-config.php.bak" grep -q '"files": *"wp-config.php.bak"' "$WORK/scan.json"
python3 - "$WORK/probes.json" <<'PY'
import json, sys
probes = json.load(open(sys.argv[1]))
probes.append({"path": "/wp-config.php.bak", "kind": "deny"})
json.dump(probes, open(sys.argv[1], "w"), indent=1)
PY
check "probes cover the denied file" grep -q 'wp-config.php.bak' "$WORK/probes.json"

echo
echo "## Native tier: the same files on a website the broker makes"
# The Native tier is a website as the broker makes it: an account, and an
# OpenLiteSpeed vhost for its domain on port 80. The proof makes one with
# its own broker, copies the old site's files in as the account's user, and
# compares through 127.0.0.1:80 with the site's Host header. The account is
# deleted at the end. Nothing here needs OpenLiteSpeed's sample site, which
# the installer removes.
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
systemctl stop "$UNIT" 2>/dev/null
systemctl reset-failed "$UNIT" 2>/dev/null
systemd-run --quiet --unit "$UNIT" --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "${ols_user:-nobody}"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker runs with the web operation on" test -S "$SOCKET"
native_id=""
native_rev=""
# shellcheck disable=SC2317 # called by the EXIT trap below
remove_native() {
  if [ -n "$native_id" ] && ! drive delete --id "$native_id" --revision "$native_rev" --reason 'Remove the Proof 3 Native copy' >/dev/null; then
    echo "FAIL  the broker deletes the account $NATIVE_USER"
  fi
  systemctl stop "$UNIT" 2>/dev/null
}
trap remove_native EXIT
if created="$(drive create --username "$NATIVE_USER" --domain "$NATIVE_DOMAIN" --reason 'Proof 3 Native copy')"; then
  native_id="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  native_rev="$(printf '%s' "$created" | revision)"
  pass "the broker makes the account $NATIVE_USER for $NATIVE_DOMAIN"
else
  fail "the broker makes the account $NATIVE_USER for $NATIVE_DOMAIN"
fi
check "the account's user copies the old site's files into its public_html" runuser -u "$NATIVE_USER" -- cp -R "$OLD/." "$NATIVE_DOCROOT/"
if live="$(drive web --id "$native_id" --revision "$native_rev" --php 8.3 --quota-mib 200 --reason 'Proof 3 Native copy')"; then
  native_rev="$(printf '%s' "$live" | revision)"
  pass "the broker puts $NATIVE_DOMAIN live on OpenLiteSpeed"
else
  fail "the broker puts $NATIVE_DOMAIN live on OpenLiteSpeed"
fi
served=no
for _ in $(seq 1 60); do
  if curl -fsS -H "Host: $NATIVE_DOMAIN" http://127.0.0.1/ 2>/dev/null | grep -q 'Proof shop'; then
    served=yes
    break
  fi
  sleep 2
done
check "OpenLiteSpeed serves the copy for $NATIVE_DOMAIN on 127.0.0.1:80" test "$served" = yes
echo "OpenLiteSpeed answers /private/ with $(native_status /private/) and wp-config.php.bak with $(native_status /wp-config.php.bak)"
rc=0
"$BIN/panelctl" migrate verify --old http://127.0.0.1:8081 --new "http://$NATIVE_DOMAIN" --new-connect 127.0.0.1:80 --probes-file "$WORK/probes.json" --out "$WORK/native-report.json" > "$WORK/native-report.txt" 2>&1 || rc=$?
sed -n '1,14p' "$WORK/native-report.txt"
check "verify exits 3: the gate is closed against the Native copy" test "$rc" -eq 3
check "the report names the opened password folder" grep -q 'new_open' "$WORK/native-report.txt"
check "the JSON report says cutover_allowed false" python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["cutover_allowed"] is False else 1)' "$WORK/native-report.json"

echo
echo "## Compat tier: the same files on Apache"
rc=0
"$BIN/panelctl" migrate verify --old http://127.0.0.1:8081 --new http://127.0.0.1:8082 --probes-file "$WORK/probes.json" --out "$WORK/compat-report.json" > "$WORK/compat-report.txt" 2>&1 || rc=$?
sed -n '1,8p' "$WORK/compat-report.txt"
check "verify exits 0: the gate opens against the Compat copy" test "$rc" -eq 0
check "every probe passed" python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["counts"]; sys.exit(0 if c["probes_fail"]==0 and c["probes_pass"]>=2 else 1)' "$WORK/compat-report.json"
check "pages were compared" python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["counts"]; sys.exit(0 if c["pages_pass"]>=5 and c["pages_fail"]==0 else 1)' "$WORK/compat-report.json"

echo
echo "## A broken copy is caught too"
mv "$COMPAT/blog/first.html" "$WORK/first.html.moved"
rc=0
"$BIN/panelctl" migrate verify --old http://127.0.0.1:8081 --new http://127.0.0.1:8082 --probes-file "$WORK/probes.json" > "$WORK/broken-report.txt" 2>&1 || rc=$?
grep -m1 'first.html' "$WORK/broken-report.txt"
check "a page missing on the copy closes the gate" test "$rc" -eq 3

echo
echo "Reports: $WORK"
echo "# Result: $fails failed"
exit "$fails"
