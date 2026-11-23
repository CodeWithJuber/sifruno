#!/usr/bin/env bash
# Proof 3 rehearsal (docs/PRODUCT-PLAN.md, Phase 0 item 9), guest side. Runs
# as root in the dev VM after provision.sh.
#
# The real proof copies a HostLelo cPanel site over root SSH; that needs the
# owner's server. This rehearsal uses the same tools on a stand-in: an
# Apache site with a password folder and a denied file plays the old cPanel
# site, and two copies play the new server:
#   - OpenLiteSpeed (the Native tier), which ignores .htaccess access rules
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
OLS_DOCROOT=/usr/local/lsws/Example/html
WORK="$RUN/work"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
status_of() { curl -s -o /dev/null -w '%{http_code}' "$1"; }

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
echo "## Native tier: the same files on OpenLiteSpeed"
# OpenLiteSpeed's stock Example vhost answers on 8088. Its own pages are
# moved aside for the run and put back at the end: the vhost's /protected/
# context points into them, and without them openlitespeed -t reports an
# error that other proofs would trip over.
stock="$OLS_DOCROOT.stock-proof3"
if [ -d "$OLS_DOCROOT" ] && [ ! -e "$OLS_DOCROOT/.sifruno-proof3" ] && [ ! -e "$stock" ]; then
  mv "$OLS_DOCROOT" "$stock"
elif [ -e "$OLS_DOCROOT/.sifruno-proof3" ]; then
  mv "$OLS_DOCROOT" "$RUN/ols-copy-from-an-earlier-run"
fi
# shellcheck disable=SC2317 # called by the EXIT trap below
restore_stock() {
  if [ -d "$stock" ]; then
    [ -e "$OLS_DOCROOT/.sifruno-proof3" ] && mv "$OLS_DOCROOT" "$RUN/ols-copy"
    mv "$stock" "$OLS_DOCROOT"
    /usr/local/lsws/bin/lswsctrl restart >/dev/null 2>&1
  fi
}
trap restore_stock EXIT
mkdir -p "$OLS_DOCROOT"
cp -a "$OLD"/. "$OLS_DOCROOT"/
touch "$OLS_DOCROOT/.sifruno-proof3"
chown -R nobody:nobody "$OLS_DOCROOT"
restorecon -R "$OLS_DOCROOT" 2>/dev/null
/usr/local/lsws/bin/lswsctrl restart >/dev/null 2>&1
sleep 5
check "OpenLiteSpeed serves the copy on 8088" curl -fsS -o /dev/null http://127.0.0.1:8088/
echo "OpenLiteSpeed answers /private/ with $(status_of http://127.0.0.1:8088/private/) and wp-config.php.bak with $(status_of http://127.0.0.1:8088/wp-config.php.bak)"
rc=0
"$BIN/panelctl" migrate verify --old http://127.0.0.1:8081 --new http://127.0.0.1:8088 --probes-file "$WORK/probes.json" --out "$WORK/native-report.json" > "$WORK/native-report.txt" 2>&1 || rc=$?
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
