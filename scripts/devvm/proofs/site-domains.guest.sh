#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh site-domains copies it in).
# Proves a site's other domains and redirects at the broker, with OpenLiteSpeed
# serving them: an alias serving the site, a path redirect answering 301 with
# the right Location, www redirecting to the bare domain with its path kept,
# a domain clash refused, config-injection attempts refused, a certificate
# from the VM's Pebble test CA naming every domain that points here (and not
# one whose DNS does not), the suspended rendering, and removing an alias.
# Prints PASS/FAIL per check.
#
# DNS: Pebble's own DNS answers 127.0.0.1 for every name, so Pebble validates
# any name. The panel's reachability probe uses this VM's resolver, so this
# script puts the names that "point here" in /etc/hosts (one marked line,
# removed at the end) and leaves nodns.<domain> out: that one stays http.
# shellcheck disable=SC2317 # the helpers are called through check
set -uo pipefail
# Byte order for every sort, as the broker sorts a certificate's names.
export LC_ALL=C

BIN=/opt/sifruno-proof
SOCKET=/run/sifruno-broker/control.sock
STATE=/var/lib/sifruno-broker
LSWS=/usr/local/lsws
ACME_DIRECTORY=https://127.0.0.1:14000/dir
PEBBLE_API_CA=/etc/pebble/api-ca.pem
ACME_CHALLENGES=/var/lib/sifruno-acme
RUNID="$(date +%s)"
RUNID="${RUNID: -5}"
SITE_USER="dom${RUNID}"
DOMAIN="${SITE_USER}.proof.test"
WWW="www.${DOMAIN}"
SHOP="shop.${DOMAIN}"
NODNS="nodns.${DOMAIN}"
OTHER="alias${RUNID}.proof.test"
TWO_USER="two${RUNID}"
TWO_DOMAIN="${TWO_USER}.proof.test"
WORK="/var/lib/sifpanel/site-domains-${RUNID}"
HOSTS_MARK="# sifruno site-domains proof ${RUNID}"
PROOF_TEXT="site-domains proof ${RUNID}"
fails=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
drive() { runuser -u sifpanel -- "$BIN/brokerdrive" --socket "$SOCKET" "$@"; }
# A change answers either the account or {"account": ...}.
revision() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('account', d)['revision'])"; }
answer() { # answer HOST PATH: the status and Location of one plain http request
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $1" "http://127.0.0.1$2"
}
serves() { # serves HOST: the site's own page over http
  curl -s -H "Host: $1" http://127.0.0.1/ | grep -q "$PROOF_TEXT"
}
wait_serves() { local _; for _ in $(seq 1 90); do serves "$1" && return 0; sleep 2; done; return 1; }
wait_answer() { local _; for _ in $(seq 1 90); do [ "$(answer "$1" "$2")" = "$3" ] && return 0; sleep 2; done; return 1; }
# domains_file NAME JSON: a domains input file sifpanel can read.
domains_file() { printf '%s\n' "$2" > "$WORK/$1.json"; chown sifpanel:sifpanel "$WORK/$1.json"; echo "$WORK/$1.json"; }
listed() { # listed ID PYTHON-CONDITION-ON-a
  drive list | python3 -c "import json,sys; a=[x for x in json.load(sys.stdin) if x['id']=='$1']; sys.exit(0 if a and ($2) else 1)"
}
# sans HOST: the DNS names of the certificate OpenLiteSpeed serves for HOST, sorted.
sans() {
  openssl s_client -connect 127.0.0.1:443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null |
    tail -n +2 | tr ',' '\n' | sed 's/^ *DNS://' | sort | paste -sd ' '
}
cleanup() {
  sed -i "/$HOSTS_MARK\$/d" /etc/hosts
}
trap cleanup EXIT

echo "# A site's other domains and redirects, served by OpenLiteSpeed, with a certificate from Pebble"
echo "# $(date -u +%FT%TZ)  $(rpm -q openlitespeed lsphp83 | paste -sd ' ')  SELinux $(getenforce)"
echo "# site user $SITE_USER, domain $DOMAIN, aliases $WWW $SHOP $OTHER $NODNS"

echo
echo "## 1. The broker runs with the web operation on, and Pebble is fresh"
ols_user="$(awk '$1=="user"{print $2; exit}' "$LSWS/conf/httpd_config.conf")"
ols_user="${ols_user:-nobody}"
systemctl stop sifruno-broker-proof 2>/dev/null
systemctl reset-failed sifruno-broker-proof 2>/dev/null
systemd-run --quiet --unit sifruno-broker-proof --collect \
  "$BIN/hostbroker" --state "$STATE" --socket "$SOCKET" --homes /home --controller-uid "$(id -u sifpanel)" --web-user "$ols_user"
for _ in $(seq 1 60); do [ -S "$SOCKET" ] && break; sleep 1; done
check "the broker started with --web-user $ols_user" test -S "$SOCKET"
systemctl restart pebble-challtestsrv pebble
for _ in $(seq 1 60); do curl -fs -o /dev/null --cacert "$PEBBLE_API_CA" "$ACME_DIRECTORY" && break; sleep 1; done
check "Pebble serves its ACME directory" curl -fs -o /dev/null --cacert "$PEBBLE_API_CA" "$ACME_DIRECTORY"
check "the ACME challenge folder is sifpanel's, mode 0755" test "$(stat -c '%U %a' "$ACME_CHALLENGES" 2>/dev/null)" = "sifpanel 755"
install -d -o sifpanel -g sifpanel -m 0700 "$WORK"
curl -fsS --cacert "$PEBBLE_API_CA" -o "$WORK/pebble-root.pem" https://127.0.0.1:15000/roots/0
check "Pebble's root for this run is saved" openssl x509 -in "$WORK/pebble-root.pem" -noout
printf '127.0.0.1 %s %s %s %s %s %s\n' "$DOMAIN" "$WWW" "$SHOP" "$OTHER" "$TWO_DOMAIN" "$HOSTS_MARK" >> /etc/hosts
check "the names that point here resolve to this VM, $NODNS does not" bash -c "getent hosts $SHOP >/dev/null && ! getent hosts $NODNS"

echo
echo "## 2. A live site"
created="$(drive create --username "$SITE_USER" --domain "$DOMAIN" --reason 'Site domains proof')" || fail "the broker creates the account"
id="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
rev="$(printf '%s' "$created" | revision)"
runuser -u "$SITE_USER" -- sh -c "printf '%s\n' '<!doctype html><title>proof</title><p>$PROOF_TEXT</p>' > /home/$SITE_USER/public_html/index.html"
live="$(drive web --id "$id" --revision "$rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the site goes live"
rev="$(printf '%s' "$live" | revision)"
check "the site serves on $DOMAIN" wait_serves "$DOMAIN"
vhost="$LSWS/conf/vhosts/sifruno-u${id:0:31}/vhconf.conf"

echo
echo "## 3. Other domains and redirects"
set_json="{\"aliases\":[\"$WWW\",\"$SHOP\",\"$OTHER\",\"$NODNS\"],\"redirects\":[{\"path\":\"/old-page\",\"target\":\"https://$DOMAIN/new-page\",\"status\":301},{\"domain\":\"$WWW\",\"target\":\"https://$DOMAIN\",\"status\":301}]}"
changed="$(drive domains --id "$id" --revision "$rev" --input-file "$(domains_file set "$set_json")" --reason 'Domains and redirects')" || fail "the broker records the domains and redirects"
rev="$(printf '%s' "$changed" | revision)"
echo "  listener map: $(grep "map .*sifruno-u${id:0:31}" "$LSWS/conf/sifruno.conf" | head -1 | sed 's/^ *//')"
echo "  vhost rules:"
sed -n '/rules *<<<END_rules/,/END_rules$/p' "$vhost" | grep -E 'RewriteCond|R=30' | sed 's/^/    /'
check "the alias $SHOP serves the site" wait_serves "$SHOP"
check "another registered domain, $OTHER, serves the site" wait_serves "$OTHER"
got="$(answer "$DOMAIN" /old-page)"
echo "  $DOMAIN/old-page: $got"
check "a path redirect answers 301 with Location https://$DOMAIN/new-page" test "$got" = "301 https://$DOMAIN/new-page"
check "it matches with a trailing slash too" test "$(answer "$SHOP" /old-page/)" = "301 https://$DOMAIN/new-page"
got="$(answer "$WWW" '/some/path?q=1')"
echo "  $WWW/some/path?q=1: $got"
check "www redirects to the bare domain with its path and query" test "$got" = "301 https://$DOMAIN/some/path?q=1"
token="proof-${RUNID}"
runuser -u sifpanel -- sh -c "printf 'challenge %s\n' $RUNID > $ACME_CHALLENGES/$token && chmod 0644 $ACME_CHALLENGES/$token"
check "the ACME challenge path on www is not redirected" bash -c "curl -s -H 'Host: $WWW' http://127.0.0.1/.well-known/acme-challenge/$token | grep -q 'challenge $RUNID'"
rm -f "$ACME_CHALLENGES/$token"
check "the tenant's .htaccess holds none of it" bash -c "! grep -qs 'RewriteRule' /home/$SITE_USER/public_html/.htaccess"
check "the account list shows 4 aliases and 2 redirects" listed "$id" "a[0].get('site_domains', {}).get('redirects') == 2 and len(a[0]['site_domains']['aliases']) == 4"

echo
echo "## 4. A domain belongs to one account only"
two="$(drive create --username "$TWO_USER" --domain "$TWO_DOMAIN" --reason 'Second site')" || fail "the broker creates a second account"
two_id="$(printf '%s' "$two" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
two_rev="$(printf '%s' "$two" | revision)"
two_live="$(drive web --id "$two_id" --revision "$two_rev" --php 8.3 --quota-mib 200 --reason 'Go live')" || fail "the second site goes live"
two_rev="$(printf '%s' "$two_live" | revision)"
for taken in "$SHOP" "$DOMAIN" "www.$SHOP"; do
  out="$(drive domains --id "$two_id" --revision "$two_rev" --input-file "$(domains_file taken "{\"aliases\":[\"$taken\"],\"redirects\":[]}")" --reason 'Take a domain' 2>&1)"
  echo "  adding $taken to $TWO_DOMAIN: $out"
  check "$taken is refused for the second account" grep -q 'domain belongs to another account' <<<"$out"
done
out="$(drive create --username "three${RUNID}" --domain "$OTHER" --reason 'Third site' 2>&1)"
check "a new account cannot take the alias $OTHER" grep -q 'conflict' <<<"$out"
check "$SHOP still serves the first site" serves "$SHOP"

echo
echo "## 5. Config injection is refused, and nothing changes"
before="$(sha256sum "$vhost" "$LSWS/conf/sifruno.conf")"
for bad in \
  "{\"path\":\"/a\",\"target\":\"https://$DOMAIN/x [R=302,L]\\nRewriteRule .* /etc/passwd\",\"status\":301}" \
  "{\"path\":\"/a\",\"target\":\"https://$DOMAIN/\\n  END_rules\\n}\\nvirtualhost evil {\",\"status\":301}" \
  "{\"path\":\"/a\",\"target\":\"https://$DOMAIN/\$1\",\"status\":301}" \
  "{\"path\":\"/a\",\"target\":\"https://$DOMAIN/%{HTTP_COOKIE}\",\"status\":301}" \
  "{\"path\":\"/a.*\",\"target\":\"https://$DOMAIN/\",\"status\":301}" \
  "{\"path\":\"/.well-known/acme-challenge/x\",\"target\":\"https://$DOMAIN/\",\"status\":301}" \
  "{\"domain\":\"$WWW\",\"target\":\"https://$DOMAIN/\$1\",\"status\":301}" \
  "{\"path\":\"/a\",\"target\":\"https://$DOMAIN/\",\"status\":301,\"flags\":\"L\"}"; do
  out="$(drive domains --id "$id" --revision "$rev" --input-file "$(domains_file bad "{\"aliases\":[\"$WWW\"],\"redirects\":[$bad]}")" --reason 'Injection attempt' 2>&1)"
  check "refused: $bad" grep -Eq 'invalid|read the domains file' <<<"$out"
done
check "the vhost and the server fragment are unchanged" test "$(sha256sum "$vhost" "$LSWS/conf/sifruno.conf")" = "$before"
check "the account's revision did not move" listed "$id" "a[0]['revision'] == $rev"

echo
echo "## 6. One certificate from Pebble for every domain that points here"
out="$(drive secure --id "$id" --acme-directory "$ACME_DIRECTORY" --acme-ca-file "$PEBBLE_API_CA" --acme-state "$WORK/acme" --acme-email admin@proof.test 2>&1)" || fail "the certificate is asked for and installed"
waiting="$(python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["waiting"]))' <<<"$out" 2>/dev/null)"
names="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["account"]["certificate"]["names"])' <<<"$out" 2>/dev/null)"
rev="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["account"]["revision"])' <<<"$out" 2>/dev/null || echo "$rev")"
echo "  waiting for DNS: ${waiting:-none}; the broker lists the certificate's names: ${names:-none}"
want="$(printf '%s\n' "$DOMAIN" "$WWW" "$SHOP" "$OTHER" | sort | paste -sd ' ')"
check "$NODNS was left out, waiting for its DNS" test "$waiting" = "$NODNS"
check "the broker records the names" test "$(tr ',' ' ' <<<"$names")" = "$want"
tls="/etc/sifruno/tls/u${id:0:31}"
check "the installed certificate names exactly the domains that point here" test "$(openssl x509 -in "$tls/cert.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' | sed 's/^ *DNS://' | sort | paste -sd ' ')" = "$want"
for host in "$DOMAIN" "$WWW" "$SHOP" "$OTHER"; do
  served="$(sans "$host")"
  echo "  served for $host: $served"
  check "OpenLiteSpeed serves it for $host" test "$served" = "$want"
done
check "https on $SHOP serves the site, trusting only Pebble's root" bash -c "curl -s --resolve $SHOP:443:127.0.0.1 --cacert $WORK/pebble-root.pem https://$SHOP/ | grep -q '$PROOF_TEXT'"
check "https on $OTHER serves the site" bash -c "curl -s --resolve $OTHER:443:127.0.0.1 --cacert $WORK/pebble-root.pem https://$OTHER/ | grep -q '$PROOF_TEXT'"
served="$(sans "$NODNS")"
fallback="the listener certificate, which names no site"
echo "  served for $NODNS: ${served:-$fallback}"
named=no
grep -qw "$NODNS" <<<"$served" && named=yes
check "no certificate naming $NODNS is served (it is http only)" test "$named" = no
check "https for $NODNS does not verify against Pebble's root" bash -c "! curl -s --resolve $NODNS:443:127.0.0.1 --cacert $WORK/pebble-root.pem https://$NODNS/ >/dev/null"
check "$NODNS still serves the site over http" serves "$NODNS"

echo
echo "## 7. A suspended site serves nothing and redirects nothing"
suspended="$(drive state --id "$id" --revision "$rev" --state suspended --reason 'Unpaid invoice')" || fail "the broker suspends the account"
rev="$(printf '%s' "$suspended" | revision)"
check "the alias $SHOP answers 403" wait_answer "$SHOP" / "403 "
check "the path redirect answers 403, not 301" test "$(answer "$DOMAIN" /old-page)" = "403 "
check "www answers 403, not a redirect" test "$(answer "$WWW" /)" = "403 "
check "the suspended vhost has no redirect rule" bash -c "! grep -q 'R=301' $vhost"
resumed="$(drive state --id "$id" --revision "$rev" --state active --reason 'Paid')" || fail "the broker resumes the account"
rev="$(printf '%s' "$resumed" | revision)"
check "after the resume, $SHOP serves the site again" wait_serves "$SHOP"
check "and the redirect answers again" wait_answer "$DOMAIN" /old-page "301 https://$DOMAIN/new-page"

echo
echo "## 8. Removing an alias takes it out, and the next certificate drops it"
smaller="{\"aliases\":[\"$WWW\",\"$OTHER\",\"$NODNS\"],\"redirects\":[{\"path\":\"/old-page\",\"target\":\"https://$DOMAIN/new-page\",\"status\":301},{\"domain\":\"$WWW\",\"target\":\"https://$DOMAIN\",\"status\":301}]}"
changed="$(drive domains --id "$id" --revision "$rev" --input-file "$(domains_file smaller "$smaller")" --reason 'Remove the shop domain')" || fail "the broker removes the alias"
rev="$(printf '%s' "$changed" | revision)"
check "$SHOP no longer serves the site" bash -c "! curl -s -H 'Host: $SHOP' http://127.0.0.1/ | grep -q '$PROOF_TEXT'"
check "the HTTPS listener no longer maps $SHOP" bash -c "! sed -n '/listener sifruno-https/,/^}/p' $LSWS/conf/sifruno.conf | grep -q ' $SHOP'"
out="$(drive secure --id "$id" --acme-directory "$ACME_DIRECTORY" --acme-ca-file "$PEBBLE_API_CA" --acme-state "$WORK/acme" --acme-email admin@proof.test 2>&1)" || fail "the certificate is renewed"
rev="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["account"]["revision"])' <<<"$out" 2>/dev/null || echo "$rev")"
want="$(printf '%s\n' "$DOMAIN" "$WWW" "$OTHER" | sort | paste -sd ' ')"
check "the renewed certificate names $DOMAIN, $WWW and $OTHER only" test "$(sans "$DOMAIN")" = "$want"

echo
echo "## 9. Delete"
drive delete --id "$id" --revision "$rev" --reason 'Remove the proof site' >/dev/null || fail "the broker deletes the account"
two_rev="$(drive list | python3 -c "import json,sys; print([x for x in json.load(sys.stdin) if x['id']=='$two_id'][0]['revision'])")"
drive delete --id "$two_id" --revision "$two_rev" --reason 'Remove the second proof site' >/dev/null || fail "the broker deletes the second account"
check "no alias of the deleted site is mapped" bash -c "! grep -qE '$OTHER|$NODNS' $LSWS/conf/sifruno.conf"
check "OpenLiteSpeed is still running" systemctl is-active --quiet lsws
rm -rf -- "$WORK"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
