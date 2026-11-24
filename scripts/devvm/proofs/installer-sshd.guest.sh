#!/usr/bin/env bash
# Runs inside the dev VM as root (proof.sh installer-sshd copies it in).
# Checks the installer's sshd pre-checks, which decide whether turning SSH
# passwords off would lock everyone out. It loads install.sh's functions
# only and works on candidate copies of the configuration and throwaway
# users; the live sshd configuration is not changed.
# Each check is a string t evaluates when it runs, so variables in single
# quotes expand then, and are read only there.
# shellcheck disable=SC2016,SC2034
set -uo pipefail

INSTALL_SH=/opt/sifruno-proof/install.sh
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
t() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }

# shellcheck disable=SC1090
SIFRUNO_INSTALL_FUNCTIONS_ONLY=1 source "$INSTALL_SH"
set +e +u
# The proof runs over SSH; each case below names the connection it judges.
real_connection="${SSH_CONNECTION:-}"

echo "# Installer sshd pre-checks: who can still sign in once passwords are off"
echo "# $(date -u +%FT%TZ)  $(rpm -q openssh-server)  SELinux $(getenforce)"
echo "# nsswitch passwd:$(awk '$1=="passwd:"{$1="";print}' /etc/nsswitch.conf)"
live_before="$(sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)"

echo
echo "## 1. The candidate copy with the policy in place"
cand="$(sshd_candidate)"
t "the copy is built in a private temporary folder" '[ -d "$cand" ] && [ "$(stat -c %a "$cand")" = 700 ]'
t "it holds the policy as 40-sifruno.conf" 'cmp -s "$cand/sshd_config.d/40-sifruno.conf" <(sshd_policy)'
t "it includes its own drop-in folder instead of /etc's" 'grep -qxF "Include $cand/sshd_config.d/*.conf" "$cand/sshd_config"'
t "sshd accepts the whole copied configuration" 'sshd -t -f "$cand/sshd_config"'
eff="$(sshd -T -f "$cand/sshd_config" -C user=nosuchuser9,host=localhost,addr=127.0.0.1)"
t "other users get ForceCommand internal-sftp" '[ "$(sshd_value forcecommand <<<"$eff")" = internal-sftp ]'
t "and PasswordAuthentication no" '[ "$(sshd_value passwordauthentication <<<"$eff")" = no ]'
t "root with a valid key is found as the admin" '[ "$(ssh_admin "$cand/sshd_config")" = root ]'

echo
echo "## 2. Root does not count when another file stands in the way"
in_the_way() { # in_the_way WHAT CONFIG-LINES
  printf '%b\n' "$2" > "$cand/sshd_config.d/10-proof.conf"
  t "$1: root does not count" '! ssh_admin_ok "$cand/sshd_config" root'
  rm -f "$cand/sshd_config.d/10-proof.conf"
}
in_the_way "PermitRootLogin no in another drop-in" 'PermitRootLogin no'
in_the_way "AllowUsers without root" 'AllowUsers someoneelse'
in_the_way "AllowGroups set" 'AllowGroups admins'
in_the_way "DenyUsers set" 'DenyUsers nobody'
in_the_way "AuthenticationMethods needing a password too" 'AuthenticationMethods publickey,password'
in_the_way "a ForceCommand for root" 'Match User root\n    ForceCommand /bin/false'
printf 'AllowUsers root someoneelse\n' > "$cand/sshd_config.d/10-proof.conf"
t "AllowUsers naming root: root counts" 'ssh_admin_ok "$cand/sshd_config" root'

echo
echo "## 3. Match rules on addresses are judged for the admin's own connection"
printf 'Match Address 192.0.2.0/24\n    PermitRootLogin no\n' > "$cand/sshd_config.d/10-proof.conf"
export SSH_CONNECTION="192.0.2.5 50000 10.0.2.15 22"
t "connected from 192.0.2.5, where root may not sign in: root does not count" '! ssh_admin_ok "$cand/sshd_config" root'
export SSH_CONNECTION="198.51.100.7 50000 10.0.2.15 22"
t "connected from 198.51.100.7: root counts" 'ssh_admin_ok "$cand/sshd_config" root'
unset SSH_CONNECTION
t "not over SSH, so the rule cannot be judged: root does not count" '! ssh_admin_ok "$cand/sshd_config" root'
rm -f "$cand/sshd_config.d/10-proof.conf"
t "not over SSH and no such rule: root counts" 'ssh_admin_ok "$cand/sshd_config" root'
export SSH_CONNECTION="192.0.2.5,addr=198.51.100.7 50000 10.0.2.15 22"
t "an SSH_CONNECTION that would add its own sshd -C fields is not used" '[ -z "$(ssh_connection_spec)" ]'
export SSH_CONNECTION="$real_connection"

echo
echo "## 4. A wheel member as the admin"
useradd -m -d /var/lib/proof-admin -G wheel -s /bin/bash proofadm
install -d -o proofadm -g proofadm -m 0700 /var/lib/proof-admin/.ssh
keys=/var/lib/proof-admin/.ssh/authorized_keys
printf '# a comment and no key\n' > "$keys"
chown proofadm:proofadm "$keys"
chmod 0600 "$keys"
t "a key file with only a comment: does not count" '! ssh_admin_ok "$cand/sshd_config" proofadm'
ssh-keygen -q -t ed25519 -N '' -C proof -f /root/proof-admin-key
cat /root/proof-admin-key.pub > "$keys"
t "a valid key: counts" 'ssh_admin_ok "$cand/sshd_config" proofadm'
chmod 0770 /var/lib/proof-admin/.ssh
t "a group-writable .ssh (StrictModes): does not count" '! ssh_admin_ok "$cand/sshd_config" proofadm'
chmod 0700 /var/lib/proof-admin/.ssh
chmod 0775 /var/lib/proof-admin
t "a group-writable home (StrictModes): does not count" '! ssh_admin_ok "$cand/sshd_config" proofadm'
chmod 0700 /var/lib/proof-admin
usermod -s /sbin/nologin proofadm
t "a nologin shell: does not count" '! ssh_admin_ok "$cand/sshd_config" proofadm'
usermod -s /bin/bash proofadm
t "found in the local files with getent -s files" 'getent -s files passwd proofadm'

echo
echo "## 5. Other local users who would lose their shell"
t "the wheel member is not listed" '[[ " $(other_login_users) " != *" proofadm "* ]]'
useradd -m -d /var/lib/proof-other -s /bin/bash proofoth
t "a user with a shell outside wheel and outside /home is listed" '[[ " $(other_login_users) " == *" proofoth "* ]]'
echo "  listed: $(other_login_users)"

userdel -r proofadm 2>/dev/null
userdel -r proofoth 2>/dev/null
rm -f /root/proof-admin-key /root/proof-admin-key.pub
rm -rf -- "$cand"

echo
echo "## 6. Nothing live changed"
t "the live sshd files are as they were" '[ "$(sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" = "$live_before" ]'
t "the live configuration still validates" 'sshd -t'

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit "$fails"
