"""Synthetic, disposable AlmaLinux guest qualification; never a host installer."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

CONTROLLER_UID = 2000
CONTROLLER_GID = 2000
BASE = Path('/opt/sifruno-account-qualification')
STATE = Path('/home/sifruno-controller/private')
SOCKET = '/run/sifruno-accounts/broker.sock'
ORIGIN = 'http://127.0.0.1:18080'
LAST_COMMAND = None


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(args, ok=True, controller=False):
    global LAST_COMMAND
    LAST_COMMAND = {'executable': Path(args[0]).name, 'controller': controller}
    if 'accounts' in args:
        LAST_COMMAND['account_operation'] = args[args.index('accounts') + 1]
    if controller:
        args = ['/usr/bin/setpriv', '--reuid=2000', '--regid=2000', '--clear-groups', '--'] + args
    result = subprocess.run(args, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, cwd=str(BASE), capture_output=True, timeout=55)
    LAST_COMMAND['exit_code'] = result.returncode
    status = re.search(rb'\(HTTP ([0-9]{3})\)', result.stderr)
    if status:
        LAST_COMMAND['http_status'] = int(status.group(1))
    require(len(result.stdout) + len(result.stderr) <= 256 * 1024, 'Command output limit exceeded')
    require(result.returncode == 0 if ok else result.returncode == 1, 'Unexpected fixture command result')
    return result


def cli(*args, ok=True):
    result = command([str(BASE/'panelctl'), '--state', str(STATE), '--panel-url', ORIGIN, 'accounts', *args], ok=ok, controller=True)
    if not ok:
        return None
    value = json.loads(result.stdout)
    require('csrf_token' not in result.stdout.decode() and 'access_key' not in result.stdout.decode(), 'CLI returned session material')
    return value


def stop(child):
    if child is None or child.poll() is not None:
        return
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=8)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)
        raise RuntimeError('Owned process required forced shutdown')
    require(child.returncode == 0, 'Owned process did not shut down cleanly')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--disposable-alma-guest', action='store_true', required=True)
    p.add_argument('--report', required=True)
    p.add_argument('--qualification-files-only-nss', action='store_true')
    p.add_argument('--qualification-no-mail-spool-default', action='store_true')
    args = p.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Disposable Linux root required')
    admission = Path('/run/sifruno-qualification-admission')
    require(admission.is_file() and not admission.is_symlink() and admission.read_text() == 'trusted-disposable-alma9\n' and stat.S_IMODE(admission.stat().st_mode) == 0o600 and admission.stat().st_uid == 0, 'Explicit disposable guest admission missing')
    release = dict(line.strip().split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID') == '"almalinux"' or release.get('ID') == 'almalinux', 'AlmaLinux qualification only')
    require(release.get('VERSION_ID', '').strip('"').startswith('9.'), 'AlmaLinux 9 qualification only')
    require(BASE.is_dir() and not BASE.is_symlink(), 'Fixed guest payload missing')
    require(not STATE.exists() and not Path('/var/lib/sifruno-hostbroker').exists() and not Path('/home/sifruno-managed').exists(), 'Fresh disposable guest required')
    report_path = Path(args.report)
    require(report_path.is_absolute() and report_path.parent == BASE and not report_path.exists(), 'Exclusive fixture report required')
    checks = []
    broker = panel = None
    logs = []
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    nss_proof = None
    useradd_proof = None
    environment_proof = None
    try:
        package = command(['/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}\n', 'shadow-utils']).stdout.decode().strip()
        require(bool(re.fullmatch(r'shadow-utils-[a-zA-Z0-9_.+-]{1,100}', package)), 'Unexpected shadow package metadata')
        mounts = Path('/proc/mounts').read_text()
        require(len(mounts) <= 1024*1024, 'Bounded mount metadata required')
        root_filesystems = [row.split()[2] for row in mounts.splitlines() if len(row.split()) >= 3 and row.split()[1] == '/']
        environment_proof = {'kernel': os.uname().release, 'architecture': os.uname().machine, 'root_filesystems': root_filesystems, 'selinux_enforcing': Path('/sys/fs/selinux/enforce').read_text().strip() == '1', 'shadow_package': package}
        nss = Path('/etc/nsswitch.conf')
        original = nss.read_bytes()
        require(len(original) <= 1024 * 1024, 'Bounded guest NSS configuration required')
        original_lines = [line for line in original.decode().splitlines() if re.match(r'^\s*(passwd|group|shadow)\s*:', line)]
        if args.qualification_files_only_nss:
            replacement = re.sub(r'^\s*(passwd|group|shadow)\s*:.*$', lambda match: match.group(1) + ': files', original.decode(), flags=re.MULTILINE)
            for database in ['passwd', 'group', 'shadow']:
                if not re.search(r'^' + database + r': files$', replacement, re.MULTILINE):
                    replacement += '\n' + database + ': files\n'
            temporary = Path('/etc/.sifruno-qualified-nss')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(replacement.encode())
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o644)
            original_link = nss.is_symlink()
            os.replace(temporary, nss)
            nss_proof = {'guest_only_files_policy_declared': True, 'original_was_symlink': original_link, 'original_sha256': hashlib.sha256(original).hexdigest(), 'original_identity_policy': original_lines, 'effective_identity_policy': ['passwd: files', 'group: files', 'shadow: files'], 'stock_alma_nss_qualified': False}
        else:
            nss_proof = {'guest_only_files_policy_declared': False, 'effective_identity_policy': original_lines}
        if args.qualification_no_mail_spool_default:
            defaults = Path('/etc/default/useradd')
            original_defaults = defaults.read_bytes()
            require(len(original_defaults) <= 65536 and defaults.is_file() and not defaults.is_symlink(), 'Bounded regular guest useradd defaults required')
            replacement = re.sub(r'^\s*CREATE_MAIL_SPOOL\s*=.*$', 'CREATE_MAIL_SPOOL=no', original_defaults.decode(), flags=re.MULTILINE)
            if not re.search(r'^CREATE_MAIL_SPOOL=no$', replacement, re.MULTILINE):
                replacement += '\nCREATE_MAIL_SPOOL=no\n'
            temporary = Path('/etc/default/.sifruno-qualified-useradd')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(replacement.encode());output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(), 0o644)
            os.replace(temporary, defaults)
            useradd_proof = {'guest_only_no_mail_spool_policy_declared': True, 'original_sha256': hashlib.sha256(original_defaults).hexdigest(), 'effective_mail_spool': False, 'stock_useradd_policy_qualified': False}
        command(['/usr/sbin/useradd', '--uid', '2000', '--user-group', '--create-home', '--home-dir', '/home/sifruno-controller', '--shell', '/usr/sbin/nologin', 'sifrunocontrol'])
        require(os.stat('/home/sifruno-controller').st_uid == CONTROLLER_UID, 'Controller ownership mismatch')
        os.mkdir('/run/sifruno-accounts', 0o755)
        logs = [open(BASE/'broker.log', 'xb'), open(BASE/'panel.log', 'xb')]

        def start_broker():
            return subprocess.Popen([str(BASE/'hostbroker'), '--state', '/var/lib/sifruno-hostbroker', '--socket', SOCKET, '--homes', '/home/sifruno-managed', '--controller-uid', '2000'], cwd=str(BASE), env=env, stdout=logs[0], stderr=logs[0])

        broker = start_broker()
        deadline = time.monotonic() + 20
        while not Path(SOCKET).exists() and broker.poll() is None and time.monotonic() < deadline:
            time.sleep(.1)
        require(Path(SOCKET).exists() and broker.poll() is None, 'Broker startup failed')
        panel = subprocess.Popen(['/usr/bin/setpriv', '--reuid=2000', '--regid=2000', '--clear-groups', '--', str(BASE/'sifruno'), '--listen', '127.0.0.1:18080', '--sites-listen', '', '--state', str(STATE), '--ui', str(BASE/'ui'), '--accounts-socket', SOCKET], cwd=str(BASE), env=env, stdout=logs[1], stderr=logs[1])
        deadline = time.monotonic() + 25
        while not (STATE/'operator/access.key').exists() and panel.poll() is None and time.monotonic() < deadline:
            time.sleep(.1)
        require((STATE/'operator/access.key').exists() and panel.poll() is None, 'Unprivileged panel startup failed')
        # Key creation precedes the listener. Retry only this read-only probe;
        # account writes are never replayed after an unknown outcome.
        ready = False
        deadline = time.monotonic() + 20
        while panel.poll() is None and time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', 18080, timeout=1)
            try:
                connection.request('GET', '/api/v1/status')
                response = connection.getresponse()
                body = response.read(32769)
                ready = response.status == 200 and len(body) <= 32768 and json.loads(body).get('ready') is False
                if ready:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.1)
        require(ready, 'Read-only panel readiness deadline exceeded')
        cap = cli('capability')
        require(cap['available'] is True, 'Actual Linux broker not available')
        checks.append('nonroot_panel_to_root_broker_capability')
        require(cli('list')['items'] == [], 'Fresh account list not empty')
        account = cli('create', '--username', 'proofacct', '--domain', 'proof.example.test', '--reason', 'Disposable guest account creation')
        require(account['username'] == 'proofacct' and account['state'] == 'active' and account['revision'] == 1 and account['uid'] != CONTROLLER_UID, 'Created account DTO mismatch')
        passwd = command(['/usr/bin/getent', 'passwd', 'proofacct']).stdout.decode().strip().split(':')
        require(len(passwd) == 7 and int(passwd[2]) == account['uid'] and int(passwd[3]) == account['gid'] and passwd[5] == account['home'] and passwd[6] == '/usr/sbin/nologin', 'Actual OS identity mismatch')
        for field in ['home', 'public_html']:
            info = os.lstat(account[field])
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == account['uid'] and info.st_gid == account['gid'], 'Actual managed directory ownership mismatch')
        require(command(['/usr/bin/passwd', '--status', 'proofacct']).stdout.decode().split()[1] == 'LK', 'Created password not locked')
        checks.append('real_shadow_utils_identity_home_public_html_nologin_locked_password')
        groups = command(['/usr/bin/getent', 'group']).stdout.decode().splitlines()
        require(not any('proofacct' in row.split(':')[3].split(',') for row in groups if len(row.split(':')) == 4), 'Unexpected supplementary group membership')
        require(not Path('/var/spool/mail/proofacct').exists(), 'Unexpected mail spool created')
        checks.append('no_supplementary_groups_or_native_mail_spool')
        cli('create', '--username', 'proofacct', '--domain', 'other.example.test', '--reason', 'Duplicate fixture', ok=False)
        cli('create', '--username', 'anotheracct', '--domain', 'proof.example.test', '--reason', 'Duplicate domain fixture', ok=False)
        require(len(cli('list')['items']) == 1, 'Duplicate operation created account')
        checks.append('duplicate_username_domain_refused')
        account = cli('state', '--id', account['id'], '--state', 'suspended', '--revision', '1', '--reason', 'Disposable new-access restriction')
        require(account['state'] == 'suspended' and account['revision'] == 2, 'Suspension metadata mismatch')
        expiry = command(['/usr/bin/chage', '--list', 'proofacct']).stdout.decode()
        require('Jan 02, 1970' in expiry, 'Actual suspension expiry missing')
        checks.append('actual_pam_account_expiry_suspension_only')
        cli('state', '--id', account['id'], '--state', 'active', '--revision', '1', '--reason', 'Stale revision fixture', ok=False)
        account = cli('state', '--id', account['id'], '--state', 'active', '--revision', '2', '--reason', 'Disposable access restriction removal')
        require(account['state'] == 'active' and account['revision'] == 3, 'Resume metadata mismatch')
        expiry_lines = command(['/usr/bin/chage', '--list', 'proofacct']).stdout.decode().splitlines()
        require(any(line.startswith('Account expires') and line.split(':', 1)[1].strip() == 'never' for line in expiry_lines), 'Actual account expiry not cleared')
        require(command(['/usr/bin/passwd', '--status', 'proofacct']).stdout.decode().split()[1] == 'LK', 'Resume unlocked password')
        checks.append('revision_conflict_and_resume_preserve_locked_nologin')
        stop(broker);broker = None
        require(not Path(SOCKET).exists(), 'Owned socket retained after clean broker shutdown')
        broker = start_broker()
        deadline = time.monotonic() + 20
        while not Path(SOCKET).exists() and broker.poll() is None and time.monotonic() < deadline:
            time.sleep(.1)
        require(Path(SOCKET).exists() and broker.poll() is None, 'Broker restart failed')
        rows = cli('list')['items']
        require(len(rows) == 1 and rows[0]['id'] == account['id'] and rows[0]['revision'] == 3 and rows[0]['state'] == 'active', 'Persisted account changed after broker restart')
        checks.append('broker_restart_persists_actual_account')
        command(['/usr/sbin/usermod', '--shell', '/bin/bash', 'proofacct'])
        rows = cli('list')['items']
        require(rows[0]['state'] == 'recovery_required', 'External identity conflict hidden')
        require(cli('capability')['available'] is False, 'Recovery gate did not close')
        cli('create', '--username', 'secondacct', '--domain', 'second.example.test', '--reason', 'Closed recovery gate fixture', ok=False)
        checks.append('external_identity_conflict_visible_and_mutations_blocked')
        for name in ['operator/access.key', 'sites/sites.db']:
            item = STATE/name
            if item.exists():
                require(os.stat(item).st_uid == CONTROLLER_UID and stat.S_IMODE(os.stat(item).st_mode) == 0o600, 'Private controller permissions mismatch')
        require(stat.S_IMODE(os.stat('/var/lib/sifruno-hostbroker').st_mode) == 0o700, 'Privileged state permissions mismatch')
        checks.append('separate_root_private_and_controller_private_permissions')
        stop(panel);panel = None;stop(broker);broker = None
        checks.append('owned_panel_and_broker_sigterm_cleanup')
        report = {'passed': True, 'checks': checks, 'os_release': release, 'nss_policy': nss_proof, 'controller_uid': CONTROLLER_UID, 'managed_uid': account['uid'], 'managed_gid': account['gid'], 'managed_accounts': 1, 'root_http_controller': False, 'reference_observed': False, 'cpanel_compatibility_certified': False, 'full_hosting_suspension': False, 'web_dns_mail_provisioned': False, 'reboot_qualified': False, 'synthetic_fixture': True, 'binary_sha256': {name: hashlib.sha256((BASE/name).read_bytes()).hexdigest() for name in ['sifruno', 'panelctl', 'hostbroker']}}
    except Exception as failure:
        # No subprocess output, paths, access keys or session material are echoed.
        report = {'passed': False, 'checks': checks, 'failure': str(failure), 'last_command': LAST_COMMAND, 'nss_policy': nss_proof, 'synthetic_fixture': True}
    finally:
        for child in [panel, broker]:
            try: stop(child)
            except Exception: pass
        for log in logs: log.close()
    report['useradd_policy'] = useradd_proof
    report['environment'] = environment_proof
    with report_path.open('x') as target: json.dump(report, target, indent=2);target.write('\n')
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
