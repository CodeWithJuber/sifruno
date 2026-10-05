"""Read fixed synthetic identity metadata in an already failed disposable guest."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = Path('/opt/sifruno-account-qualification')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def query(args):
    result = subprocess.run(args, env=ENV, cwd=BASE, capture_output=True, timeout=20)
    assert len(result.stdout) + len(result.stderr) <= 65536
    return result


def main():
    assert len(sys.argv) == 1 and sys.platform == 'linux' and os.geteuid() == 0
    prior = json.loads((BASE/'account-report.json').read_text())
    assert prior.get('passed') is False and prior.get('synthetic_fixture') is True
    assert prior.get('last_command', {}).get('account_operation') == 'create'
    report = {'synthetic_fixture': True, 'read_only_identity_observation': True, 'cpanel_compatibility_certified': False}
    package = query(['/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}\n', 'shadow-utils'])
    package_name = package.stdout.decode('ascii').strip()
    assert package.returncode == 0 and re.fullmatch(r'shadow-utils-[a-zA-Z0-9_.+-]{1,100}', package_name)
    report['shadow_package'] = package_name
    # --help exits during option parsing before any account action. The
    # disputed -K comes first so the installed parser is actually exercised.
    parser = query(['/usr/sbin/useradd', '-K', 'CREATE_MAIL_SPOOL=no', '--help'])
    report['mail_spool_key_help_only_probe'] = {'exit_code': parser.returncode, 'unknown_configuration_item': b'unknown configuration item' in parser.stderr}
    defaults = Path('/etc/default/useradd').read_text()
    assert len(defaults) <= 65536
    report['useradd_defaults'] = {'explicit_mail_spool_no': bool(re.search(r'^CREATE_MAIL_SPOOL=no\s*$', defaults, re.MULTILINE)), 'explicit_mail_spool_yes': bool(re.search(r'^CREATE_MAIL_SPOOL=yes\s*$', defaults, re.MULTILINE))}
    for database, count in [('passwd', 7), ('group', 4)]:
        result = query(['/usr/bin/getent', database, 'proofacct'])
        fields = result.stdout.decode('ascii').strip().split(':')
        value = {'exit_code': result.returncode, 'present': result.returncode == 0}
        if result.returncode == 0:
            assert len(fields) == count and fields[0] == 'proofacct'
            if database == 'passwd':
                value.update(uid=int(fields[2]), gid=int(fields[3]), tag_is_expected=bool(re.fullmatch(r'sifruno-managed-[a-f0-9]{32}', fields[4])), home_is_expected=fields[5] == '/home/sifruno-managed/proofacct', shell_is_nologin=fields[6] == '/usr/sbin/nologin')
            else:
                value.update(gid=int(fields[2]), members_empty=fields[3] == '')
        report[database] = value
    for utility, args in [('passwd_status', ['/usr/bin/passwd', '--status', 'proofacct']), ('account_expiry', ['/usr/bin/chage', '--list', 'proofacct'])]:
        result = query(args)
        value = {'exit_code': result.returncode}
        if result.returncode == 0:
            if utility == 'passwd_status':
                fields = result.stdout.decode('ascii').split()
                value['locked'] = len(fields) >= 2 and fields[0] == 'proofacct' and fields[1] in ('L', 'LK')
                value['status_token'] = fields[1] if fields[1] in ('L', 'LK', 'NP', 'P', 'PS') else 'unrecognized'
            else:
                lines = result.stdout.decode('ascii').splitlines()
                value['never'] = any(line.startswith('Account expires') and line.split(':', 1)[1].strip() == 'never' for line in lines)
        report[utility] = value
    metadata = []
    for name in ['/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/var/lib/sifruno-hostbroker', '/var/lib/sifruno-hostbroker/owners', '/var/lib/sifruno-hostbroker/empty-skel', '/home/sifruno-managed', '/home/sifruno-managed/proofacct', '/home/sifruno-managed/proofacct/public_html']:
        item = {'path': name, 'present': False}
        try:
            info = os.lstat(name)
            item.update(present=True, uid=info.st_uid, gid=info.st_gid, mode=oct(stat.S_IMODE(info.st_mode)), links=info.st_nlink, symlink=stat.S_ISLNK(info.st_mode))
        except FileNotFoundError:
            pass
        metadata.append(item)
    report['fixed_metadata'] = metadata
    audit = Path('/var/log/audit/audit.log')
    denials = []
    if audit.is_file():
        with audit.open('rb') as source:
            source.seek(max(0, audit.stat().st_size - 1024*1024))
            for raw in source:
                line = raw.decode('ascii', errors='ignore')
                command = re.search(r'\bcomm="(useradd|groupadd|passwd|chage)"', line)
                action = re.search(r'avc:\s+denied\s+\{\s*([a-z_ ]+)\}', line)
                if command and action:
                    denials.append({'utility': command.group(1), 'denied': action.group(1).strip()})
    report['fixed_utility_selinux_denials'] = denials[-20:]
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'passed': False, 'failure': 'fixed_guest_diagnostics_failed', 'synthetic_fixture': True}))
        raise SystemExit(1)
