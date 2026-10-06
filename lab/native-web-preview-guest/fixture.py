"""Real preview composition, only inside a nonce-admitted disposable Alma guest.
Imports are inert. Credentials remain solely in the owned guest controller state.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import time

import startup_helpers as helpers

SCOPE = 'populated_native_web_preview_NSS_adapted_Alma9_8'
PORT = 18391
PHASE = 'admission'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
RUNTIME = ['/var/lib/sifruno/hostweb', '/var/lib/sifruno/front-jail', '/var/lib/sifruno/backend-jails', '/run/sifruno/hostweb', '/etc/sifruno/tls']


def require(value, code):
    if not value:
        raise AssertionError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def admitted(nonce):
    require(sys.platform == 'linux' and os.geteuid() == 0 and re.fullmatch('[a-f0-9]{32}', nonce), 'guest_platform')
    marker = Path('/run/sifruno-web-preview-admission')
    info = marker.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and helpers.bounded_bytes(marker, 100) == (nonce+'\n').encode(), 'guest_nonce')
    release = helpers.bounded_bytes('/etc/os-release').decode()
    require('ID="almalinux"' in release and 'VERSION_ID="9.8"' in release and platform.machine() == 'x86_64', 'guest_profile')


def drop():
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def http_request(conn, method, path, body=None, headers=None):
    data = None if body is None else compact(body)
    conn.request(method, path, data, {'Content-Type': 'application/json', **(headers or {})})
    response = conn.getresponse()
    raw = response.read(262145)
    require(len(raw) <= 262144, 'response_bound')
    return {'status': response.status, 'body': helpers.strict_json(raw.decode('utf-8')), 'raw_sha256': sha(raw), 'raw_base64': base64.b64encode(raw).decode('ascii')}


def api(operation, parent, argument):
    # Only this child reads its own newly generated operator key. Never emit it.
    drop()
    conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=50)
    if operation == 'unsigned':
        return http_request(conn, 'GET', '/api/v1/accounts/web-preview')
    key = helpers.bounded_bytes(parent/'controller/operator/access.key', 256).decode().strip()
    conn.request('POST', '/api/v1/session/login', compact({'access_key': key}), {'Content-Type': 'application/json', 'Origin': 'http://127.0.0.1:'+str(PORT)})
    response = conn.getresponse()
    raw = response.read(8193)
    require(response.status == 200 and len(raw) <= 8192, 'login')
    session = helpers.strict_json(raw.decode())
    cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    headers = {'Cookie': cookie, 'X-CSRF-Token': session['csrf_token'], 'Origin': 'http://127.0.0.1:'+str(PORT)}
    key = ''
    try:
        if operation == 'create':
            return http_request(conn, 'POST', '/api/v1/accounts', {'username': argument, 'domain': argument+'.example.test', 'reason': 'isolated preview qualification'}, headers)
        if operation == 'state':
            account_id, wanted, revision = argument.split(':')
            return http_request(conn, 'POST', '/api/v1/accounts/'+account_id+'/state', {'state': wanted, 'expected_revision': int(revision), 'reason': 'isolated preview qualification'}, headers)
        require(operation == 'preview', 'operation')
        return http_request(conn, 'GET', '/api/v1/accounts/web-preview', headers=headers)
    finally:
        result = http_request(conn, 'POST', '/api/v1/session/logout', {}, headers)
        require(result['status'] == 200, 'logout')
        conn.close()


def peer(parent, wrong):
    if not wrong:
        drop()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(str(parent/'run/broker.sock'))
    conn = http.client.HTTPConnection('unix', timeout=5)
    conn.sock = sock
    try:
        return http_request(conn, 'GET', '/v1/web-preview')
    except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
        require(wrong, 'admitted_peer_closed')
        return {'refused': True, 'peer_uid': os.geteuid()}
    finally:
        conn.close()


def child(nonce, operation, argument=''):
    result = helpers.run_child(['/usr/bin/python3', '-B', __file__, '--child', nonce, operation, argument], timeout=60, limit=300000)
    require(result['exit_code'] == 0 and result['stderr'] == b'' and result['owned_child_exited'], 'child_failed')
    return helpers.strict_json(result['stdout'].decode())


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise AssertionError('forced_child_cleanup')
    require(process.poll() == 0, 'child_cleanup')


def observe(nonce, expected_file):
    global PHASE
    admitted(nonce)
    here = Path(__file__).resolve().parent
    expected = helpers.strict_json(Path(expected_file).read_text())
    names = ['hostsetup', 'hostbroker', 'sifruno', 'panelctl', 'fixture.py', 'startup_helpers.py']
    require(set(expected) == set(names), 'input_names')
    for name in names:
        info = (here/name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and sha(helpers.bounded_bytes(here/name, 64*1024*1024)) == expected[name], 'input_hash')
    helpers.unique_uid(Path('/etc/passwd'), 65534)
    parent = Path('/run')/('wp'+nonce[:6])
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)
    nss_before = sha(helpers.bounded_bytes('/etc/nsswitch.conf'))
    PHASE = 'stock_refusal'
    stock_args = [str(here/'hostsetup'), '--plan', '--state', str(parent/'state'), '--homes', str(parent/'homes'), '--socket', str(parent/'run/broker.sock'), '--controller-uid', '65534', '--controller-state', str(parent/'controller')]
    stock_result = helpers.run_child(stock_args)
    stock_body = helpers.strict_json(stock_result['stdout'].decode())
    require(stock_result['exit_code'] == 1 and stock_result['stderr'] == b'' and stock_body['ready'] is False and list(parent.iterdir()) == [] and sha(helpers.bounded_bytes('/etc/nsswitch.conf')) == nss_before, 'stock_refusal')
    stock = {'exit_code': 1, 'body': stock_body, 'raw_sha256': sha(stock_result['stdout']), 'raw_base64': base64.b64encode(stock_result['stdout']).decode('ascii'), 'paths_unchanged': True}
    helpers.adapt_nss(nonce)
    mail_before = sha(helpers.bounded_bytes('/etc/default/useradd'))
    PHASE = 'layout'
    setup = helpers.run_child([str(here/'hostsetup'), '--apply', '--state', str(parent/'state'), '--homes', str(parent/'homes'), '--socket', str(parent/'run/broker.sock'), '--controller-uid', '65534', '--controller-state', str(parent/'controller')])
    require(setup['exit_code'] == 0 and helpers.strict_json(setup['stdout'].decode())['ready'] is True, 'layout')
    require(all(not os.path.lexists(p) for p in RUNTIME), 'runtime_preexisting')
    children = []
    cases = []
    broker_args = [str(here/'hostbroker'), '--state', str(parent/'state'), '--homes', str(parent/'homes'), '--socket', str(parent/'run/broker.sock'), '--controller-uid', '65534']
    def launch(argv, controller=False):
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV, start_new_session=True, preexec_fn=drop if controller else None)
        children.append(p)
        return p
    def broker(enabled):
        p = launch(broker_args+(['--web-preview'] if enabled else []))
        for _ in range(200):
            require(p.poll() is None, 'broker_start')
            if (parent/'run/broker.sock').is_socket():
                return p
            time.sleep(.05)
        raise AssertionError('broker_timeout')
    try:
        PHASE = 'broker_and_controller'
        b = broker(False)
        controller = launch([str(here/'sifruno'), '--state', str(parent/'controller'), '--listen', '127.0.0.1:'+str(PORT), '--sites-listen=', '--ui', str(parent/'absent-ui'), '--accounts-socket', str(parent/'run/broker.sock')], True)
        for _ in range(200):
            require(controller.poll() is None, 'controller_start')
            try:
                with socket.create_connection(('127.0.0.1', PORT), .1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError('controller_timeout')
        PHASE = 'disabled_preview'
        off = child(nonce, 'preview')
        require(off['status'] == 503 and 'bundle_sha256' not in off['body'], 'optin_off')
        cases.append({'id': 'disabled_preview', **off})
        PHASE = 'unsigned_api'
        unsigned = child(nonce, 'unsigned')
        require(unsigned['status'] == 401, 'unsigned')
        cases.append({'id': 'unsigned_api', **unsigned})
        stop(b)
        require(not (parent/'run/broker.sock').exists(), 'socket_cleanup')
        b = broker(True)
        PHASE = 'wrong_peer'
        wrong = peer(parent, True)
        require(wrong == {'refused': True, 'peer_uid': 0}, 'wrong_peer')
        cases.append({'id': 'wrong_peer', **wrong})
        PHASE = 'create_accounts'
        first = child(nonce, 'create', 'wpa'+nonce[:6])
        second = child(nonce, 'create', 'wpb'+nonce[:6])
        require(first['status'] == 200 and second['status'] == 200, 'create')
        a, b_account = first['body'], second['body']
        PHASE = 'suspend'
        suspended = child(nonce, 'state', b_account['id']+':suspended:1')
        require(suspended['status'] == 200 and suspended['body']['revision'] == 2, 'suspend')
        PHASE = 'populated_preview'
        populated = child(nonce, 'preview')
        require(populated['status'] == 200 and populated['body']['accounts'] == 2 and populated['body']['active_accounts'] == 1, 'populated')
        cases.append({'id': 'populated', **populated})
        direct = child(nonce, 'peer')
        require(direct['body'] == populated['body'] and direct['status'] == 200, 'peer_metadata')
        PHASE = 'activate'
        activated = child(nonce, 'state', b_account['id']+':active:2')
        require(activated['status'] == 200 and activated['body']['revision'] == 3, 'activate')
        changed = child(nonce, 'preview')
        require(changed['status'] == 200 and changed['body']['active_accounts'] == 2 and changed['body']['snapshot_sha256'] != populated['body']['snapshot_sha256'] and changed['body']['bundle_sha256'] != populated['body']['bundle_sha256'], 'changed')
        cases.append({'id': 'state_changed', **changed})
        PHASE = 'cli_preview'
        cli = child(nonce, 'cli')
        require(cli['body'] == changed['body'] and cli['exit_code'] == 0, 'cli_metadata')
        cases.append({'id': 'cli_matches', **cli})
        import pwd
        native_accounts = []
        for row in [a, activated['body']]:
            identity = pwd.getpwnam(row['username'])
            home = Path(row['home']).stat(); public = Path(row['public_html']).stat()
            require(identity.pw_uid == row['uid'] == home.st_uid == public.st_uid and identity.pw_gid == row['gid'] == home.st_gid == public.st_gid and stat.S_IMODE(home.st_mode) == stat.S_IMODE(public.st_mode) == 0o750, 'native_identity')
            native_accounts.append({'id': row['id'], 'uid': identity.pw_uid, 'gid': identity.pw_gid, 'home_mode': '0750', 'public_html_mode': '0750'})
        # Deliberate owned-account home-mode drift, never a crash or runtime apply.
        PHASE = 'drift'
        os.chmod(a['home'], 0o755)
        drift = child(nonce, 'preview')
        require(drift['status'] == 503 and 'bundle_sha256' not in drift['body'], 'drift_refusal')
        cases.append({'id': 'drift_refused', **drift})
        require(all(not os.path.lexists(p) for p in RUNTIME), 'runtime_created')
        require(helpers.bounded_bytes('/etc/nsswitch.conf') == helpers.NSS_BYTES, 'nss_changed')
        require(mail_before == sha(helpers.bounded_bytes('/etc/default/useradd')), 'mail_defaults_changed')
        require(all(sha(helpers.bounded_bytes(here/name, 64*1024*1024)) == expected[name] for name in names), 'input_changed')
    finally:
        for p in reversed(children):
            stop(p)
    return {'schema_version': 1, 'scope': SCOPE, 'nonce': nonce, 'passed': True, 'profile': {'distribution': 'almalinux', 'version': '9.8', 'machine': platform.machine()}, 'controller_uid': 65534, 'inputs': expected, 'nss_before_sha256': nss_before, 'nss_adapted_sha256': sha(helpers.bounded_bytes('/etc/nsswitch.conf')), 'stock': stock, 'cases': cases, 'direct_peer': direct, 'accounts': [a, activated['body']], 'native_accounts': native_accounts, 'runtime_paths': [{'path': p, 'before': 'missing', 'after': 'missing'} for p in RUNTIME], 'stock_mail_defaults_unchanged': True, 'owned_children_exited': all(p.poll() is not None for p in children)}


def main():
    require(len(sys.argv) >= 3, 'arguments')
    if sys.argv[1] == '--child':
        require(len(sys.argv) == 5, 'child_arguments')
        nonce, operation, argument = sys.argv[2:]
        admitted(nonce)
        parent = Path('/run')/('wp'+nonce[:6])
        if operation == 'peer':
            value = peer(parent, False)
        elif operation == 'cli':
            drop()
            result = helpers.run_child([str(Path(__file__).resolve().parent/'panelctl'), '--state', str(parent/'controller'), '--panel-url', 'http://127.0.0.1:'+str(PORT), 'accounts', 'web-preview'], timeout=60, limit=262144)
            require(result['exit_code'] == 0 and result['stderr'] == b'', 'cli')
            value = {'exit_code': result['exit_code'], 'body': helpers.strict_json(result['stdout'].decode()), 'raw_sha256': sha(result['stdout']), 'raw_base64': base64.b64encode(result['stdout']).decode('ascii')}
        else:
            value = api(operation, parent, argument)
    else:
        require(len(sys.argv) == 3, 'arguments')
        value = observe(sys.argv[1], sys.argv[2])
    print(compact(value).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No exception text: HTTP bodies, credentials and guest paths stay private.
        print('NATIVE_PREVIEW_FAILURE_PHASE=' + PHASE, file=sys.stderr)
        sys.exit(1)
