"""New crash qualification wrapper; immutable prior fixture is a setup library.

Import performs no guest operations. All execution uses fixed synthetic paths
in an admitted disposable guest. The old fixture's main/report is never used.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

ROOT = Path('/opt/sifruno-runtime-fixture')
ADMISSION = Path('/run/sifruno-runtime-crash-admission')
LIBRARY_SHA = '99705157a37d290f6c5a3ed87c8f042ed45169b1c98c57f0017c99cc627acd9e'
HELPER_SHA = '73ef86f95b34d255b4ab5c6145caae718ad1578efba7f1c0d24f5712c57fc9ed'
HEX = re.compile(r'^[a-f0-9]{64}$')
DRIVER_FIELDS = set('schema_version fixture_only execution_kind run_id nonce driver_sha256 input_sha256 profile_sha256 intended_generations observations probes crash checkpoints history inventory_sha256 source_catalog_sha256 prerequisites stage passed shutdown_passed close_passed listeners_extinct input_stable selinux_stable worker_evidence observed_namespace_ids namespaces_extinct namespace_epochs namespace_drain'.split())
CHECKS = ['fixed_current_payload_admission','alma9_enforcing_no_external_nics','signed18_installed_exact_nevras','guest_policy_adapted_declared','two_fixture_accounts_and_private_receipts','disjoint_jail_nss_and_exact_bind_mappings','current_driver_negative_tests','controller_death_checkpoint_denial_selective_apply','owned_driver_reaped_listeners_namespaces_extinct','owned_mounts_removed','input_source_package_policy_stable']

class Failure(RuntimeError):
    pass

def require(condition, code):
    if not condition:
        raise Failure(code)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def strict_json(data, maximum=2 << 20):
    require(0 < len(data) <= maximum, 'json_bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Failure('nonfinite_json')))
    except (UnicodeError, ValueError):
        raise Failure('invalid_json') from None

def exact(value, fields):
    require(isinstance(value, dict) and set(value) == fields, 'exact_fields_required')
    return value

def initial_file(p, mode, maximum):
    st = p.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == mode and 0 < st.st_size <= maximum, 'private_regular_payload_required')
    for parent in [p, *p.parents]:
        require(not parent.is_symlink(), 'payload_link_refused')
    with p.open('rb') as f:
        require(os.fstat(f.fileno()).st_ino == st.st_ino, 'payload_changed')
        b = f.read(maximum + 1)
    require(len(b) == st.st_size, 'payload_size_changed')
    return b

def admission(value):
    fields = set('schema_version kind nonce prepared_image_sha256 fixture_sha256 library_sha256 helper_sha256 source_catalog_sha256 package_report_sha256 driver_sha256 test_sha256 reaping_test_sha256 zero_external_nics'.split())
    a = exact(value, fields)
    require(type(a['schema_version']) is int and a['schema_version'] == 2 and a['kind'] == 'trusted-disposable-alma9-controller-crash' and a['zero_external_nics'] is True and isinstance(a['nonce'], str) and re.fullmatch(r'[a-f0-9]{24}', a['nonce']), 'admission_required')
    require(all(isinstance(a[k], str) and HEX.fullmatch(a[k]) for k in fields if k.endswith('sha256')), 'admission_digest')
    require(a['library_sha256'] == LIBRARY_SHA and a['helper_sha256'] == HELPER_SHA, 'library_pin_mismatch')
    return a

def load_library():
    p = ROOT / 'serving_guest_library.py'
    require(digest(initial_file(p, 0o600, 128 << 10)) == LIBRARY_SHA, 'fixture_library_hash')
    spec = importlib.util.spec_from_file_location('sifruno_crash_fixture_library', p)
    require(spec is not None and spec.loader is not None, 'library_load_failed')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.TOTAL_SECONDS = 420
    return module

def run_id(nonce):
    return digest(('sifruno-crash:' + nonce).encode('ascii'))[:32]

def driver_header(r, a, input_sha):
    exact(r, DRIVER_FIELDS)
    require(type(r['schema_version']) is int and r['schema_version'] == 2 and r['fixture_only'] is True and r['execution_kind'] == 'native-linux-controller-crash-driver' and r['run_id'] == run_id(a['nonce']) and r['driver_sha256'] == a['driver_sha256'] and r['source_catalog_sha256'] == a['source_catalog_sha256'] and r['input_sha256'] == input_sha and re.fullmatch(r'[a-f0-9]{32}', r['nonce']) and re.fullmatch(r'[a-z_]{1,80}(?::[a-z_]{1,80})?', r['stage']), 'driver_receipt_unbound')
    return r

def valid_driver(r, a, input_sha):
    driver_header(r, a, input_sha)
    for k in ['passed','shutdown_passed','close_passed','listeners_extinct','input_stable','selinux_stable','namespaces_extinct']:
        require(r[k] is True, 'driver_cleanup_or_failure')
    require(r['stage'] == 'complete' and len(r['checkpoints']) == 9 and len(r['probes']) == 10 and len(r['worker_evidence']) == 1 and 1 <= len(r['observed_namespace_ids']) <= 32, 'driver_evidence_incomplete')
    c = r['crash']
    require(c['owned_child'] is True and c['signal'] == 9 and c['wait_signaled'] is True and c['native_metadata_stable'] is True and c['strict_observe_rejected'] is True and c['listeners_extinct'] is True and c['namespaces_extinct'] is True and c['journal_before_sha256'] == c['journal_after_sha256'], 'controller_death_unproven')
    require([x['stage'] for x in r['checkpoints']] == ['after_kill','apply_checkpoint','repeated_checkpoint','reopened_checkpoint','stale_refused','denied_repaired','healthy_repair_refused','reopened_denied','selective_apply'], 'checkpoint_order')
    require([x['coordinator']['revision'] for x in r['checkpoints']] == [0,1,1,1,1,2,2,2,3], 'counter_progression')
    require([x['stage'] for x in r['namespace_epochs']] == ['before_kill','repair_denied','selective'] and [len(x['processes']) for x in r['namespace_epochs']] == [5,1,3], 'namespace_epochs_required')
    ids = sorted(set(p['namespace'] for x in r['namespace_epochs'] for p in x['processes']))
    require(r['observed_namespace_ids'] == ids and 5 <= len(ids) <= 9, 'namespace_epoch_union')
    for value in [r['namespace_drain'],r['crash']['namespace_drain']]:
        exact(value,set('attempts elapsed_ms initial final extinct'.split()))
        require(value['extinct'] is True and type(value['attempts']) is int and 1 <= value['attempts'] <= 162 and type(value['elapsed_ms']) is int and 0 <= value['elapsed_ms'] <= 10000,'namespace_drain_bound')
        for scan in [value['initial'],value['final']]:exact(scan,set('matching error error_pid error_errno'.split()))
        require(value['final'] == dict(matching=[],error='',error_pid=0,error_errno=0),'namespace_drain_failed')
        require(value['attempts'] != 1 or value['initial'] == value['final'],'namespace_drain_contradiction')
    return r

def execute(lib, h, kind, nonce, tests):
    require(kind in ('test','regression','driver') and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and len(threading.enumerate()) == 1, 'exclusive_child_wait_required')
    name = {'test':'serving-linux.test','regression':'reaping-linux.test','driver':'qualification-driver'}[kind]
    args = ['-test.v','-test.count=1','-test.timeout=60s'] if kind != 'driver' else ['--input',str(ROOT / 'qualification-input.json')]
    if kind == 'regression':args.append('-test.run=^TestNamespaceReopenedHandlesReapOriginalChild$')
    argv = ['/usr/bin/setpriv','--bounding-set=-net_admin,-net_raw,-net_bind_service,-net_broadcast','--',str(ROOT / name),*args]
    env = h.clean_env(); env.update({'HOME':str(ROOT / 'work'),'TMPDIR':str(ROOT / 'test-tmp')})
    if kind == 'regression':env['SIFRUNO_NATIVE_RUNTIME_TEST'] = '1'
    deadline = min(h.RUN_DEADLINE, time.monotonic() + (70 if kind != 'driver' else 195))
    child = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    receipt, out = lib.capture_child(child, deadline)
    if kind != 'driver':
        safe = len(out) <= 128 << 10 and all(b in (9,10,13) or 32 <= b <= 126 for b in out)
        tag = 'TEST' if kind == 'test' else 'REGRESSION'
        print(f'SIFRUNO_RUNTIME_CRASH_{tag}_BEGIN {nonce}', flush=True)
        if safe:
            sys.stdout.write(out.decode('ascii'))
            if out and not out.endswith(b'\n'):
                sys.stdout.write('\n')
        print(f'SIFRUNO_RUNTIME_CRASH_{tag}_END {nonce}', flush=True)
        names = sorted(re.findall(r'^--- PASS: (Test\w+) \(',out.decode('ascii'),re.MULTILINE)) if safe else []
        receipt['passed_names'] = names
        receipt['contract_passed'] = safe and receipt['exit_code'] == 0 and not receipt['timed_out'] and not receipt['output_bound_exceeded'] and names == tests and b'\nPASS\n' in out and not re.search(rb'--- SKIP:|--- FAIL:|^FAIL$|^panic:',out,re.MULTILINE)
    return receipt, out

def main():
    require(len(sys.argv) == 1 and sys.platform == 'linux' and os.geteuid() == 0 and os.getegid() == 0 and hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'), 'root_linux_pidfd_required')
    os.umask(0o077)
    a = admission(strict_json(initial_file(ADMISSION,0o600,4096)))
    require(Path(__file__).absolute() == ROOT / 'crash_guest.py', 'fixed_entry_required')
    st = ROOT.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700,'private_fixture_root_required')
    lib = load_library()
    result = {'schema_version':2,'kind':'alma9-controller-crash-qualification','nonce':a['nonce'],'driver_run_id':run_id(a['nonce']),'fixture_only':True,'passed':False,'failure_code':None,'checks':[],'cleanup':{'driver_reaped':False,'listeners_extinct':False,'observed_worker_namespaces_extinct':False,'mounts_removed':False},'provenance':{},'environment':{},'policy_adaptations':{},'packages':[],'system_inputs':[],'tls_public_inputs':[],'accounts':[],'sentinels':[],'binds':[],'tests':None,'reaping_test':None,'driver':None}
    h, owned, source_pins, package_pins, policy_hashes, driver = None, [], {}, [], {}, None
    try:
        for name,field,mode,limit in [('crash_guest.py','fixture_sha256',0o600,128<<10),('serving_guest_library.py','library_sha256',0o600,128<<10),('web_runtime_fixture.py','helper_sha256',0o600,128<<10),('source_catalog.json','source_catalog_sha256',0o600,2<<20),('prepared-packages.json','package_report_sha256',0o600,64<<10),('qualification-driver','driver_sha256',0o700,32<<20),('serving-linux.test','test_sha256',0o700,32<<20),('reaping-linux.test','reaping_test_sha256',0o700,32<<20)]:
            data = lib.root_file(ROOT / name,mode,limit);require(digest(data) == a[field],'payload_digest_mismatch');source_pins[name] = (digest(data),mode,limit)
        catalog = strict_json(lib.root_file(ROOT / 'source_catalog.json',0o600,2<<20))
        require(catalog['schema_version'] == 1 and catalog['kind'] == 'current-native-web-controller-crash-build' and catalog['driver']['sha256'] == a['driver_sha256'] and catalog['test']['sha256'] == a['test_sha256'] and catalog['native_execution'] is False,'current_catalog_required')
        require(catalog['reaping_test']['sha256'] == a['reaping_test_sha256'] and catalog['required_reaping_tests'] == ['TestNamespaceReopenedHandlesReapOriginalChild'],'reaping_catalog_required')
        tests = catalog['required_tests'];require(isinstance(tests,list) and tests == sorted(set(tests)) and len(tests) >= 3 and all(isinstance(t,str) and re.fullmatch(r'Test\w{1,100}',t) for t in tests),'test_inventory_required')
        require(not lib.mounted(),'fixture_mounts_not_fresh')
        for name in ['guest-report.json','qualification-input.json','qualification-report.json','fixture-inventory.json','coordinator','managed','homes','front-jail','backend-jails','runtime','tls','work','test-tmp','gpg-check']:
            require(not (ROOT / name).exists() and not (ROOT / name).is_symlink(),'fixture_layout_not_fresh')
        h = lib.load_helper(a)
        result['provenance'] = {**{k:a[k] for k in a if k.endswith('sha256')},'prepared_image_hash_admitted_not_guest_measured':True,'linked_source_catalog_admitted_not_guest_reconstructed':True,'borrowed_fixture_library_sha256':LIBRARY_SHA,'borrowed_helper_functions':['clean_env','run_cmd','write_exact','write_runtime_report','ensure_dir','mount_bind','unmount','prepare_guest_policies','make_certificates'],'old_fixture_main_called':False}
        result['checks'].append(CHECKS[0]);result['environment']['before'] = lib.environment();result['checks'].append(CHECKS[1])
        for name in ['work','test-tmp','managed','homes','front-jail','backend-jails','runtime']:
            lib.directory(h,ROOT / name,0o700 if name in ('work','test-tmp','managed') else 0o755)
        entries = lib.package_entries(strict_json(lib.root_file(ROOT / 'prepared-packages.json',0o600,64<<10)))
        result['packages'] = lib.verify_packages(h,entries);package_pins = entries;result['system_inputs'] = lib.system_inputs();result['checks'].append(CHECKS[2])
        result['policy_adaptations'] = h.prepare_guest_policies(SimpleNamespace(qualification_files_only_nss=True,qualification_no_mail_spool_default=True))
        policy_hashes = {str(p):digest(p.read_bytes()) for p in [Path('/etc/nsswitch.conf'),Path('/etc/default/useradd')]};result['policy_adaptations']['effective_sha256'] = policy_hashes;result['checks'].append(CHECKS[3])
        items,p = lib.accounts(),lib.profile();result['accounts'] = lib.setup_accounts(h,items)
        sentinel = ROOT / 'managed/controller-private-sentinel';h.write_exact(sentinel,b'SIFRUNO_CONTROLLER_PRIVATE\n');result['sentinels'].append(lib.receipt(sentinel,b'SIFRUNO_CONTROLLER_PRIVATE\n',0,0o600))
        for row in items:
            secret = Path(row['home']) / 'private.txt';h.write_exact(secret,b'SIFRUNO_PRIVATE_SENTINEL\n');os.chown(secret,row['uid'],row['gid']);result['sentinels'].append(lib.receipt(secret,b'SIFRUNO_PRIVATE_SENTINEL\n',row['uid'],0o600))
            for name,data in [('index.html',f"SIFRUNO_STATIC_{row['username']}\n".encode()),('probe.php',lib.php_code(row,next(other for other in items if other != row)))]:
                target = Path(row['public_html']) / name;h.write_exact(target,data,0o640);os.chown(target,row['uid'],row['gid'])
        result['checks'].append(CHECKS[4]);result['binds'] = lib.setup_jails(h,p,items,owned);h.make_certificates(p,lib.helper_accounts(items),ROOT / 'work')
        for pth in [ROOT / 'tls/ca.pem',*[ROOT / 'tls' / row['id'] / 'cert.pem' for row in items]]:
            result['tls_public_inputs'].append({'path':str(pth),'sha256':digest(lib.root_file(pth,0o600,16<<10))})
        result['checks'].append(CHECKS[5])
        value = {'schema_version':1,'fixture_only':True,'run_id':run_id(a['nonce']),'root':str(ROOT),'profile':p,'accounts':items}
        raw_input = lib.encoded(value);h.write_exact(ROOT / 'qualification-input.json',raw_input);source_pins['qualification-input.json'] = (digest(raw_input),0o600,32768)
        result['tests'],_ = execute(lib,h,'test',a['nonce'],tests);require(result['tests']['contract_passed'],'native_test_failed');result['reaping_test'],_ = execute(lib,h,'regression',a['nonce'],['TestNamespaceReopenedHandlesReapOriginalChild']);require(result['reaping_test']['contract_passed'],'native_reaping_regression_failed');result['checks'].append(CHECKS[6])
        result['driver'],_ = execute(lib,h,'driver',a['nonce'],tests);result['cleanup']['driver_reaped'] = result['driver']['reaped']
        raw = lib.root_file(ROOT / 'qualification-report.json',0o600,64<<10);driver = driver_header(strict_json(raw),a,digest(raw_input))
        print(f"SIFRUNO_RUNTIME_CRASH_DRIVER_BEGIN {a['nonce']}",flush=True);sys.stdout.write(raw.decode('utf-8')+'\n');print(f"SIFRUNO_RUNTIME_CRASH_DRIVER_END {a['nonce']}",flush=True)
        result['driver']['report_sha256'] = digest(raw);result['driver']['passed'] = driver['passed']
        result['cleanup']['listeners_extinct'] = lib.listener_extinction()
        ids = driver['observed_namespace_ids'];require(all(type(n) is int and n > 0 for n in ids) and len(set(ids)) == len(ids),'namespace_inventory_invalid')
        result['cleanup']['observed_worker_namespaces_extinct'] = lib.namespace_extinction([{'namespace':n} for n in ids])
        valid_driver(driver,a,digest(raw_input))
        require(result['driver']['exit_code'] == 0 and not result['driver']['timed_out'] and not result['driver']['output_bound_exceeded'],'driver_exit_failed');result['checks'].append(CHECKS[7])
        result['checks'].append(CHECKS[8])
    except Exception as error:
        code = str(error) if isinstance(error,(Failure,lib.Failure,getattr(h,'FixtureError',Failure))) else 'unexpected_fixture_failure'
        result['failure_code'] = code if re.fullmatch(r'[a-z0-9_]{1,80}',code) else 'unexpected_fixture_failure'
    finally:
        try:
            if h is not None:
                h.RUN_DEADLINE = time.monotonic()+45;result['cleanup']['mounts_removed'] = lib.cleanup_mounts(h,owned);require(result['cleanup']['mounts_removed'],'mount_cleanup_failed');result['checks'].append(CHECKS[9])
                for name,(sha,mode,limit) in source_pins.items():require(digest(lib.root_file(ROOT/name,mode,limit)) == sha,'source_input_changed')
                for entry in package_pins:require(digest(lib.root_file(ROOT/'packages'/entry['filename'],0o600,64<<20)) == entry['sha256'],'rpm_input_changed')
                for pth,sha in policy_hashes.items():require(digest(Path(pth).read_bytes()) == sha,'effective_policy_changed')
                for row in result['system_inputs']:require(digest(lib.root_file(Path(row['path']),row['mode'],64<<20)) == row['sha256'],'system_input_changed')
                for row in result['tls_public_inputs']:require(digest(lib.root_file(Path(row['path']),0o600,16<<10)) == row['sha256'],'public_tls_input_changed')
                result['environment']['after'] = lib.environment();require(result['environment']['after'] == result['environment']['before'],'environment_changed');result['checks'].append(CHECKS[10])
            require(result['failure_code'] is None and result['checks'] == CHECKS and all(result['cleanup'].values()),'qualification_incomplete');result['passed'] = True
        except Exception as error:
            result['passed'] = False
            if result['failure_code'] is None:result['failure_code'] = str(error) if isinstance(error,(Failure,lib.Failure)) else 'cleanup_or_stability_failed'
        data = lib.encoded(result);require(len(data) <= 64<<10,'guest_report_bound')
        if h is not None:h.write_runtime_report(ROOT/'guest-report.json',ROOT,result)
        print(f"SIFRUNO_RUNTIME_CRASH_BEGIN {a['nonce']}",flush=True);sys.stdout.write(data.decode('utf-8'));print(f"SIFRUNO_RUNTIME_CRASH_END {a['nonce']}",flush=True)
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('runtime_crash_fixture_failed',file=sys.stderr)
        raise SystemExit(1)
