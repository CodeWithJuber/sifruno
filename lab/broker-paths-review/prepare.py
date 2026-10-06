"""Admit exact reviewed files; add one test file without replacing product code."""
import hashlib, json, os, pathlib, stat, subprocess

ROOT = pathlib.Path.cwd().resolve()
BASE = 'b4225d8877d798cdf93b49d3584cc0d8d4cc8375'
CORE = '4af0b7190ba5b73271c57a824d8d713190587553'
assert ROOT.name == 'broker-paths-review-sol' and ROOT.parent.name == '.worktrees'
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def directory(path):
    assert path.is_relative_to(ROOT)
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.exists() or current.is_symlink():
            st = current.lstat()
            assert stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400
        else:
            current.mkdir()
    return path
expected = ['internal/hostaccounts/broker_linux.go', 'internal/hostaccounts/broker_paths_linux.go', 'internal/hostaccounts/broker_paths_linux_test.go']
assert sorted(git('diff','--name-only',BASE,CORE).decode().splitlines()) == sorted(expected)
for label in expected:
    assert git('show','HEAD:'+label) == git('show',CORE+':'+label)
assert git('diff',BASE,'HEAD','--','internal/hostaccounts/native_linux.go','internal/hostaccounts/store.go','internal/hostaccounts/client.go','cmd','go.mod','go.sum') == b''
broker=(ROOT/expected[0]).read_bytes().replace(b'\r\n',b'\n').decode()
assert broker.index('newLinuxSystem(opts)') < broker.index('admitBrokerPaths(opts)') < broker.index('declaredDir(d.path, d.mode)') < broker.index('openStore(opening, opts, system)')
assert broker.index('ctx.Err() != nil') < broker.index('systemUsers()')
helper=(ROOT/expected[1]).read_bytes().replace(b'\r\n',b'\n').decode()
assert 'f.ReadDir(1)' in helper and 'os.SameFile(before, info)' in helper
assert not any(token in helper for token in ['os.Mkdir','os.WriteFile','os.Remove','os.Chmod','os.Chown','openStore('])
out=directory(ROOT/'artifacts/broker-paths-review/build')
directory(out/'temp')
test=ROOT/'lab/broker-paths-review/private_linux_test.go.txt'
virtual=ROOT/'internal/hostaccounts/independent_broker_paths_linux_test.go'
assert not virtual.exists()
overlay={'Replace':{str(virtual):str(test)}}
for label,data in [('overlay.json',json.dumps(overlay,indent=2)+'\n')]:
    target=out/label
    if target.exists() or target.is_symlink():
        info=target.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not getattr(info,'st_file_attributes',0)&0x400 and target.read_bytes().replace(b'\r\n',b'\n')==data.encode('utf-8')
    else:
        target.write_text(data,encoding='utf-8')
pins=[]
for label in expected+['internal/hostaccounts/native_linux.go','internal/hostaccounts/store.go','go.mod','go.sum','lab/broker-paths-review/private_linux_test.go.txt','lab/broker-paths-review/public_test.go','lab/broker-paths-review/prepare.py']:
    raw=(ROOT/label).read_bytes();pins.append({'path':label,'bytes':len(raw),'sha256':sha(raw)})
record={'schema_version':1,'core_commit':CORE,'baseline_commit':BASE,'review_head':git('rev-parse','HEAD').decode().strip(),'source_pins':pins,'overlay_sha256':sha((out/'overlay.json').read_bytes()),'native_guards_store_client_cli_modules_unchanged':True,'all_path_admission_before_first_declared_directory_write':True,'one_entry_read_and_descriptor_identity_source_checked':True,'limits':['Source/compile checks only; Linux runtime is pending.','No full database-content or atomic privileged filesystem stability guarantee.']}
target=out/'source-audit.json'
if target.exists() or target.is_symlink():
    info=target.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not getattr(info,'st_file_attributes',0)&0x400
target.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'source_pins':len(pins),'output':str(out)}))
