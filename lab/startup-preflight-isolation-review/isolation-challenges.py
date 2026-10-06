"""Independent model checks only. Never launch native/privileged children."""
import importlib.util, io, json, os, stat
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

guest = Path(__file__).resolve().parents[3] / 'startup-preflight-guest-sol'
spec = importlib.util.spec_from_file_location('fixture', guest / 'lab/startup-preflight-guest/fixture.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
checks = 0
def check(value):
    global checks
    assert value
    checks += 1
def refuse(action):
    global checks
    try: action()
    except (AssertionError, FileExistsError): checks += 1; return
    raise AssertionError('unexpected_admission')
def info(mode=0o755, uid=0, inode=1, device=1, kind=stat.S_IFDIR):
    return SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_ino=inode, st_dev=device)
root = '/run/sp-tests-' + 'b' * 32
target = root + '/core'
observed = {root: info(0o700), target: info(0o700)}
class ModelPath(PurePosixPath):
    def lstat(self): return observed.get(str(self), info())
with patch.object(f, 'Path', ModelPath), patch.object(f.os, 'O_DIRECTORY', 0x10000, create=True), patch.object(f.os, 'O_NOFOLLOW', 0x20000, create=True), patch.object(f.os, 'open', return_value=42) as opened, patch.object(f.os, 'fstat', return_value=info(0o700)), patch.object(f.os, 'close') as closed:
    check(str(f.trusted_test_temp(target)) == target)
    check(opened.call_args.args[1] == os.O_RDONLY | 0x30000)
    check(closed.call_args.args == (42,))
    for path in [target, root, '/run', '/']:
        for bad in [info(0o777), info(0o755,uid=1), info(kind=stat.S_IFLNK), info(kind=stat.S_IFREG), info(0o2755)]:
            prior = observed.get(path)
            observed[path] = bad
            refuse(lambda: f.trusted_test_temp(target))
            if prior is None: observed.pop(path)
            else: observed[path] = prior
    for path in ['/tmp', root+'/foreign', '/run/sp-tests-'+'B'*32+'/core', 'relative']:
        refuse(lambda: f.trusted_test_temp(path))
    for drift in [info(0o700,inode=2), info(0o700,device=2)]:
        with patch.object(f.os,'fstat',return_value=drift): refuse(lambda:f.trusted_test_temp(target))
    check(closed.call_count == 3) # Successful open and both drift refusals close.

# Fully mock process and pipes: environment validation precedes Popen.
def child():
    c = MagicMock()
    c.stdout, c.stderr = io.BytesIO(b'safe\n'), io.BytesIO(b'')
    c.poll.return_value, c.returncode = 0, 0
    return c
with patch.object(f.subprocess,'Popen',side_effect=lambda *a,**kw:child()) as spawned, patch.object(f,'trusted_test_temp',return_value=target) as trusted, patch.object(f.os,'name','nt'):
    with patch.dict(os.environ, {'SYNTHETIC_SECRET':'must-not-inherit', 'TMPDIR':'foreign', 'TEMP':'foreign', 'TMP':'foreign'}):
        f.run_child(['synthetic-only'],test_temp=target)
        f.run_child(['synthetic-only'])
    fixed = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LANG='C',LC_ALL='C')
    check(spawned.call_args_list[0].kwargs['env'] == dict(fixed,TMPDIR=target))
    check(spawned.call_args_list[1].kwargs['env'] == fixed)
    check(trusted.call_count == 1)
with patch.object(f,'trusted_test_temp',side_effect=AssertionError('test_temp_authority')), patch.object(f.subprocess,'Popen') as spawned:
    refuse(lambda:f.run_child(['synthetic-never-executed'],test_temp='/tmp'))
    check(not spawned.called)

# Exclusive descriptor-relative setup, distinct roles and closure on refusal.
def model_info(path): return info(0o700) if path.name.startswith('sp-tests-') else info()
with patch.object(f,'Path',ModelPath), patch.object(ModelPath,'lstat',model_info), patch.object(f.sys,'platform','linux'), patch.object(f.os,'geteuid',return_value=0,create=True), patch.object(f.os,'O_DIRECTORY',0x10000,create=True), patch.object(f.os,'O_NOFOLLOW',0x20000,create=True), patch.object(f.os,'open',side_effect=[42,43]), patch.object(f.os,'fstat',side_effect=[info(),info(0o700),info(0o700)]), patch.object(f.os,'mkdir') as mkdir, patch.object(f.os,'close') as closed, patch.object(f,'trusted_test_temp',side_effect=lambda p:p):
    dirs = f.create_test_temps('b'*32)
    check(str(dirs['core']) == target and str(dirs['review']) == root+'/review')
    check([(c.args,c.kwargs) for c in mkdir.call_args_list] == [((root.split('/')[-1],0o700),{'dir_fd':42}),(('core',0o700),{'dir_fd':43}),(('review',0o700),{'dir_fd':43})])
    check([c.args for c in closed.call_args_list] == [(42,),(43,)])
with patch.object(f,'Path',ModelPath), patch.object(ModelPath,'lstat',model_info), patch.object(f.sys,'platform','linux'), patch.object(f.os,'geteuid',return_value=0,create=True), patch.object(f.os,'O_DIRECTORY',0x10000,create=True), patch.object(f.os,'O_NOFOLLOW',0x20000,create=True), patch.object(f.os,'open',return_value=42), patch.object(f.os,'fstat',return_value=info()), patch.object(f.os,'mkdir',side_effect=FileExistsError), patch.object(f.os,'close') as closed, patch.object(f,'trusted_test_temp') as trusted:
    refuse(lambda:f.create_test_temps('b'*32))
    check(not trusted.called and closed.call_args.args == (42,))
print(json.dumps(dict(passed=True,checks=checks,synthetic=True,native_observation=False)))
