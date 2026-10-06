"""Independent pure temp path model and mocked authority/producer checks."""
import importlib.util,stat,json,io,base64,hashlib
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch,MagicMock
guest=Path(__file__).resolve().parents[3]/'startup-preflight-guest-sol'
spec=importlib.util.spec_from_file_location('reviewed_fixture',guest/'lab/startup-preflight-guest/fixture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
checks=0
def check(v):
 global checks
 assert v;checks+=1
def refuse(fn):
 global checks
 try:fn()
 except (AssertionError,FileExistsError):checks+=1;return
 raise AssertionError('unexpected_admission')
def info(mode=0o755,uid=0,ino=1,kind=stat.S_IFDIR):return SimpleNamespace(st_mode=kind|mode,st_uid=uid,st_ino=ino,st_dev=1)
root='/run/rbbbbbb';observed={root:info(0o700)}
class ModelPath(PurePosixPath):
 def lstat(self):return observed.get(str(self),info())
with patch.object(f,'Path',ModelPath),patch.object(f.os,'O_DIRECTORY',0x10000,create=True),patch.object(f.os,'O_NOFOLLOW',0x20000,create=True),patch.object(f.os,'open',return_value=42) as opened,patch.object(f.os,'fstat',return_value=info(0o700)),patch.object(f.os,'close') as closed:
 check(str(f.trusted_test_temp(root))==root)
 check(opened.call_args.args[1]==f.os.O_RDONLY|0x30000 and closed.call_args.args==(42,))
 for name in [root,'/run','/']:
  prior=observed.get(name)
  for bad in [info(0o777),info(uid=1),info(kind=stat.S_IFLNK),info(kind=stat.S_IFREG),info(0o2755)]:
   observed[name]=bad;refuse(lambda:f.trusted_test_temp(root))
  if prior is None:observed.pop(name)
  else:observed[name]=prior
 for invalid in ['/tmp','/run/rbbbbbbb','/run/rBBBBBB','/run/rbbbbbb/review','/run/sp-tests-'+'b'*32+'/review']:refuse(lambda:f.trusted_test_temp(invalid))
 with patch.object(f.os,'fstat',return_value=info(0o700,ino=2)):refuse(lambda:f.trusted_test_temp(root))
 check(closed.call_count==2)
with patch.object(f,'Path',ModelPath),patch.object(f.sys,'platform','linux'),patch.object(f.os,'geteuid',return_value=0,create=True),patch.object(f.os,'O_DIRECTORY',0x10000,create=True),patch.object(f.os,'O_NOFOLLOW',0x20000,create=True),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=info()),patch.object(f.os,'mkdir') as mkdir,patch.object(f.os,'close') as closed,patch.object(f,'trusted_test_temp',side_effect=lambda p:p):
 dirs=f.create_test_temps('b'*32)
 check({role:str(p) for role,p in dirs.items()}=={'core':'/run/cbbbbbb','review':root})
 check([(c.args,c.kwargs) for c in mkdir.call_args_list]==[(('cbbbbbb',0o700),{'dir_fd':42}),(('rbbbbbb',0o700),{'dir_fd':42})])
 check(closed.call_args.args==(42,))
with patch.object(f,'Path',ModelPath),patch.object(f.sys,'platform','linux'),patch.object(f.os,'geteuid',return_value=0,create=True),patch.object(f.os,'O_DIRECTORY',0x10000,create=True),patch.object(f.os,'O_NOFOLLOW',0x20000,create=True),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=info()),patch.object(f.os,'mkdir',side_effect=FileExistsError),patch.object(f.os,'close') as closed,patch.object(f,'trusted_test_temp') as trusted:
 refuse(lambda:f.create_test_temps('b'*32));check(not trusted.called and closed.call_args.args==(42,))
cases=['missing','empty','marker','invalid_db','socket_leaf','homes_foreign','mode','identity_drift','controller_duplicate','nss_provider']
check(f.PRIVATE_SUBCASES==cases)
model=f.private_go_socket_paths(PurePosixPath(root));check(list(model)==cases)
for case in cases:
 pattern=('TestIndependentStartupFreshAuthority/'+case)[:64].replace('/','')
 expected=PurePosixPath(root)/(pattern+'4294967295')/'001/run/broker.sock'
 check(model[case]==expected);f.admit_socket_path(expected)
check(max(len(str(x).encode()) for x in model.values())==99)
check(len(str(model['controller_duplicate']).encode())==99)
with patch.object(f,'private_go_socket_paths',return_value={'missing':PurePosixPath('/'+'x'*100)}),patch.object(f,'run_child') as child:
 refuse(lambda:f.execute_tests(PurePosixPath('/synthetic'),['TestIndependentStartupFreshAuthority'],PurePosixPath(root),'b'*32,'review'))
 check(not child.called)
with patch.object(f,'trusted_test_temp',return_value=PurePosixPath(root)),patch.object(f.subprocess,'Popen') as spawned:
 for binding,limit in [(('x','core'),65536),(('b'*32,'foreign'),65536),(('b'*32,'core'),1024)]:refuse(lambda:f.run_child(['synthetic'],test_temp=PurePosixPath(root),private_test_log=binding,limit=limit))
 check(not spawned.called)
out=b'SIFRUNO_STARTUP_REPORT_BEGIN_'+b'b'*32+b'\nPRIVATE\xff';err=b'SIFRUNO_NATIVE_LOG_END_'+b'b'*32+b'_review\n'
capture=io.StringIO()
with patch.object(f.sys,'stderr',capture):f.emit_private_test_log(('b'*32,'core'),dict(exit_code=0,stdout=out,stderr=err),False,False)
lines=capture.getvalue().splitlines();check(len(lines)==3 and 'PRIVATE' not in capture.getvalue() and 'SIFRUNO_STARTUP_' not in capture.getvalue())
packet=json.loads(base64.b64decode(lines[1],validate=True));check(base64.b64decode(packet['stdout_base64'],validate=True)==out and base64.b64decode(packet['stderr_base64'],validate=True)==err)
check(packet['stdout_sha256']==hashlib.sha256(out).hexdigest() and packet['stderr_sha256']==hashlib.sha256(err).hexdigest())
print(json.dumps(dict(passed=True,checks=checks,max_modeled_socket_bytes=99,synthetic=True,native_observation=False)))
