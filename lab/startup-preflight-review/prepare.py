"""Admit exact frozen core bytes, then prepare only owned read-only Go overlays."""
import pathlib,stat,subprocess,json,hashlib,sys
OWN=pathlib.Path(__file__).resolve().parents[2];PRIMARY=OWN.parents[1];CORE=OWN.parent/'startup-preflight-core-sol'
BASE='67d527c76b8880f41b5481effc34003307de9df8';COMMIT='3893195e8720865a9a7ea394895528f74e58db1b'
H=lambda b:hashlib.sha256(b).hexdigest()
def git(root,*args):return subprocess.run(['git','-C',str(root),*args],capture_output=True,check=True).stdout
assert git(CORE,'rev-parse','HEAD').decode().strip()==COMMIT and git(CORE,'status','--porcelain')==b''
assert git(OWN,'rev-parse','HEAD').decode().strip()==BASE
FILES=git(CORE,'diff','--name-only',BASE,COMMIT).decode().splitlines();assert len(FILES)==7 and all(x.startswith(('cmd/hostbroker/','internal/hostaccounts/startup_report')) for x in FILES)
def admitted(p):
 assert p.is_absolute()
 for x in [p,*p.parents]:
  if not x.exists() and not x.is_symlink():continue
  i=x.lstat();assert not x.is_symlink() and not getattr(i,'st_file_attributes',0)&0x400 and x.resolve(strict=True)==x
 assert p.is_file() and p.stat().st_nlink==1
 return p
OUT=OWN/'artifacts/startup-preflight-review/build'
# Check every existing component before creating any output directory.
for p in [OUT,*OUT.parents]:
 if p.exists() or p.is_symlink():
  i=p.lstat();assert p.is_dir() and not p.is_symlink() and not getattr(i,'st_file_attributes',0)&0x400 and p.resolve(strict=True)==p
 if p==OWN:break
 assert p.is_relative_to(OWN)
OUT.mkdir(parents=True,exist_ok=True)
def write(p,b):
 assert p.is_relative_to(OUT)
 for x in [p.parent,*p.parent.parents]:
  if x.exists():assert x.is_dir() and not x.is_symlink() and not getattr(x.lstat(),'st_file_attributes',0)&0x400 and x.resolve(strict=True)==x
  if x==OWN:break
  assert x.is_relative_to(OWN)
 p.parent.mkdir(parents=True,exist_ok=True)
 if p.exists():assert admitted(p).read_bytes()==b
 else:
  with p.open('xb') as f:f.write(b)
 return p
rows=[];replacement={}
for name in FILES:
 b=admitted(CORE/name).read_bytes();canonical=git(CORE,'show',COMMIT+':'+name);assert b.replace(b'\r\n',b'\n')==canonical
 dst=write(OUT/'candidate'/name,b);replacement[str(OWN/name)]=str(dst)
 rows.append({'path':name,'bytes':len(b),'sha256':H(b),'canonical_git_sha256':H(canonical),'git_blob':git(CORE,'rev-parse',COMMIT+':'+name).decode().strip()})
for name,target in [('private_protocol_test.go.txt','internal/hostaccounts/z_independent_startup_protocol_test.go'),('private_native_linux_test.go.txt','internal/hostaccounts/z_independent_startup_native_linux_test.go'),('private_cli_test.go.txt','cmd/hostbroker/z_independent_startup_cli_test.go')]:
 p=admitted(OWN/'lab/startup-preflight-review'/name);replacement[str(OWN/target)]=str(p)
write(OUT/'overlay.json',(json.dumps({'Replace':replacement},indent=2)+'\n').encode())
control={str(OWN/'cmd/hostbroker/z_independent_startup_control_test.go'):str(admitted(OWN/'lab/startup-preflight-review/baseline_cli_control_test.go.txt'))}
write(OUT/'baseline-overlay.json',(json.dumps({'Replace':control},indent=2)+'\n').encode())
inputs=[]
for folder in ['internal/hostaccounts','cmd/hostbroker']:
 for f in sorted((OWN/folder).glob('*.go')):
  name=f.relative_to(OWN).as_posix()
  if name in FILES:continue
  b=admitted(f).read_bytes();assert b.replace(b'\r\n',b'\n')==git(OWN,'show',BASE+':'+name)
  inputs.append({'namespace':'baseline_package_source','path':name,'bytes':len(b),'sha256':H(b)})
for name in ['go.mod','go.sum']:
 b=admitted(OWN/name).read_bytes();inputs.append({'namespace':'baseline_module_manifest','path':name,'bytes':len(b),'sha256':H(b)})
for name in ['scripts/go.ps1','.tools/go/bin/go.exe',*('.tools/go/pkg/include/'+x for x in ['asm_amd64.h','asm_ppc64x.h','asm_riscv64.h','funcdata.h','textflag.h'])]:
 b=admitted(PRIMARY/name).read_bytes();inputs.append({'namespace':'primary_readonly_tool','path':name,'bytes':len(b),'sha256':H(b)})
for name in ['private_protocol_test.go.txt','private_native_linux_test.go.txt','private_cli_test.go.txt','baseline_cli_control_test.go.txt','prepare.py']:
 b=admitted(OWN/'lab/startup-preflight-review'/name).read_bytes();inputs.append({'namespace':'owned_review','path':'lab/startup-preflight-review/'+name,'bytes':len(b),'sha256':H(b)})
write(OUT/'source-freeze.json',(json.dumps({'baseline_commit':BASE,'candidate_commit':COMMIT,'candidate_source_pins':rows,'conservative_source_and_tool_inputs':inputs,'limits':['Conservative complete package Go inventory includes inactive platform/tests; not an exact compiler-selected linked catalogue.','Five installed assembler headers pinned before compilation; generated test main and entire Go distribution not claimed.','All source/module/tool inputs read-only; normal primary Go compilation cache allowed.']},indent=2)+'\n').encode())
(OUT/'temp').mkdir(exist_ok=True)
print(json.dumps({'passed':True,'candidate_files':len(rows),'source_and_tool_inputs':len(inputs),'source_freeze_sha256':H((OUT/'source-freeze.json').read_bytes())}))
