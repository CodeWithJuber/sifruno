"""Read-only candidate overlay; outputs stay in the assigned reviewer tree."""
import hashlib,json,pathlib,stat,subprocess
ROOT=pathlib.Path.cwd().resolve(strict=True)
BASE='392700489d49f13810923586a94eef6b48ec9cf6'
CORE='23e9a97f17b9735fdffa7ed4012f78e4e8e44a57'
assert ROOT.name=='service-accounts-review-sol' and ROOT.parent.name=='.worktrees'
CANDIDATE=ROOT.parent/'service-accounts-core-sol'
FILES=['internal/hostaccounts/'+x for x in ['native_linux.go','native_linux_test.go','policy.go','policy_report.go','policy_report_test.go','policy_test.go','types.go']]
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(root,*args):return subprocess.check_output(['git','-C',str(root),*args])
def regular(path):
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not getattr(st,'st_file_attributes',0)&0x400
 return path.read_bytes()
def directory(path):
 assert path.is_relative_to(ROOT)
 current=ROOT
 for part in path.relative_to(ROOT).parts:
  current/=part
  if current.exists() or current.is_symlink():
   st=current.lstat();assert stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400
  else:current.mkdir()
 return path
def write(path,raw):
 directory(path.parent)
 if path.exists() or path.is_symlink():assert regular(path)==raw
 else:path.write_bytes(raw)
assert subprocess.run(['git','merge-base','--is-ancestor',BASE,'HEAD'],cwd=ROOT,check=False).returncode==0
assert all(label.startswith('lab/service-accounts-review/') for label in git(ROOT,'diff','--name-only',BASE,'HEAD').decode().splitlines())
assert sorted(git(ROOT,'diff','--name-only',BASE,CORE).decode().splitlines())==sorted(FILES)
assert git(CANDIDATE,'rev-parse','HEAD').decode().strip()==CORE
assert not git(CANDIDATE,'status','--porcelain')
out=directory(ROOT/'artifacts/service-accounts-review/build')
directory(out/'temp');directory(out/'candidate')
pins=[];overlay={}
for label in FILES:
 raw=regular(CANDIDATE/label);blob=git(ROOT,'show',CORE+':'+label)
 assert raw.replace(b'\r\n',b'\n')==blob
 assert regular(ROOT/label).replace(b'\r\n',b'\n')==git(ROOT,'show',BASE+':'+label)
 dest=out/'candidate'/pathlib.Path(label).name;write(dest,raw);overlay[str(ROOT/label)]=str(dest)
 pins.append({'path':label,'bytes':len(raw),'sha256':sha(raw),'canonical_git_sha256':sha(blob),'git_blob':git(ROOT,'rev-parse',CORE+':'+label).decode().strip()})
for test,target in [('private_policy_test.go.txt','independent_service_policy_test.go'),('private_argv_linux_test.go.txt','independent_service_argv_linux_test.go')]:
 path=ROOT/'lab/service-accounts-review'/test;raw=regular(path)
 assert not (ROOT/'internal/hostaccounts'/target).exists()
 overlay[str(ROOT/'internal/hostaccounts'/target)]=str(path)
write(out/'overlay.json',(json.dumps({'Replace':overlay},indent=2)+'\n').encode())
# Expected-failure baseline control preserves all old production bytes, injecting
# only the independently authored yes-default and report regression challenges.
control=regular(ROOT/'lab/service-accounts-review/private_policy_test.go.txt').replace(b'serviceAccountDefaults(',b'mailDisabledDefaults(')
write(out/'baseline_control_test.go.txt',control)
write(out/'baseline-overlay.json',(json.dumps({'Replace':{str(ROOT/'internal/hostaccounts/independent_service_policy_test.go'):str(out/'baseline_control_test.go.txt')}},indent=2)+'\n').encode())
record={'schema_version':1,'baseline_commit':BASE,'candidate_commit':CORE,'candidate_source_pins':pins,'candidate_replaces':len(FILES),'private_test_additions':2,'overlay_sha256':sha((out/'overlay.json').read_bytes()),'private_test_pins':[{'path':'lab/service-accounts-review/'+x,'bytes':len(regular(ROOT/'lab/service-accounts-review'/x)),'sha256':sha(regular(ROOT/'lab/service-accounts-review'/x))} for x in ['private_policy_test.go.txt','private_argv_linux_test.go.txt']],'no_other_candidate_source_changes':True,'source_findings':[],'limits':['Read-only source overlay; no product edits or native execution.','Installed distro patched utility behavior remains unqualified until actual native flow.']}
write(out/'source-audit.json',(json.dumps(record,indent=2)+'\n').encode());print(json.dumps({'passed':True,'candidate_files':len(pins),'output':str(out)}))
