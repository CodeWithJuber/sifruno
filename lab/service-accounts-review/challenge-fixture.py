"""Independent synthetic native-identity cross-contract; no host reads/children."""
import hashlib,importlib.util,json,pathlib,stat,sys,types
from unittest.mock import patch
from datetime import datetime as ActualDatetime, date
source=pathlib.Path(sys.argv[1]).resolve();raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
spec=importlib.util.spec_from_file_location('reviewed_service_fixture',source);fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
assert fixture.NSS_BYTES==b'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' and len(fixture.NSS_BYTES)==54
account={'username':'sfsynthetic','uid':20000,'gid':20000,'home':'/owned/sfsynthetic','public_html':'/owned/sfsynthetic/public_html','state':'active'}
class FakePath:
 def __init__(self,value):self.value=str(value)
 def __str__(self):return self.value
 def lstat(self):
  assert self.value in (account['home'],account['public_html'])
  return types.SimpleNamespace(st_mode=stat.S_IFDIR|0o750,st_uid=20000,st_gid=20000,st_ino=500 if self.value==account['home'] else 501,st_dev=1)
 def iterdir(self):
  assert self.value in (account['home'],account['public_html'])
  return iter([types.SimpleNamespace(name='public_html')]) if self.value==account['home'] else iter([])
def rows(path,columns):
 if str(path)=='/etc/passwd':assert columns==7;return [['sfsynthetic','x','20000','20000','owned-tag',account['home'],'/usr/sbin/nologin']]
 assert str(path)=='/etc/group' and columns==4
 return [['sfsynthetic','x','20000',''],['wheel','x','10','root']]
fields={'Last password change':'Oct 06, 2026','Password expires':'never','Password inactive':'never','Account expires':'never','Minimum number of days between password change':'-1','Maximum number of days between password change':'-1','Number of days of warning before password expires':'-1'}
def command(argv,limit):
 assert argv[2]=='sfsynthetic' and limit==4096
 if argv[:2]==['/usr/bin/passwd','--status']:return {'exit_code':0,'stdout':b'sfsynthetic LK 2026-10-06 -1 -1 -1 -1\n','stderr':b''}
 assert argv[:2]==['/usr/bin/chage','--list']
 return {'exit_code':0,'stdout':('\n'.join(k+' : '+v for k,v in fields.items())+'\n').encode(),'stderr':b''}
class FixedDatetime(ActualDatetime):
 @classmethod
 def now(cls,tz):return cls(2026,10,6,tzinfo=tz)
def observed():
 with patch.object(fixture,'Path',FakePath),patch.object(fixture,'public_rows',rows),patch.object(fixture,'run_child',command),patch.object(fixture,'datetime',FixedDatetime):return fixture.native_identity(account,date(2026,10,6))
positive=negative=0
result=observed();assert result['password_aging']=='disabled' and result['account_expiry']=='never';positive+=1
for key,value in [('Password expires','Oct 07, 2026'),('Password inactive','Oct 08, 2026'),('Account expires','Jan 02, 1970'),('Maximum number of days between password change','99999'),('Last password change','malformed last change')]:
 previous=fields[key];fields[key]=value
 try:
  observed()
 except AssertionError:negative+=1
 else:raise AssertionError('unexpected identity admission: '+key)
 finally:fields[key]=previous
account['state']='suspended';fields['Account expires']='Jan 02, 1970';result=observed();assert result['account_expiry']=='1970-01-02';positive+=1
assert fixture.BROKER_SECONDS==60 and fixture.PEER_REQUEST_SECONDS==50 and fixture.PEER_SOCKET_SECONDS==45
for value in ['never','Oct 05, 2026','Oct 07, 2026','Feb 30, 2026','garbage']:
 try:fixture.validate_last_change(value,date(2026,10,6),date(2026,10,6))
 except (AssertionError,ValueError):negative+=1
 else:raise AssertionError('unbounded last-change admitted')
assert fixture.validate_last_change('never',date(1970,1,1),date(1970,1,1))=='never';positive+=1
print(json.dumps({'passed':True,'synthetic_only':True,'positive':positive,'negative':negative,'native_execution':False,'fixture_sha256':sys.argv[2]}))
