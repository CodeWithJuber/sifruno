"""Independent read-only ISO contents audit using the existing admitted wheel."""
import hashlib,io,json,pathlib,stat,sys
own=pathlib.Path(__file__).resolve().parents[2]
worker=pathlib.Path(sys.argv[1]).resolve(strict=True)
report_file=pathlib.Path(sys.argv[2]).resolve(strict=True)
expected=sys.argv[3];output=pathlib.Path(sys.argv[4]).resolve()
assert worker.name=='stock-preflight-cli-sol' and report_file.is_relative_to(worker)
assert output.is_relative_to(own/'.cache/stock-policy-review') and not output.exists()
raw=report_file.read_bytes();assert hashlib.sha256(raw).hexdigest()==expected
r=json.loads(raw);assert r['passed'] and r['native_observation']
work=worker/'.cache/alma9-qualification'/r['run_id']
wheel=worker.parents[1]/'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'
assert hashlib.sha256(wheel.read_bytes()).hexdigest()=='1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e'
sys.path.insert(0,str(wheel));import pycdlib
plan_raw=(work/'payload-plan.json').read_bytes();assert hashlib.sha256(plan_raw).hexdigest()==r['payload_plan_sha256']
plan=json.loads(plan_raw);expected_files={e['destination']:e for e in plan['entries']}
assert len(expected_files)==6 and set(expected_files)=={'payload/panelctl','payload/hostbroker','payload/qualifier.py','user-data','meta-data','network-config'}
image=work/'payload.iso';assert hashlib.sha256(image.read_bytes()).hexdigest()==r['iso_sha256']
iso=pycdlib.PyCdlib();iso.open(str(image));actual_files=[];directories=[];records=[]
try:
 assert iso.pvd.volume_identifier.decode('ascii').strip()=='CIDATA'
 for folder,dirs,files in iso.walk(rr_path='/'):
  directories.extend(folder.rstrip('/')+'/'+name for name in dirs)
  actual_files.extend((folder.rstrip('/')+'/'+name).lstrip('/') for name in files)
 assert sorted(directories)==['/payload'] and sorted(actual_files)==sorted(expected_files)
 px=iso.get_record(rr_path='/payload').rock_ridge.dr_entries.px_record
 assert stat.S_ISDIR(px.posix_file_mode) and px.posix_file_mode==0o40555
 for name,e in expected_files.items():
  rec=iso.get_record(rr_path='/'+name);px=rec.rock_ridge.dr_entries.px_record
  assert stat.S_ISREG(px.posix_file_mode) and px.posix_file_mode==0o100444 and px.posix_file_links==1
  stream=io.BytesIO();iso.get_file_from_iso_fp(stream,rr_path='/'+name);data=stream.getvalue()
  assert len(data)==e['bytes'] and hashlib.sha256(data).hexdigest()==e['sha256']
  assert data==(worker/e['source']).read_bytes()
  if name=='network-config':assert data==b'version: 2\nethernets: {}\n'
  if name=='meta-data':assert data==('instance-id: '+r['run_id']+'\nlocal-hostname: sifruno-stock-policy\n').encode()
  if name=='user-data':
   assert data.startswith(b'#cloud-config\nusers: []\nssh_genkeytypes: []\nssh_deletekeys: false\n')
   assert b'--nonce '+r['guest']['nonce'].encode() in data
   for key,label in [('baseline','payload/panelctl'),('candidate','payload/hostbroker'),('fixture','payload/qualifier.py')]:assert expected_files[label]['sha256']==r['binary_sha256'][key]
  records.append({'destination':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'regular_mode':'100444','links':1})
finally:iso.close()
result={'schema_version':1,'kind':'independent_actual_stock_policy_ISO_contents_audit','passed':True,'report_sha256':expected,'iso_sha256':r['iso_sha256'],'payload_plan_sha256':r['payload_plan_sha256'],'existing_readonly_wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),'volume_label':'CIDATA','directories':['/payload'],'entries':records,'native_execution_performed':False,'limits':['Read-only binary ISO payload/metadata/nonce and exact current source-byte closure; no guest execution repeated.','Existing pinned PyCdlib wheel is an approved dependency, not stdlib or a new download.','Cloud-init staging precedes the guest policy snapshot boundary; this audit does not certify entire pristine image or full Go distribution.']}
with output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps({'passed':True,'entries':len(records),'audit_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'iso_sha256':r['iso_sha256']}))
