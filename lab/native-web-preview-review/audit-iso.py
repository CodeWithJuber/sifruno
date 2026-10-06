import sys,json,hashlib,io
from pathlib import Path
sys.dont_write_bytecode=True
root=Path(sys.argv[1]); primary=Path(sys.argv[2]); wheel=primary/'.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'
sys.path.insert(0,str(wheel));import pycdlib
plan=json.loads((root/'payload-plan.json').read_bytes());iso=pycdlib.PyCdlib();iso.open(str(root/'payload.iso'));actual=[]
for folder,dirs,files in iso.walk(rr_path='/'):actual.extend((folder.rstrip('/')+'/'+name).lstrip('/') for name in files)
assert len(actual)==10 and len(set(actual))==10 and set(actual)=={e['destination'] for e in plan['entries']}
for e in plan['entries']:
 stream=io.BytesIO();iso.get_file_from_iso_fp(stream,rr_path='/'+e['destination']);data=stream.getvalue();assert len(data)==e['bytes'] and hashlib.sha256(data).hexdigest()==e['sha256'] and data==Path(e['source']).read_bytes()
 px=iso.get_record(rr_path='/'+e['destination']).rock_ridge.dr_entries.px_record;assert px.posix_file_mode==0o100444 and px.posix_file_links==1
iso.close();print(json.dumps({'passed':True,'entries':10,'iso_sha256':hashlib.sha256((root/'payload.iso').read_bytes()).hexdigest(),'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest()}))
