"""Read-only baseline/candidate source admission and retained native guard audit."""
import hashlib,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[2]
baseline='cebd86fa9ec12a24e6e597e88d5185d76540c685'
def old(name):
 return subprocess.check_output(['git','-C',str(root),'show',baseline+':'+name]).replace(b'\r\n',b'\n')
def new(name):return (root/name).read_bytes().replace(b'\r\n',b'\n')
native='internal/hostaccounts/native_linux.go'
original=old(native);candidate=new(native)
marker=b'func authority('
assert original[original.index(marker):]==candidate[candidate.index(marker):], 'native authority/command/Plan/identity/admission/Create/Recover/Verify/SetState guard suffix changed'
broker='internal/hostaccounts/broker_linux.go'
original=old(broker);candidate=new(broker)
stanza=b'\tsystem, e := newLinuxSystem(opts)\n\tif e != nil {\n\t\treturn e\n\t}\n'
assert original.count(stanza)==candidate.count(stanza)==1
assert original.replace(stanza,b'')==candidate.replace(stanza,b''), 'broker change exceeds relocation'
run=candidate[candidate.index(b'func RunBroker('):]
assert run.index(stanza)<run.index(b'\tfor _, d := range')<run.index(b'if declaredDir(')<run.index(b'openStore(')<run.index(b'net.ListenUnix('), 'admission ordering'
catalog=json.loads((root/'lab/stock-policy-review/source-catalog.json').read_text(encoding='utf-8'))
for row in catalog['files']:
 raw=(root/row['path']).read_bytes()
 assert row['bytes']==len(raw) and row['sha256']==hashlib.sha256(raw).hexdigest(), 'source pin'
print(json.dumps({'passed':True,'admitted_source_pins':len(catalog['files']),'native_guard_suffix_lf_byte_unchanged':True,'broker_only_constructor_relocation':True,'constructor_refusal_before_declared_directories_store_socket':True,'limits':['Read-only source equality/order proof, not executed native startup or atomic host-policy stability.','Portable injected callbacks never access real Linux account policy or execute utilities.']}))
