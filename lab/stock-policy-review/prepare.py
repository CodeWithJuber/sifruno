"""Admit exact reviewer source then inject only owned test files via Go overlay."""
import hashlib,json,pathlib,stat
root=pathlib.Path(__file__).resolve().parents[2]
catalog=json.loads((root/'lab/stock-policy-review/source-catalog.json').read_text(encoding='utf-8'))
for row in catalog['files']:
 p=root/row['path']; raw=p.read_bytes()
 if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:
  raise ValueError('source pin mismatch: '+row['path'])
cache=root/'.cache/stock-policy-review'
planned=[root/'.cache',cache]
output=cache/'overlay.json'
for p in [*planned,output]:
 try:s=p.lstat()
 except FileNotFoundError:continue
 if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&0x400:raise ValueError('output alias')
 if p in planned and not stat.S_ISDIR(s.st_mode):raise ValueError('output parent type')
 if p==output and (not stat.S_ISREG(s.st_mode) or s.st_nlink!=1):raise ValueError('output file alias')
for p in planned:
 if not p.exists():p.mkdir()
mapping={str(root/'internal/hostaccounts/independent_stock_review_test.go'):str(root/'lab/stock-policy-review/private_challenges_test.go.txt')}
mapping[str(root/'cmd/hostbroker/independent_stock_cli_review_test.go')]=str(root/'lab/stock-policy-review/cli_challenges_test.go.txt')
output.write_text(json.dumps({'Replace':mapping},indent=2)+'\n',encoding='utf-8')
print(json.dumps({'admitted_source_files':len(catalog['files']),'additional_test_files':len(mapping),'production_source_overridden':0}))
