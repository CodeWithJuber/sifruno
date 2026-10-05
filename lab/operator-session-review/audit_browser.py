"""Read-only current-byte audit; never launches a browser or opens fixture keys."""
import hashlib,json,re,struct,sys
from pathlib import Path

root=Path(sys.argv[1]).resolve()
work=root/'artifacts/operator-sessions/20261005T184230380-b8410d0f'
def digest(b): return hashlib.sha256(b).hexdigest()
def strict(b):
 def pairs(items):
  result={}
  for k,v in items:
   assert k not in result, 'duplicate JSON field'
   result[k]=v
  return result
 return json.loads(b,object_pairs_hook=pairs)
def bounded(path,maximum):
 assert path.is_file() and not path.is_symlink()
 assert not any(p.is_symlink() for p in path.parents)
 stat=path.stat();assert stat.st_nlink==1 and 0<stat.st_size<=maximum
 b=path.read_bytes();assert len(b)==stat.st_size
 return b
raw=bounded(work/'report.json',1<<20)
assert digest(raw)=='ca3feb33aa2e94ea2fd162397e257a751a12ca06ae77c5ffad439d16420564fc'
r=strict(raw)
assert r['schema_version']==1 and r['evidence_kind']=='observed_isolated_operator_sessions_browser_qa' and r['platform']=='win32' and r['passed'] is True
assert r['fixture_only'] is True and r['main_state_mutated'] is False and r['paid_provider_calls']==0
assert all(r[k] is False for k in ('live_activation','remote_auth_qualified','compatibility_certified')) and 'failure' not in r
workflow='login cancel_escape_focus selected_revoke_cookie_replay_401 bulk_revoke_count_2_current_retained logout_cookie_replay_401 external_revoke_refresh_clears_private_ui real_mutation_delayed_response_unmount synthetic_503_stale_actions_disabled_recovery client_clock_expiry_only actual_isolated_tcp'.split()
assert set(r['workflow'])==set(workflow+['resource_errors']) and all(r['workflow'][k] is True for k in workflow) and r['workflow']['resource_errors']==0
assert set(r['cleanup'])==set('browser_closed public_fixture_closed owned_child_stopped owned_listener_closed'.split()) and all(v is True for v in r['cleanup'].values())
assert r['source_binary_ui_unchanged_after_execution'] is True
assert 'Local HTML declaration' in r['public_mode_limit'] and 'production proxy exclusion is separately tested by Go' in r['public_mode_limit']
assert 'synthetic 503' in r['timing_limit'] and 'distinct from server expiry' in r['timing_limit']
matrix={(w,t) for w in (390,768,1440) for t in ('light','dark')}
for section in ('private_viewports','public_mode_viewports'):
 entries=r[section];assert len(entries)==6 and {(x['width'],x['theme']) for x in entries}==matrix
 for x in entries:
  assert x['passed'] is True and x['overflow'] is False
  assert all(x[k]==0 for k in ('page_errors','external_requests','asset_failures','mutation_requests'))
  if section=='private_viewports': assert x['dialog_bounds'] is True and x['visible_credentials'] is False and x['browser_storage_credentials'] is False and x['session_requests']==2
  else: assert x['access_hidden'] is True and x['session_requests']==0
sources='scripts/verify-access-ui.mjs internal/operator/operator.go internal/operator/sessions.go internal/api/api.go internal/api/session_controls.go internal/api/session_spec.go web/src/App.tsx web/src/Access.tsx web/src/access.css web/src/lib/access-api.ts web/dist/index.html'.split()
screens={f'{kind}-{w}-{t}.png' for kind in ('private','dialog','public') for w,t in matrix}
assert set(r['sources'])==set(sources)|screens
for name,sha in r['sources'].items():
 assert re.fullmatch('[0-9a-f]{64}',sha)
 p=work/name if name in screens else root/name
 b=bounded(p,8<<20);assert digest(b)==sha,name
 if name in screens:
  assert b[:8]==b'\x89PNG\r\n\x1a\n' and b[12:16]==b'IHDR'
  width,height=struct.unpack('>II',b[16:24]);assert width==int(name.split('-')[1]) and 0<height<10000
  if name.startswith('dialog'):assert height==(844 if width==390 else 1000)
assert {p.name for p in work.glob('*.png')}==screens
ui=root/'web/dist';catalog=r['ui_assets']
assert 0<len(catalog)<=512 and sum(x['bytes'] for x in catalog)<=80<<20
assert [x['path'] for x in catalog]==sorted(x['path'] for x in catalog)
seen=set()
for x in catalog:
 assert set(x)=={'path','bytes','sha256'}
 parts=x['path'].split('/');assert all(p not in ('','..','.') for p in parts) and ':' not in x['path'] and '\\' not in x['path'] and x['path'] not in seen
 seen.add(x['path']);b=bounded(ui.joinpath(*parts),8<<20);assert len(b)==x['bytes'] and digest(b)==x['sha256']
assert seen=={p.relative_to(ui).as_posix() for p in ui.rglob('*') if p.is_file()}
assert digest(json.dumps(catalog,ensure_ascii=False,separators=(',',':')).encode())==r['ui_catalog_sha256']
assert digest(bounded(root/'.cache/session-batch/sifruno.exe',80<<20))==r['binary_sha256']
pins=strict((Path(__file__).parent/'handler-review.json').read_bytes().decode('utf-8-sig'))['source_inputs']
for pin in pins:assert digest(bounded(root/pin['path'],2<<20))==pin['sha256']
def safe_fields(v):
 if isinstance(v,dict):
  assert not {'access_key','csrf_token','cookie','cookies','credential','raw_id'}&set(v)
  for x in v.values():safe_fields(x)
 elif isinstance(v,list):
  for x in v:safe_fields(x)
safe_fields(r)
assert not re.search(rb'BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|Bearer [A-Za-z0-9]|gh[pousr]_[A-Za-z0-9]|sk-[A-Za-z0-9]{20}',raw)
print(json.dumps(dict(kind='independent-operator-session-browser-artifact-audit',passed=True,report_sha256=digest(raw),ui_assets=len(catalog),ui_bytes=sum(x['bytes'] for x in catalog),ui_catalog_sha256=r['ui_catalog_sha256'],binary_sha256=r['binary_sha256'],source_pins=len(pins),screenshots=len(screens),private_viewports=6,public_mode_viewports=6,actual_and_synthetic_authorities_separated=True,cleanup=True,browser_execution_performed=False),separators=(',',':')))
