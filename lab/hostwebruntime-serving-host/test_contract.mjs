// Execute only the pinned guest's import-safe validators on Windows.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {test} from 'node:test';
import {digest,regular} from '../hostwebruntime-mechanics/admission.mjs';
import {buildAdmission,preparedPackages} from './inputs.mjs';
import {expectedDigests,inputHash,runID} from './parser.mjs';
const here=path.dirname(fileURLToPath(import.meta.url)),owner=path.resolve(here,'../..'),primary=path.basename(path.dirname(owner))==='.worktrees'?path.resolve(owner,'../..'):owner;
const pins=JSON.parse(fs.readFileSync(path.join(here,'pins.json')));
const python=path.join(process.env.LOCALAPPDATA,'Programs/Python/Python312/python.exe');
const guest=regular(primary,pins.fixture.path);assert.equal(digest(fs.readFileSync(guest)),pins.fixture.sha256);
const manifest=JSON.parse(fs.readFileSync(regular(primary,pins.guest_manifest.path)));assert.equal(digest(fs.readFileSync(python)),manifest.python_tool_sha256);
const nonce='a'.repeat(24),packages=preparedPackages(JSON.parse(fs.readFileSync(regular(primary,pins.package_manifest.path))));
const admission=buildAdmission(pins,nonce,JSON.stringify(packages)+'\n');
const program=`import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('fixed_serving_guest_contract',sys.argv[1])
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
v=json.load(sys.stdin);g.validate_admission(v)
for key,value in [('kind','sifruno-runtime-serving-admission'),('zero_external_nics',1),('nonce','a'*32)]:
 bad=dict(v);bad[key]=value
 try:g.validate_admission(bad)
 except g.Failure:pass
 else:raise RuntimeError('negative admission accepted')
p,s=g.expected_digests()
# Path.__str__ uses backslashes on Windows; characterize the guest's Linux
# absolute root using its same Path.as_posix value, without executing main.
body={'schema_version':1,'fixture_only':True,'run_id':g.driver_run_id(v['nonce']),'root':g.ROOT.as_posix(),'profile':g.profile(),'accounts':g.accounts()}
print(json.dumps({'admission':v,'profile':p,'snapshots':s,'input_sha256':g.digest(g.encoded(body)),'run_id':g.driver_run_id(v['nonce'])}))
`;
test('real generated host admission accepted by pinned guest validator; old kind refused',()=>{
 const r=spawnSync(python,['-I','-B','-c',program,guest],{input:JSON.stringify(admission),encoding:'utf8',windowsHide:true,timeout:10000,maxBuffer:16384});assert(!r.error);assert.equal(r.status,0,r.stderr);const value=JSON.parse(r.stdout);assert.deepEqual(value.admission,admission);assert.equal(value.run_id,runID(nonce));assert.equal(value.profile,expectedDigests().profile);assert.deepEqual(value.snapshots,expectedDigests().snapshots);assert.equal(value.input_sha256,inputHash(nonce));
});
