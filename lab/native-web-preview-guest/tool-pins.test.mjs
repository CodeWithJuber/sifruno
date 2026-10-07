import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {TOOL_AUTHORITIES,admitToolPins} from './tool-pins.mjs';

const own=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const entries=Object.entries(TOOL_AUTHORITIES);
test('four independent authority identities admit exact pins unchanged',()=>{
 assert.equal(entries.length,4);assert(Object.isFrozen(TOOL_AUTHORITIES));
 const pins=entries.map(([name,sha256])=>({path:name,sha256,bytes:123}));
 const seen=[];assert.deepEqual(admitToolPins(name=>{seen.push(name);return pins.find(p=>p.path===name);}),pins);
 assert.deepEqual(seen,entries.map(([name])=>name));
});
for(const [target] of entries)for(const mode of ['missing','mismatch']){
 test(`${mode} authority refuses before subsequent admissions: ${target}`,()=>{
  const seen=[];
  assert.throws(()=>admitToolPins(name=>{
   seen.push(name);
   if(name===target){if(mode==='missing')throw new Error('ENOENT');return {path:name,sha256:'0'.repeat(64)};}
   return {path:name,sha256:TOOL_AUTHORITIES[name]};
  }));
  assert.equal(seen.at(-1),target);
 });
}
test('substituted input identity refuses even with another admitted digest',()=>{
 assert.throws(()=>admitToolPins(name=>({path:entries[1][0],sha256:TOOL_AUTHORITIES[name]})));
});

function inventory(root){return fs.readdirSync(root,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(e=>{const p=path.join(root,e.name);return e.isDirectory()?[e.name+'/',...inventory(p).map(x=>e.name+'/'+x)]:[e.name+':'+fs.readFileSync(p).toString('base64')];});}
for(const mode of ['default','check','import'])test(`temporary isolated runner ${mode} is inert`,t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'sifruno-preview-pins-'));
 t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 for(const name of ['lab/native-web-preview-guest/run.mjs','lab/native-web-preview-guest/tool-pins.mjs','lab/native-web-preview-guest/report.mjs','scripts/verify-startup-preflight.mjs']){
  const target=path.join(temp,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(own,name),target);
 }
 const runner=path.join(temp,'lab/native-web-preview-guest/run.mjs');
 const before=inventory(temp);
 const args=mode==='import'?['--input-type=module','-e',`process.argv=[process.execPath,'unrelated-importer','--run'];await import(${JSON.stringify(pathToFileURL(runner).href)});console.log('IMPORTED_INERT');`]:[runner,...(mode==='check'?['--check']:[])];
 const result=spawnSync(process.execPath,args,{cwd:temp,encoding:'utf8',timeout:10000,maxBuffer:65536,env:{SystemRoot:process.env.SystemRoot??process.env.SYSTEMROOT??'',TEMP:temp,TMP:temp}});
 assert.equal(result.status,0,result.stderr);assert.equal(result.error,undefined);assert.equal(result.stderr,'');
 if(mode==='import')assert.equal(result.stdout,'IMPORTED_INERT\n');
 else assert.deepEqual(JSON.parse(result.stdout),{mode:'check_only',native_observation:false,requires_explicit_run:true});
 assert.deepEqual(inventory(temp),before);
});
