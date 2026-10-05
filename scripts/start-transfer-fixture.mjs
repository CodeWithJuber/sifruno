// Runs only the isolated local feature fixture, never the main state/listeners.
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, lstat, realpath } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join, relative, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const ui=join(root,'.worktrees','native-transfer-ui','web','dist');
const env={};
for(const key of ['SystemRoot','WINDIR','COMSPEC','PATH','PATHEXT','TEMP','TMP','USERPROFILE','LOCALAPPDATA'])if(process.env[key])env[key]=process.env[key];
Object.assign(env,{GOCACHE:join(root,'.cache','go-build'),GOMODCACHE:join(root,'.cache','go-mod'),GOPROXY:'off',GOSUMDB:'off',CGO_ENABLED:'0'});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
let child, phase='UI admission';
async function main(){
 const st=await lstat(join(ui,'index.html'));if(!st.isFile()||st.isSymbolicLink()||await realpath(ui)!==ui)throw new Error('UI not ready');
 // Refuse a second active fixture without stopping any existing process.
 phase='port admission';
 for(const port of [8084,8086]){
  try{await fetch('http://127.0.0.1:'+port+'/',{signal:AbortSignal.timeout(500)});throw new Error('Fixture port occupied');}catch(error){if(error.message==='Fixture port occupied')throw error;}
 }
 phase='fixture directory';
 const id=new Date().toISOString().replace(/[-:.Z]/g,'')+'-'+randomUUID().slice(0,8);
 const dir=join(root,'.cache','native-transfer-fixture',id);await mkdir(dir,{recursive:true});
 if(isAbsolute(relative(root,dir))||relative(root,dir).startsWith('..')||await realpath(dir)!==dir)throw new Error('Unsafe fixture path');
 const binary=join(dir,'sifruno.exe');
 phase='binary build';
 const built=spawnSync(join(root,'.tools','go','bin','go.exe'),['build','-buildvcs=false','-o',binary,'./cmd/sifruno'],{cwd:root,env,encoding:'utf8',windowsHide:true});
 if(built.status!==0)throw new Error('Fixture build failed');
 const state=join(dir,'private-state');
 phase='fixture startup';
 child=spawn(binary,['--listen','127.0.0.1:8084','--sites-listen','127.0.0.1:8086','--state',state,'--ui',ui],{cwd:root,env,stdio:['ignore','ignore','ignore'],windowsHide:true,detached:true});
 const startedAt=new Date().toISOString();
 for(let i=0;i<60;i++){
  if(child.exitCode!==null)throw new Error('Fixture exited');
  try{const r=await fetch('http://127.0.0.1:8084/api/v1/session',{redirect:'error',signal:AbortSignal.timeout(1000)});if(r.status===401)break;}catch{}
  if(i===59)throw new Error('Fixture startup failed');
  await new Promise(r=>setTimeout(r,250));
 }
 const report={schema_version:1,id,pid:child.pid,started_at:startedAt,binary:relative(root,binary),binary_sha256:hash(await readFile(binary)),state:relative(root,state),ui:relative(root,ui),origin:'http://127.0.0.1:8084',sites_origin:'http://127.0.0.1:8086',main_state_mutated:false,paid_provider_calls:0,application_credentials_inherited:false};
 await writeFile(join(root,'.cache','native-transfer-fixture','current.json'),JSON.stringify(report,null,2)+'\n');child.unref();
 console.log(JSON.stringify(report));
}
main().catch(()=>{if(child)child.kill();console.error(JSON.stringify({fixture_passed:false,phase,main_services_changed:false}));process.exitCode=1;});
