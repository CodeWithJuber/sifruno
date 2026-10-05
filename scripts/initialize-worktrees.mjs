// Local, credential-free Git snapshot and isolated worktrees. Never publishes.
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sourceRoots=['assets','cmd','config','internal','lab','scripts','web','docs','README.md','DESIGN.md','AGENTS.md','go.mod','go.sum','package.json','package-lock.json','.gitignore'];
const excluded=new Set(['node_modules','dist','__pycache__','.state','.cache','.forge','.git','.aws','.codex','.tools','.worktrees']);
const privateValues=Object.entries(process.env).filter(([key,value])=>/key|token|secret|password/i.test(key)&&value?.length>=12).map(([,value])=>Buffer.from(value));
const env={};
for(const key of ['SystemRoot','WINDIR','COMSPEC','PATH','PATHEXT','TEMP','TMP','USERPROFILE','HOMEDRIVE','HOMEPATH','LOCALAPPDATA'])if(process.env[key])env[key]=process.env[key];
const empty=join(root,'.cache','worktree-bootstrap','empty');
const git=(args,cwd=root)=>execFileSync('git',['-c','core.hooksPath='+empty,'-c','commit.gpgsign=false',...args],{cwd,env,encoding:'utf8',stdio:['ignore','pipe','pipe'],windowsHide:true}).trim();
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const files=[];
async function collect(path){
 const name=relative(root,path).split(sep).join('/');
 if(name.split('/').some(x=>excluded.has(x))||/(?:^|\/)\.env(?:\.|$)|\.(?:pyc|tsbuildinfo|key|pem|log)$/.test(name))return;
 const info=await lstat(path);if(info.isSymbolicLink())throw new Error('Linked source input rejected');
 if(info.isDirectory()){for(const item of(await readdir(path)).sort())await collect(join(path,item));return;}
 if(!info.isFile()||info.nlink!==1)throw new Error('Source must be a regular single-link file');
 const bytes=await readFile(path);if(privateValues.some(x=>bytes.includes(x)))throw new Error('Inherited credential found; snapshot refused without disclosure');
 files.push({path:name,sha256:hash(bytes)});
}
async function main(){
 await mkdir(empty,{recursive:true});
 for(const name of sourceRoots)await collect(join(root,name));
 // Refuse to adopt an existing repository silently.
 try{await lstat(join(root,'.git'));throw new Error('Repository already exists; use existing worktrees rather than reinitialize');}catch(error){if(error.code!=='ENOENT')throw error;}
 git(['init','-b','main','--template='+empty]);
 git(['add','--',...sourceRoots]);
 const staged=git(['diff','--cached','--name-only','-z']).split('\0').filter(Boolean);
 const accepted=new Set(files.map(x=>x.path));
 if(staged.length===0||staged.some(x=>!accepted.has(x))||['AGENTS.md','go.mod','go.sum','package.json','web/package.json','internal/sites/migration.go','internal/api/site_transfers.go'].some(x=>!staged.includes(x)))throw new Error('Staged source admission mismatch; no commit made');
 for(const file of files)if(hash(await readFile(join(root,file.path)))!==file.sha256)throw new Error('Source changed before snapshot; no commit made');
 git(['-c','user.name=Sifruno local development','-c','user.email=sifruno@localhost','commit','-m','Snapshot native Sifruno control plane for isolated development']);
 const baseline=git(['rev-parse','HEAD']);
 const worktrees=[];
 for(const task of ['native-transfer-ui','native-transfer-cli','native-transfer-review']){
  const path=join(root,'.worktrees',task);const rel=relative(root,path);
  if(!rel||rel.startsWith('..')||resolve(root,rel)!==path)throw new Error('Worktree path escaped workspace');
  git(['worktree','add','-b','workers/'+task,path,baseline]);
  worktrees.push({task,branch:'workers/'+task,path});
 }
 const tracked=files.filter(x=>staged.includes(x.path));
 const report={schema_version:1,baseline,source_files:tracked.length,source_fingerprint:hash(Buffer.from(JSON.stringify(tracked))),private_state_included:false,inherited_credentials_excluded:true,published:false,concurrent_agent_limit:4,worktrees};
 await writeFile(join(root,'.cache','worktree-bootstrap','report.json'),JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify(report));
}
main().catch(()=>{console.error('Local worktree setup failed; inspect source admission and Git status. No remote publication attempted.');process.exitCode=1;});
