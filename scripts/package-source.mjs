import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { configure, Uint8ArrayReader, Uint8ArrayWriter, ZipReader, ZipWriter } from '@zip.js/zip.js';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=x=>createHash('sha256').update(x).digest('hex');
const excluded=new Set(['node_modules','dist','__pycache__','artifacts','.worktrees','.state','.cache','.forge','.git','.aws','.codex']);
// Compare locally, without logging names/values or writing the environment.
const privateValues=Object.entries(process.env).filter(([name,value])=>/key|token|secret|password/i.test(name)&&value?.length>=12).map(([,value])=>Buffer.from(value));
async function main(){
 configure({useWebWorkers:false});const writer=new ZipWriter(new Uint8ArrayWriter(),{useWebWorkers:false,level:6});const listing=[];
 async function add(path){
  const name=relative(root,path).split(sep).join('/');if(name.split('/').some(p=>excluded.has(p))||/(?:^|\/)\.env(?:\.|$)|\.(?:pyc|tsbuildinfo|key|pem|log)$/.test(name))return;
  const info=await lstat(path);if(info.isSymbolicLink())throw new Error('Source inputs must not be symlinks');
  if(info.isDirectory()){for(const item of(await readdir(path)).sort())await add(join(path,item));return}
  if(!info.isFile())throw new Error('Source inputs must be regular files');
  const bytes=await readFile(path);if(privateValues.some(value=>bytes.includes(value)))throw new Error('Source contains an inherited credential value; packaging stopped without disclosure');
  listing.push({path:name,bytes:bytes.length,sha256:hash(bytes)});await writer.add(name,new Uint8ArrayReader(bytes));
 }
 for(const name of ['.gitattributes','.github','assets','cmd','config','internal','lab','scripts','web','docs','README.md','DESIGN.md','LICENSE','LICENSING.md','go.mod','go.sum','package.json','package-lock.json','.gitignore'])await add(join(root,name));
 try{await lstat(join(root,'AGENTS.md'));await add(join(root,'AGENTS.md'))}catch(error){if(error.code!=='ENOENT')throw error}
 const manifest={product:'Sifruno source',version:'0.1.0',compatibility_certified:false,includes_private_state:false,files:listing};
 await writer.add('SOURCE-MANIFEST.json',new Uint8ArrayReader(Buffer.from(JSON.stringify(manifest,null,2)+'\n')));const bytes=await writer.close();
 const reader=new ZipReader(new Uint8ArrayReader(bytes),{useWebWorkers:false});const entries=await reader.getEntries();assert.equal(entries.length,listing.length+1,'Source archive entry mismatch');const hashes=new Map(listing.map(x=>[x.path,x.sha256]));
 for(const entry of entries){const content=await entry.getData(new Uint8ArrayWriter(),{checkSignature:true});if(entry.filename!=='SOURCE-MANIFEST.json')assert.equal(hash(content),hashes.get(entry.filename),'Source archive checksum failure')}
 await reader.close();const dir=join(root,'deliverables');await mkdir(dir,{recursive:true});const path=join(dir,'sifruno-source.zip');await writeFile(path+'.partial',bytes);await rename(path+'.partial',path);await writeFile(path+'.sha256',hash(bytes)+'  sifruno-source.zip\n');
 console.log(JSON.stringify({archive:'deliverables/sifruno-source.zip',files:listing.length,bytes:bytes.length,integrity_checked:true,inherited_credentials_excluded:true,private_state_included:false,compatibility_certified:false}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
