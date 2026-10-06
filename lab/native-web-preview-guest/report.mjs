import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
export const SCOPE='populated_native_web_preview_NSS_adapted_Alma9_8';
export const CASES=['disabled_preview','unsigned_api','wrong_peer','populated','state_changed','cli_matches','drift_refused'];
export const INPUTS=['hostsetup','hostbroker','sifruno','panelctl','fixture.py','startup_helpers.py'];
export const RUNTIME=['/var/lib/sifruno/hostweb','/var/lib/sifruno/front-jail','/var/lib/sifruno/backend-jails','/run/sifruno/hostweb','/etc/sifruno/tls'];
const hash=/^[a-f0-9]{64}$/,id=/^[a-f0-9]{32}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const keys=(v,k)=>{assert(v&&typeof v==='object'&&!Array.isArray(v));assert.deepEqual(Object.keys(v).sort(),[...k].sort());};
export function validatePreview(v,ids){
 keys(v,['profile','profile_sha256','snapshot_sha256','bundle_sha256','accounts','active_accounts','suspended_accounts','files']);
 assert.equal(v.profile,'restricted-chroot-v1');for(const k of ['profile_sha256','snapshot_sha256','bundle_sha256'])assert(hash.test(v[k])&&v[k].length===64);
 assert.equal(v.accounts,2);assert.equal(v.active_accounts,ids.length);assert.equal(v.suspended_accounts,2-ids.length);
 const expected=['apache/front.conf',...ids.flatMap(x=>{assert(id.test(x)&&x.length===32);return ['apache/backends/'+x+'.conf','fpm/'+x+'.conf'];})];
 assert(Array.isArray(v.files)&&v.files.length===expected.length);assert.deepEqual(v.files.map(f=>f.path).sort(),expected.sort());let total=0;
 for(const f of v.files){keys(f,['path','mode','bytes','sha256']);assert.equal(f.mode,384);assert(Number.isSafeInteger(f.bytes)&&f.bytes>0&&f.bytes<=262144);assert(hash.test(f.sha256)&&f.sha256.length===64);total+=f.bytes;}assert(total<=8*1024*1024);
}
function captured(v,cli=false,withID=true){
 keys(v,[...(withID?['id']:[]),cli?'exit_code':'status','body','raw_sha256','raw_base64']);
 assert(typeof v.raw_base64==='string'&&v.raw_base64.length<=350000);const raw=Buffer.from(v.raw_base64,'base64');assert(raw.length<=262144&&raw.toString('base64')===v.raw_base64);assert.equal(sha(raw),v.raw_sha256);const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);assert.deepEqual(JSON.parse(text),v.body);assert.equal(text,JSON.stringify(v.body,null,cli?'  ':undefined)+'\n');
}
export function validateGuest(g,nonce,expectedInputs){
 keys(g,['schema_version','scope','nonce','passed','profile','controller_uid','inputs','nss_before_sha256','nss_adapted_sha256','stock','cases','direct_peer','accounts','native_accounts','runtime_paths','stock_mail_defaults_unchanged','owned_children_exited']);
 assert.equal(g.schema_version,1);assert.equal(g.scope,SCOPE);assert.equal(g.nonce,nonce);assert.equal(g.passed,true);assert.deepEqual(g.profile,{distribution:'almalinux',version:'9.8',machine:'x86_64'});assert.equal(g.controller_uid,65534);
 keys(g.inputs,INPUTS);for(const h of Object.values(g.inputs))assert(typeof h==='string'&&h.length===64&&hash.test(h));if(expectedInputs)assert.deepEqual(g.inputs,expectedInputs);
 assert(hash.test(g.nss_before_sha256)&&g.nss_before_sha256.length===64);assert.equal(g.nss_adapted_sha256,sha('passwd: files\ngroup: files\nshadow: files\nhosts: files\n'));
 keys(g.stock,['exit_code','body','raw_sha256','raw_base64','paths_unchanged']);const {paths_unchanged,...stock}=g.stock;assert.equal(paths_unchanged,true);const {exit_code,...stockHTTP}=stock;captured({...stockHTTP,status:exit_code},false,false);assert.equal(stock.exit_code,1);assert.equal(stock.body.ready,false);assert.equal(stock.body.read_only,true);assert.equal(stock.body.scope,'native_linux_controller_layout');
 assert(Array.isArray(g.accounts)&&g.accounts.length===2);const ids=g.accounts.map(a=>a.id);assert(new Set(ids).size===2);
 for(let i=0;i<2;i++){const a=g.accounts[i];keys(a,['$schema','id','username','domain','home','public_html','state','uid','gid','revision','created_at','updated_at']);assert.equal(a.$schema,'http://127.0.0.1:18391/Account.json');assert(id.test(a.id)&&a.id.length===32);assert.equal(a.username,(i?'wpb':'wpa')+nonce.slice(0,6));assert.equal(a.domain,a.username+'.example.test');assert.equal(a.home,'/run/wp'+nonce.slice(0,6)+'/homes/'+a.username);assert.equal(a.public_html,a.home+'/public_html');assert.equal(a.state,'active');assert.equal(a.revision,i?3:1);assert(Number.isSafeInteger(a.uid)&&a.uid>=1000&&a.uid!==65534);assert(Number.isSafeInteger(a.gid)&&a.gid>=1000);assert(Number.isFinite(Date.parse(a.created_at))&&Number.isFinite(Date.parse(a.updated_at)));}
 assert.equal(g.native_accounts.length,2);for(let i=0;i<2;i++)assert.deepEqual(g.native_accounts[i],{id:ids[i],uid:g.accounts[i].uid,gid:g.accounts[i].gid,home_mode:'0750',public_html_mode:'0750'});
 assert.deepEqual(g.cases.map(c=>c.id),CASES);
 for(const i of [0,1,6]){const c=g.cases[i];captured(c);assert.equal(c.status,i===1?401:503);keys(c.body,['type','title','status','detail','error','authenticated']);assert.equal(c.body.status,c.status);assert.equal(c.body.authenticated,false);assert.equal(c.body.type,'about:blank');assert.equal(c.body.error,i===1?'unauthorized':'web_preview_unavailable');assert(typeof c.body.detail==='string'&&c.body.detail.length<500);}
 assert.deepEqual(g.cases[2],{id:'wrong_peer',refused:true,peer_uid:0});
 for(const i of [3,4]){captured(g.cases[i]);assert.equal(g.cases[i].status,200);validatePreview(g.cases[i].body,i===3?[ids[0]]:ids);}
 const before=g.cases[3].body,after=g.cases[4].body;assert.equal(before.profile_sha256,after.profile_sha256);assert.notEqual(before.snapshot_sha256,after.snapshot_sha256);assert.notEqual(before.bundle_sha256,after.bundle_sha256);
 captured(g.cases[5],true);assert.equal(g.cases[5].exit_code,0);assert.deepEqual(g.cases[5].body,after);captured(g.direct_peer,false,false);assert.equal(g.direct_peer.status,200);assert.deepEqual(g.direct_peer.body,before);
 assert.deepEqual(g.runtime_paths,RUNTIME.map(path=>({path,before:'missing',after:'missing'})));assert.equal(g.stock_mail_defaults_unchanged,true);assert.equal(g.owned_children_exited,true);
 return g;
}
export function decodePreviewSerial(serial,nonce,expectedInputs){
 assert(typeof nonce==='string'&&nonce.length===32&&id.test(nonce));assert(Buffer.byteLength(serial)<=2*1024*1024);
 const clean=new TextDecoder('utf-8',{fatal:true}).decode(serial).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replaceAll('\r','');
 const begin='\nSIFRUNO_WEB_PREVIEW_BEGIN_'+nonce+'\n',end='\nSIFRUNO_WEB_PREVIEW_END_'+nonce+'\n',exit='SIFRUNO_WEB_PREVIEW_EXIT_'+nonce+'_0';
 assert.equal(clean.split(begin).length,2);assert.equal(clean.split(end).length,2);const a=clean.indexOf(begin)+begin.length,b=clean.indexOf(end);assert(b>=a);
 const raw=clean.slice(a,b).trimEnd();assert(Buffer.byteLength(raw)<=131072);const value=JSON.parse(raw);assert.equal(JSON.stringify(value),raw);
 assert.deepEqual(clean.split('\n').filter(l=>l.startsWith('SIFRUNO_WEB_PREVIEW_EXIT_')),[exit]);assert(clean.indexOf('\n'+exit+'\n')>=b+end.length-1);
 return validateGuest(value,nonce,expectedInputs);
}
