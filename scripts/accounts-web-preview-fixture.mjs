// Local UI QA only. All account/session/preview data is synthetic; no broker or proxy is used.
// Build web/dist first, then run this file. Use the printed loopback URL with the in-app browser.
import { createServer } from 'node:http';
import { readFile, realpath } from 'node:fs/promises';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = await realpath(resolve(root, 'web/dist'));
let mode = 'valid', signedIn = true, generation = 1;
const pending = [];
const counters = { preview: 0, aborted: 0, released: 0, writes: 0 };
const account = (id, username, state) => ({ id: id.repeat(32), username, domain: `${username}.example.test`, home: `/home/${username}`, public_html: `/home/${username}/public_html`, state, uid: 1001 + id.charCodeAt(0) - 97, gid: 1001 + id.charCodeAt(0) - 97, revision: 3, created_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-02T11:00:00Z' });
const accounts = [account('a', 'atlas', 'active'), account('b', 'studio', 'active'), account('c', 'archive', 'suspended')];
const inventory = () => mode === 'empty' ? [] : accounts;
const session = () => ({ authenticated: true, csrf_token: `synthetic-only-csrf-${generation}`, expires_at: new Date(Date.now() + (mode === 'short-session' ? 5000 : 3600000)).toISOString() });
const preview = () => {
  const items = inventory(), active = items.filter(a => a.state === 'active');
  const file = (path, bytes) => ({ path, mode: 384, bytes, sha256: 'e'.repeat(64) });
  return { profile: 'restricted-chroot-v1', profile_sha256: 'd'.repeat(64), snapshot_sha256: 'b'.repeat(64), bundle_sha256: 'c'.repeat(64), accounts: items.length, active_accounts: active.length, suspended_accounts: items.length - active.length,
    files: [file('apache/front.conf', 384), ...active.flatMap(a => [file(`apache/backends/${a.id}.conf`, 1024), file(`fpm/${a.id}.conf`, 512)])] };
};
const json = (res, status, value) => { if (!res.destroyed) res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(value)); };
const modes = ['valid', 'deferred', 'deferred-401', 'unavailable', 'conflict', 'invalid', 'forbidden', 'empty', 'short-session'];
const controls = `<aside id="qa-controls" aria-label="Synthetic QA controls" style="padding:8px 16px;background:#fff5d9;color:#41300a;font:12px system-ui;border-bottom:1px solid #c9b983;display:flex;flex-wrap:wrap;align-items:center;gap:8px"><strong>Synthetic UI fixture · no server actions</strong><label>Response <select id="qa-mode">${modes.map(m => `<option>${m}</option>`).join('')}</select></label><button id="qa-set">Set response</button><button id="qa-release">Release pending preview</button><span id="qa-status" role="status">Ready</span></aside><script>
document.getElementById('qa-set').onclick = async () => { const value=document.getElementById('qa-mode').value; await fetch('/__qa__/mode',{method:'POST',body:value}); document.getElementById('qa-status').textContent='Fixture response: '+value; };
document.getElementById('qa-release').onclick = async () => { const r=await fetch('/__qa__/release',{method:'POST'}); const v=await r.json(); document.getElementById('qa-status').textContent='Released '+v.released+' pending response(s)'; };
</script>`;
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json' };
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const p = url.pathname, method = req.method;
    if (p === '/__qa__/stats' && method === 'GET') return json(res, 200, { fixture_only: true, mode, signedIn, pending: pending.length, ...counters });
    if (p === '/__qa__/mode' && method === 'POST') {
      let body=''; for await (const chunk of req) { body+=chunk; if(body.length>100) return json(res,413,{}); }
      if (!modes.includes(body)) return json(res, 400, {});
      mode=body; return json(res, 200, { mode });
    }
    if (p === '/__qa__/release' && method === 'POST') {
      const held=pending.splice(0); let released=0;
      for (const item of held) if(!item.res.destroyed) { json(item.res,item.status,item.body); counters.released++;released++; }
      return json(res,200,{released});
    }
    if (p === '/api/v1/session' && method === 'GET') return json(res, signedIn ? 200 : 401, signedIn ? session() : { authenticated: false });
    if (p === '/api/v1/session/login' && method === 'POST') {
      let body=''; for await (const chunk of req) {body+=chunk; if(body.length>1024) return json(res,413,{});}
      if (JSON.parse(body).access_key !== 'synthetic-only-operator-key') return json(res,401,{error:'unauthorized'});
      signedIn=true;generation++;return json(res,200,session());
    }
    if (p === '/api/v1/session/logout' && method === 'POST') {signedIn=false;return json(res,200,{authenticated:false});}
    if (p.startsWith('/api/v1/accounts')) {
      if(!signedIn) return json(res,401,{error:'unauthorized'});
      if(p === '/api/v1/accounts/capability' && method==='GET') return json(res,200,{available:true,reason:'',backend:'linux-local',restrictions:['domain_metadata_only','password_locked_and_nologin_in_all_states','no_cpanel_compatibility_certification']});
      if(p === '/api/v1/accounts' && method==='GET') return json(res,200,{items:inventory()});
      if(p === '/api/v1/accounts/web-preview' && method==='GET') {
        counters.preview++;
        if(mode.startsWith('deferred')) {
          if(pending.length>=8) return json(res,429,{error:'fixture_pending_limit'});
          const item={res,status:mode==='deferred-401'?401:200,body:mode==='deferred-401'?{error:'unauthorized'}:preview()};
          pending.push(item);
          res.once('close',()=>{if(!res.writableEnded)counters.aborted++;const i=pending.indexOf(item);if(i>=0)pending.splice(i,1);});return;
        }
        if(mode==='unavailable') return json(res,503,{error:'web_preview_unavailable'});
        if(mode==='conflict') return json(res,409,{error:'conflict'});
        if(mode==='forbidden') return json(res,403,{error:'forbidden'});
        if(mode==='invalid') return json(res,200,{...preview(),files:[{path:'unexpected.conf',mode:384,bytes:10,sha256:'e'.repeat(64)}]});
        return json(res,200,preview());
      }
      if(method==='POST'){counters.writes++;return json(res,409,{error:'conflict'});}
    }
    // Other dashboard monitoring is deliberately unavailable, never real host data.
    if (p.startsWith('/api/')) return json(res,503,{error:'synthetic_monitor_unavailable'});
    if(method!=='GET'&&method!=='HEAD') return json(res,405,{});
    const name = decodeURIComponent(p === '/' ? '/index.html' : p);
    const file = resolve(dist, '.'+name), rel=relative(dist,file);
    if(!rel||isAbsolute(rel)||rel.split(sep).includes('..')) return json(res,404,{});
    const real=await realpath(file), realRel=relative(dist,real);
    if(isAbsolute(realRel)||realRel.split(sep).includes('..')) return json(res,404,{});
    let bytes=await readFile(real);
    if(name==='/index.html') bytes=Buffer.from(bytes.toString().replace('<body>', '<body>'+controls));
    res.writeHead(200,{'content-type':mime[extname(file)]||'application/octet-stream','cache-control':'no-store'}).end(method==='HEAD'?undefined:bytes);
  } catch { json(res,404,{error:'fixture_route_missing'}); }
});
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({url:`http://127.0.0.1:${server.address().port}`,fixture_only:true,dist})));
process.on('SIGINT',()=>{
  for(const item of pending.splice(0))item.res.destroy();
  server.close(()=>process.exit(0));server.closeAllConnections();
});
