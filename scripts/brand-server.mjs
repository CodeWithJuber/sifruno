import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.md': 'text/plain; charset=utf-8', '.zip': 'application/zip', '.txt': 'text/plain; charset=utf-8' };
const allowedFiles = new Set(['docs/brand-guidelines.md', 'deliverables/sifruno-brand-kit.zip', 'assets/design-tokens.json', 'assets/design-tokens.css']);
export function brandServer() {
  return createServer(async (req, res) => {
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, { Allow: 'GET, HEAD' }); res.end(); return; }
    let name;
    try { name = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname).replace(/^\/+/, ''); }
    catch { res.writeHead(400); res.end('Invalid URL'); return; }
    if (name === '') { res.writeHead(302, { Location: '/assets/brand/index.html' }); res.end(); return; }
    const path = resolve(root, name);
    const relative = path.slice(root.length + 1).split(sep).join('/');
    if (!path.startsWith(root + sep) || name.includes('\\') || name.split('/').some(p => p.startsWith('.')) || !(relative.startsWith('assets/brand/') || allowedFiles.has(relative))) {
      res.writeHead(404); res.end('Not found'); return;
    }
    try {
      const info = await stat(path);
      if (!info.isFile()) throw new Error('Not a file');
      const data = req.method === 'HEAD' ? null : await readFile(path);
      res.writeHead(200, {
        'Content-Type': types[extname(path)] ?? 'application/octet-stream',
        'Content-Length': info.size, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-cache',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
      }); res.end(data);
    } catch { res.writeHead(404); res.end('Not found'); }
  });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.SIFRUNO_BRAND_PORT ?? 4173);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid preview port');
  const server = brandServer();
  server.on('error', e => { console.error(e.message); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => console.log(`Sifruno brand preview: http://127.0.0.1:${port}`));
}
