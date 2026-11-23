import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmod, copyFile, lstat, mkdir, readFile, readdir, realpath, rename, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {commandsForTarget, commandMetadata, executableFixup, layoutQuickstart} from './runtime-package.mjs';
import { configure, Uint8ArrayReader, Uint8ArrayWriter, ZipReader, ZipWriter } from '@zip.js/zip.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const go = join(root, '.tools', 'go', 'bin', process.platform === 'win32' ? 'go.exe' : 'go');
const minimumSource = 'https://go.dev/wiki/MinimumRequirements';
const allTargets = ['windows-amd64', 'windows-arm64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64'];
const minimum = {
  windows: 'Windows 10 or later / Windows Server 2016 or later',
  linux: 'Linux kernel 3.2 or later; qualifying distro and filesystem tests still required',
  darwin: 'macOS 13 Ventura or later',
};
const hostOS = { win32: 'windows', linux: 'linux', darwin: 'darwin' }[process.platform] ?? process.platform;
const hostArch = { x64: 'amd64', arm64: 'arm64' }[process.arch] ?? process.arch;
const sha256 = value => createHash('sha256').update(value).digest('hex');
const normalized = value => value.split(sep).join('/');

function args(values) {
  const options = { dryRun: false, selfCheck: false, targets: [] };
  for (let i = 0; i < values.length; i++) {
    if (values[i] === '--dry-run') options.dryRun = true;
    else if (values[i] === '--self-check') options.selfCheck = true;
    else if (values[i] === '--target' && allTargets.includes(values[i + 1])) options.targets.push(values[++i]);
    else throw new Error('Usage: node scripts/build-runtime.mjs [--dry-run|--self-check] [--target windows-amd64|windows-arm64|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64]');
  }
  if (!options.targets.length) options.targets = [...allTargets];
  if (new Set(options.targets).size !== options.targets.length) throw new Error('Duplicate target');
  return options;
}

function environment(target) {
  const [os, arch] = target.split('-');
  const child = {};
  for (const name of ['PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'LANG', 'LC_ALL']) {
    if (process.env[name] !== undefined) child[name] = process.env[name];
  }
  return { ...child, GOOS: os, GOARCH: arch, GOAMD64: 'v1', GOARM64: 'v8.0', CGO_ENABLED: '0',
    GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off', GOENV: 'off', GOFLAGS: '', GOEXPERIMENT: '',
    GOCACHE: join(root, '.cache', 'go-build'), GOMODCACHE: join(root, '.cache', 'go-mod') };
}

function run(command, argv, env) {
  const result = spawnSync(command, argv, { cwd: root, env, encoding: 'utf8', shell: false,
    windowsHide: true, maxBuffer: 8 * 1024 * 1024, timeout: 10 * 60 * 1000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Build command failed (${result.status}): ${argv[0]}\n${result.stderr ?? ''}`);
  return result.stdout ?? '';
}

async function files(directory) {
  const list = [];
  async function walk(path) {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error(`Symlink is not allowed in runtime inputs: ${normalized(relative(root, path))}`);
    if (info.isDirectory()) {
      for (const name of (await readdir(path)).sort()) await walk(join(path, name));
    } else if (info.isFile()) list.push(path);
    else throw new Error('Only regular files and directories can be packaged');
  }
  await walk(directory);
  return list;
}

async function safeDirectory(directory) {
  const subpath = relative(root, resolve(directory));
  assert(subpath && !subpath.startsWith('..') && !subpath.includes(':'), 'Output path must stay in this workspace');
  let current = root;
  for (const component of subpath.split(sep)) {
    current = join(current, component);
    let info;
    try { info = await lstat(current); }
    catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(current); info = await lstat(current); }
    assert(info.isDirectory() && !info.isSymbolicLink(), 'Runtime output directories must not be symlinks');
  }
}

async function fingerprint() {
  const inputs = ['cmd', 'internal', 'config', 'web/dist', 'web/src', 'web/licenses', 'lab/fixtures'];
  const listing = [];
  for (const input of inputs) {
    for (const path of await files(join(root, input))) {
      if (!input.startsWith('web/') && !input.startsWith('lab/') && !/\.(go|json)$/.test(path)) continue;
      listing.push({ path: normalized(relative(root, path)), sha256: sha256(await readFile(path)) });
    }
  }
  for (const name of ['.gitattributes', 'LICENSE', 'LICENSING.md', 'go.mod', 'go.sum', 'package.json', 'package-lock.json', 'web/package.json', 'web/package-lock.json', 'web/vite.config.ts', 'web/NOTICE.md', 'scripts/build-runtime.mjs', 'scripts/build-runtime.ps1', 'scripts/runtime-package.mjs']) listing.push({ path: name, sha256: sha256(await readFile(join(root, name))) });
  listing.sort((a, b) => a.path.localeCompare(b.path, 'en'));
  return { sha256: sha256(JSON.stringify(listing)), files: listing };
}

async function copyTree(source, destination) {
  for (const path of await files(source)) {
    const target = join(destination, relative(source, path));
    await mkdir(dirname(target), { recursive: true });
    await copyFile(path, target);
  }
}

async function notices(destination, target) {
  const index = [];
  async function licenses(directory, label, metadata) {
    const names = (await readdir(directory)).filter(name => /^(license|licence|copying|notice)(\.|$|-)/i.test(name)).sort();
    if (!names.length) throw new Error(`License notice is missing for ${label}`);
    const copied = [];
    for (const name of names) {
      const source = join(directory, name);
      const info = await lstat(source);
      if (!info.isFile() || info.isSymbolicLink()) continue;
      const output = join(destination, label, name);
      await mkdir(dirname(output), { recursive: true });
      await copyFile(source, output);
      copied.push(normalized(relative(destination, output)));
    }
    if (!copied.length) throw new Error(`No regular license file found for ${label}`);
    index.push({ ...metadata, files: copied });
  }
  await licenses(join(root, '.tools/go'), 'go', { name: 'Go', source: 'https://go.dev' });
  const mods = run(go, ['list', '-mod=readonly', '-buildvcs=false', '-deps', '-f', '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}', ...commandsForTarget(target).map(command => `./cmd/${command}`)], environment(target));
  for (const line of [...new Set(mods.split(/\r?\n/).filter(Boolean))].sort()) {
    const [name, version, directory] = line.split('|');
    if (!version) continue;
    await licenses(directory, `go-modules/${name.replaceAll('/', '__')}@${version}`, { name, version, source: 'Go module build dependency' });
  }
  // Include licenses for actual UI imports and their runtime dependency closure.
  // shadcn CLI is a build tool; its MIT license is retained for generated source.
  const queue = ['react', 'react-dom', '@astryxdesign/core', '@astryxdesign/theme-neutral', '@stylexjs/stylex', '@base-ui/react', '@tanstack/react-router', 'lucide-react', 'class-variance-authority', 'cn', 'tw-animate-css', 'tailwindcss'];
  const seen = new Set();
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    const directory = join(root, 'web/node_modules', name);
    const pkg = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
    const metadata = { name: pkg.name, version: pkg.version, declared_license: pkg.license };
    const hasNotice = (await readdir(directory)).some(file => /^(license|licence|copying|notice)(\.|$|-)/i.test(file));
    const upstreamNotices = { '@astryxdesign/core': ['astryx', 'facebook/astryx'], '@astryxdesign/theme-neutral': ['astryx', 'facebook/astryx'], '@stylexjs/stylex': ['stylex', 'facebook/stylex'] };
    if (!hasNotice && upstreamNotices[name]) {
      // These exact npm distributions omit LICENSE. Preserve the official
      // commit-pinned upstream notice; unknown packages still fail closed.
      const [noticeFolder, repository] = upstreamNotices[name];
      const noticeDirectory = join(root, 'web/licenses', noticeFolder);
      const provenanceBytes = await readFile(join(noticeDirectory, 'provenance.json'));
      assert(provenanceBytes.length < 64 * 1024, 'Upstream license provenance exceeds bounds');
      const provenance = JSON.parse(provenanceBytes);
      assert(pkg.license === 'MIT' && provenance.packages?.some(item => item.name === name && item.version === pkg.version), 'UI package version lacks matching license provenance');
      assert(/^[a-f0-9]{40}$/.test(provenance.source_commit) && provenance.source_url === `https://raw.githubusercontent.com/${repository}/${provenance.source_commit}/LICENSE`, 'Upstream license source is not commit-pinned');
      const noticeBytes = await readFile(join(noticeDirectory, 'LICENSE'));
      assert(noticeBytes.length < 8192 && sha256(noticeBytes) === provenance.sha256 && noticeBytes.toString('utf8').startsWith('MIT License'), 'Upstream license checksum/content mismatch');
      await licenses(noticeDirectory, `ui/${name.replaceAll('/', '__')}`, { ...metadata, notice_source: provenance.source_url, notice_sha256: provenance.sha256 });
    } else {
      await licenses(directory, `ui/${name.replaceAll('/', '__')}`, metadata);
    }
    queue.push(...Object.keys(pkg.dependencies ?? {}).filter(dep => !dep.startsWith('@types/')));
  }
  for (const [name, directory] of [['shadcn', join(root, 'web/node_modules/shadcn')], ['zip.js-build-tool', join(root, 'node_modules/@zip.js/zip.js')]]) {
    const pkg = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
    await licenses(directory, `build-tools/${name}`, { name: pkg.name, version: pkg.version, declared_license: pkg.license });
  }
  await writeFile(join(destination, 'index.json'), JSON.stringify(index, null, 2) + '\n');
}

function quickstart(target) {
  const [os] = target.split('-');
  const windows = os === 'windows';
  const server = windows ? '.\\bin\\sifruno.exe' : './bin/sifruno';
  const cli = windows ? '.\\bin\\panelctl.exe' : './bin/panelctl';
  return `# Sifruno local workbench — ${target}

This archive contains a CGO-free monitoring panel, CLI, read-only preview proxy and optional account broker, built for ${target}.
Minimum Go 1.27 OS runtime: ${minimum[os]}. CPU baseline: ${target.endsWith('amd64') ? 'GOAMD64=v1' : 'GOARM64=v8.0'}.
Reference: ${minimumSource}

Build verification is recorded in verification-matrix.json. Cross-compilation and
package-integrity checks are not runtime tests. No full panel compatibility is
certified. Native runtime, filesystem, upgrade and recovery checks remain per OS.
No code signing, notarization, installer/service integration or automatic start
is supplied. Older operating systems remain connector candidates, not supported
native targets. Original cPanel/vendor hosting execution requires a qualified
Linux host or guest; ARM hosting translation is unverified.

Extract into a directory you own. Open a terminal in this extracted root.
${windows ? 'Use PowerShell. If your system blocks unsigned downloads, review its policy and these hashes before making a local execution decision.' : executableFixup(target)}

\`\`\`${windows ? 'powershell' : 'sh'}
${cli} status
${cli} platform
${cli} evidence compare fixtures/synthetic-reference.json fixtures/synthetic-candidate.json
${server} --listen 127.0.0.1:8080 --ui web/dist --state .state/sifruno
\`\`\`

Open http://127.0.0.1:8080 on the same machine. Stop the server with Ctrl+C.
The server requires loopback binding. It creates private local state on first
use; no state, encryption keys, credentials or real host capture is included.
Accounts requires an explicitly configured local Linux root broker and a separate
nonroot controller identity. Windows/macOS broker execution is unavailable. The
native account slice creates an OS identity/home only; domain is reserved metadata.
It requires declared dedicated directories and files-only passwd/group/shadow NSS.
Root-owned /etc/default/useradd must explicitly set CREATE_MAIL_SPOOL=no.
No host policy is rewritten automatically. Account expiry is not full hosting
suspension. No production installer, remote connector or cPanel parity is supplied.
${layoutQuickstart(target)}
Overview shows native CPU, memory, volumes, uptime and aggregate network data.
Services are read-only Windows SCM / Linux systemd observations; macOS service
inventory is explicitly unavailable. Unknown measurements stay unavailable.
Websites manages real app-owned static files with local operator sign-in,
revision/hash saves, suspend/resume and bounded ZIP backups/restores. Native
Sifruno v1 ZIPs can be downloaded and imported into a new static website through
the local UI, API or CLI. Original cPanel account restoration remains unimplemented.
For read-only original TAR/TAR.GZ characterization, run
${cli} backup inspect --from ORIGINAL.tar.gz --out NEW.jsonl
against a quiesced independent local archive. This streams hashes and metadata,
never extracts files or initializes panel state. Complete catalogs require full
archive/checksum validation. Limits:32GiB source,128GiB expanded,32GiB/file,
100000 entries,256MiB catalog and ten minutes. Authentic reference compatibility
remains unverified; a complete inventory is not a restored account. Open
.state/sifruno/operator/access.key privately on this server to sign in; never
send it through chat or public links. The native CLI reads that private key
automatically: run ${cli} --state .state/sifruno sites list in a second terminal
while the panel runs. The separate local website listener is 127.0.0.1:8082;
site-<id>.localhost aliases work locally. PHP, DNS, TLS, mail, databases and
OS-account provisioning are not supplied by this static website slice.
Optional panelpreview requires an explicit public IP and reachable firewall;
it permits monitoring GET/HEAD routes and excludes website/session APIs and
private trail/budget records.
It supplies no authentication, remote mutations or automatic firewall changes.
The evidence fixtures are synthetic and cannot count as observed parity.
AI budget is capped locally and all changes require approval; this workbench
does not call a paid model or execute hosting/vendor provisioning operations.

Verify every extracted file against manifest.json before running. sha256 entries
protect content integrity, not publisher identity. An archive checksum is also
provided next to the download and in the build index. Keep licenses/ and NOTICE.md.
`;
}

async function archive(directory, output, manifest) {
  configure({ useWebWorkers: false });
  const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false, level: 6 });
  const expected = new Map();
  for (const path of await files(directory)) {
    const name = normalized(relative(directory, path));
    assert(!name.startsWith('.') && !name.includes('/.') && !name.includes('node_modules') && !name.includes('..'), 'Unexpected private/runtime package path');
    const content = await readFile(path);
    expected.set(name, sha256(content));
    await writer.add(name, new Uint8ArrayReader(content), { lastModDate: new Date('2026-01-01T00:00:00Z'),
      msDosCompatible: false, unixMode: name.startsWith('bin/') ? 0o100755 : 0o100644, versionMadeBy: 0x031e });
  }
  const zip = await writer.close();
  const reader = new ZipReader(new Uint8ArrayReader(zip), { useWebWorkers: false });
  const entries = await reader.getEntries();
  assert.equal(entries.length, expected.size, 'Archive entries differ from staging files');
  for (const entry of entries) {
    assert(expected.has(entry.filename), 'Archive contains an unexpected file');
    const content = await entry.getData(new Uint8ArrayWriter(), { checkSignature: true });
    assert.equal(sha256(content), expected.get(entry.filename), 'Archived file checksum mismatch');
    if (entry.filename.startsWith('bin/')) assert.equal(entry.unixMode & 0o777, 0o755, 'Executable mode missing');
  }
  await reader.close();
  const partial = output + '.partial';
  await writeFile(partial, zip, { flag: 'wx' });
  await rename(partial, output);
  return { file: normalized(relative(root, output)), bytes: zip.length, sha256: sha256(zip),
    manifest_sha256: sha256(JSON.stringify(manifest, null, 2) + '\n'), archive_entries_verified: entries.length };
}

async function main() {
  const options = args(process.argv.slice(2));
  assert.equal(await realpath(root), root, 'Workspace root must be canonical');
  if (options.selfCheck) {
    const envBefore = { ...process.env };
    const directory = join(root, '.cache/runtime-builds', `self-check-${randomBytes(6).toString('hex')}`);
    const packageDir = join(directory, 'fixture');
    await safeDirectory(join(packageDir, 'bin'));
    await writeFile(join(packageDir, 'bin/probe'), 'Synthetic packaging probe; not an executable.\n');
    await writeFile(join(packageDir, 'manifest.json'), JSON.stringify({ synthetic: true, runtime_tested: false }));
    const result = await archive(packageDir, join(directory, 'synthetic-probe.zip'), { synthetic: true, runtime_tested: false });
    assert.equal(result.archive_entries_verified, 2);
    for (const target of allTargets) {
      const metadata = commandMetadata(target);
      assert.equal(metadata.included_commands.includes('hostsetup'), target.startsWith('linux-'));
      const guide = quickstart(target);
      assert.equal(guide.includes('./bin/hostsetup --plan '), target.startsWith('linux-'));
      assert.equal(guide.includes('./bin/hostsetup --apply '), target.startsWith('linux-'));
      assert.equal(guide.includes('bin/hostsetup'), target.startsWith('linux-'));
      assert(guide.includes('Cross-compilation and\npackage-integrity checks are not runtime tests.'));
    }
    assert.equal(environment('linux-arm64').GOARM64, 'v8.0');
    assert.equal(environment('windows-amd64').GOAMD64, 'v1');
    assert.equal(environment('darwin-arm64').CGO_ENABLED, '0');
    assert.equal(environment('linux-amd64').GOPROXY, 'off');
    // Never hand environment objects to assertion diagnostics: inherited
    // credentials must not appear in a failing test's formatted output.
    if (JSON.stringify({ ...process.env }) !== JSON.stringify(envBefore)) throw new Error('Caller environment was changed');
    console.log(JSON.stringify({ self_check: 'passed', synthetic: true, archive_entries_verified: 2, process_environment_unchanged: true }));
    return;
  }
  const version = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
  assert(/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version), 'Package version must be semver without shell characters');
  const goversion = run(go, ['version'], environment(options.targets[0])).trim();
  assert(/^go version go1\.27\.\d+ /.test(goversion), 'This matrix requires the pinned Go 1.27 workspace toolchain');
  const before = await fingerprint();
  assert(await lstat(join(root, 'web/dist/index.html')), 'Build web/dist first');
  const plan = { dry_run: options.dryRun, version, go: goversion, cgo_enabled: false,
    source_fingerprint: before.sha256, minimum_requirements_source: minimumSource,
    targets: options.targets.map(id => ({ id, cpu_baseline: id.endsWith('amd64') ? 'v1' : 'v8.0', minimum_runtime: minimum[id.split('-')[0]], ...commandMetadata(id), runtime_tested: false })) };
  if (options.dryRun) { console.log(JSON.stringify(plan, null, 2)); return; }
  const runID = new Date().toISOString().replaceAll(/[-:.TZ]/g, '') + '-' + randomBytes(4).toString('hex');
  const output = join(root, 'deliverables', 'runtime-builds', runID);
  const staging = join(root, '.cache', 'runtime-builds', runID);
  await safeDirectory(output);
  await safeDirectory(staging);
  await safeDirectory(join(root, '.cache/go-build'));
  await safeDirectory(join(root, '.cache/go-mod'));
  const matrix = allTargets.map(id => ({ id, compiled: options.targets.includes(id), runtime_tested: false,
    verification: options.targets.includes(id) ? 'cross-compiled; embedded Go build settings and archive contents checked' : 'not built in this run',
    native_host: id === `${hostOS}-${hostArch}`, minimum_runtime: minimum[id.split('-')[0]],
    cpu_baseline: id.endsWith('amd64') ? 'v1' : 'v8.0', ...commandMetadata(id), compatibility_certified: false }));
  const outputs = [];
  // Build the whole selected matrix before any archive can claim it compiled.
  for (const target of options.targets) {
    console.log(`Building ${target} (runtime execution remains untested by this builder)`);
    const [os, arch] = target.split('-');
    const directory = join(staging, target);
    await mkdir(join(directory, 'bin'), { recursive: true });
    for (const command of commandsForTarget(target)) {
      const binary = join(directory, 'bin', command + (os === 'windows' ? '.exe' : ''));
      run(go, ['build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', binary, `./cmd/${command}`], environment(target));
      const info = run(go, ['version', '-m', binary], environment(target));
      for (const setting of [`GOOS=${os}`, `GOARCH=${arch}`, 'CGO_ENABLED=0', arch === 'amd64' ? 'GOAMD64=v1' : 'GOARM64=v8.0']) assert(info.includes(setting), `Unexpected embedded binary setting: ${setting}`);
      await chmod(binary, 0o755);
    }
  }
  assert.equal((await fingerprint()).sha256, before.sha256, 'Source inputs changed during compilation; this run is not publishable');
  for (const target of options.targets) {
    const [, arch] = target.split('-');
    const directory = join(staging, target);
    await copyTree(join(root, 'web/dist'), join(directory, 'web/dist'));
    await mkdir(join(directory, 'fixtures'), { recursive: true });
    for (const name of ['synthetic-reference.json', 'synthetic-candidate.json']) await copyFile(join(root, 'lab/fixtures', name), join(directory, 'fixtures', name));
    await copyFile(join(root, 'web/NOTICE.md'), join(directory, 'NOTICE.md'));
    for (const name of ['LICENSE', 'LICENSING.md']) await copyFile(join(root, name), join(directory, name));
    await notices(join(directory, 'licenses'), target);
    await writeFile(join(directory, 'QUICKSTART.md'), quickstart(target));
    await writeFile(join(directory, 'verification-matrix.json'), JSON.stringify(matrix, null, 2) + '\n');
    const manifest = { schema_version: 1, product: 'Sifruno local control plane and compatibility workbench', version, target, go: goversion,
      cgo_enabled: false, cpu_baseline: arch === 'amd64' ? 'v1' : 'v8.0', input_fingerprint: before.sha256,
      build_verified: true, runtime_tested: false, compatibility_certified: false, ...commandMetadata(target), files: [] };
    for (const path of await files(directory)) { const content = await readFile(path); manifest.files.push({ path: normalized(relative(directory, path)), bytes: content.length, sha256: sha256(content) }); }
    await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
    const packed = await archive(directory, join(output, `sifruno-${version}-${target}.zip`), manifest);
    await writeFile(join(output, `sifruno-${version}-${target}.zip.sha256`), `${packed.sha256}  sifruno-${version}-${target}.zip\n`);
    outputs.push(packed);
  }
  assert.equal((await fingerprint()).sha256, before.sha256, 'Source inputs changed during build; this run is not publishable');
  const index = { ...plan, dry_run: false, run_id: runID, built_at: new Date().toISOString(),
    builder_host: { os: hostOS, arch: hostArch, node: process.version }, compatibility_certified: false,
    verification_matrix: matrix, archives: outputs };
  await writeFile(join(output, 'index.json'), JSON.stringify(index, null, 2) + '\n');
  await writeFile(join(output, 'input-manifest.json'), JSON.stringify(before, null, 2) + '\n');
  const latest = join(root, 'deliverables/runtime-builds/latest.json');
  const temporary = latest + `.${runID}.partial`;
  await writeFile(temporary, JSON.stringify({ run_id: runID, directory: normalized(relative(root, output)), index_sha256: sha256(JSON.stringify(index, null, 2) + '\n') }, null, 2) + '\n', { flag: 'wx' });
  await rename(temporary, latest);
  console.log(JSON.stringify({ archives: outputs.length, output: normalized(relative(root, output)), integrity_checked: true, runtime_tested: false, compatibility_certified: false }, null, 2));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
