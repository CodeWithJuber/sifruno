// Trusted offline guest coordinator; compilation and native qualification are separate.
// Reuses the image, QEMU, clean environment and CIDATA admission from the account lab.
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const imageSource = '.tools/linuxguest/alma9/AlmaLinux-9-GenericCloud-9.8-20260810.x86_64.qcow2';
const imageSHA = '6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b';
const signer = 'BF18AC2876178908D6E71267D36CB86CB86B3716';
const qdir = path.join(root, '.tools/linuxguest/qemu-20260811');
const MAX_FILE = 64 * 1024 * 1024;
const phase = process.argv[2];
assert(['resolve', 'install', 'qualify'].includes(phase), 'Fixed resolve/install/qualify phase required');
const flags = {};
for (let i = 3; i < process.argv.length; i += 2) {
  const flag = process.argv[i], value = process.argv[i + 1];
  assert(['--repository-run', '--prepared-run'].includes(flag) && !flags[flag]);
  assert(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(value));
  flags[flag] = value;
}
assert(flags['--repository-run'] && (phase === 'qualify' ? flags['--prepared-run'] : !flags['--prepared-run']));

function input(relative, maximum = MAX_FILE) {
  assert(typeof relative === 'string' && /^[A-Za-z0-9_.+/-]+$/.test(relative));
  assert(!path.posix.isAbsolute(relative) && !relative.split('/').some(p => p === '' || p === '.' || p === '..'));
  const p = path.join(root, ...relative.split('/'));
  const info = fs.lstatSync(p);
  assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size <= maximum);
  assert(fs.realpathSync(p) === p);
  return p;
}
function json(relative, maximum = 64 * 1024) { return JSON.parse(fs.readFileSync(input(relative, maximum), 'utf8')); }
const original = input(imageSource, 700 * 1024 * 1024);
assert.equal(sha(fs.readFileSync(original)), imageSHA);
const verified = json('.tools/linuxguest/alma9/verified.json');
assert(verified.checksum_signature_verified && verified.signer_fingerprint === signer && verified.sha256 === imageSHA);
for (const file of json('.tools/linuxguest/prepared.json').files) assert.equal(sha(fs.readFileSync(input(file.path))), file.sha256);
const qemuImage = input('.tools/linuxguest/qemu-20260811/qemu-img.exe');
assert.equal(sha(fs.readFileSync(qemuImage)), '9d930582d0d574bb106d89982c547688e10b8f356192d302cc3d0ae4e8674534');

const repoRoot = `.cache/alma-web-repositories/${flags['--repository-run']}`;
const manifestSource = `${repoRoot}/manifest.json`, repository = json(manifestSource);
assert(repository.schema_version === 1 && repository.kind === 'alma-web-repository-stage');
assert(repository.release === '9.8' && repository.architecture === 'x86_64' && repository.cloud_image_sha256 === imageSHA);
assert(repository.signing_key_fingerprint === signer && repository.repositories.length === 2);
assert.deepEqual(repository.repositories.map(r => r.id).sort(), ['AppStream', 'BaseOS']);
const run = `web-${phase}-${Date.now()}-${randomBytes(4).toString('hex')}`;
const relative = `.cache/alma-web-runtime/${run}`, work = path.join(root, ...relative.split('/'));
fs.mkdirSync(work, {recursive: true});
assert.equal(fs.realpathSync(work), work);
const entries = [];
function entry(source, destination, expected, size) {
  const p = input(source), bytes = fs.readFileSync(p), digest = sha(bytes);
  if (expected) assert.equal(digest, expected);
  if (size !== undefined) assert.equal(bytes.length, size);
  assert(!entries.some(e => e.destination === destination));
  entries.push({source, destination, bytes: bytes.length, sha256: digest});
}
entry(manifestSource, 'payload/repository-manifest.json');
for (const repo of repository.repositories) {
  assert(repo.base_url === `https://repo.almalinux.org/almalinux/9.8/${repo.id}/x86_64/os/`);
  // DNF also reads advisory and group metadata from the signed/checksummed
  // repomd inventory even when resolving only the fixed package goals.
  assert(Array.isArray(repo.files) && repo.files.length >= 4 && repo.files.length <= 33);
  for (const f of repo.files) {
    assert(/^repodata\/[A-Za-z0-9_.+-]+$/.test(f.relative_path) && /^[a-f0-9]{64}$/.test(f.checksum_sha256));
    entry(`${repoRoot}/repositories/${repo.id}/${f.relative_path}`, `repositories/${repo.id}/${f.relative_path}`, f.checksum_sha256, f.length);
  }
}
let backingSource = imageSource, backingSHA = imageSHA, packageManifest = null;
if (phase !== 'resolve') {
  const source = `${repoRoot}/payload/package-manifest.json`, packages = json(source);
  assert(packages.kind === 'alma-web-rpm-stage' && packages.cloud_image_sha256 === imageSHA && packages.signing_key_fingerprint === signer);
  assert(Array.isArray(packages.packages) && packages.packages.length > 0 && packages.packages.length <= 200);
  entry(source, 'payload/package-manifest.json');
  entry(`${repoRoot}/payload/resolve-report.json`, 'payload/resolve-report.json');
  for (const p of packages.packages) {
    assert(/^packages\/[A-Za-z0-9_.+-]+\.rpm$/.test(p.file));
    assert(/^[a-f0-9]{64}$/.test(p.checksum_sha256));
    entry(`${repoRoot}/${p.file}`, p.file, p.checksum_sha256, p.size);
  }
  packageManifest = {source, sha256: sha(fs.readFileSync(input(source))), packages: packages.packages.length};
}
if (phase === 'qualify') {
  assert(/^web-install-/.test(flags['--prepared-run']));
  const preparedSource = `artifacts/runtime/alma-web-runs/${flags['--prepared-run']}/host-report.json`;
  const prepared = json(preparedSource, 256 * 1024);
  assert(prepared.phase === 'install' && prepared.passed === true && prepared.external_nic === false && prepared.host_shares === false);
  assert(prepared.image_sha256 === imageSHA && prepared.package_manifest?.sha256 === packageManifest.sha256);
  backingSource = `.cache/alma-web-runtime/${flags['--prepared-run']}/guest.qcow2`;
  backingSHA = prepared.overlay_sha256;
  assert(/^[a-f0-9]{64}$/.test(backingSHA));
  assert.equal(sha(fs.readFileSync(input(backingSource, 2 * 1024 * 1024 * 1024))), backingSHA);
  const bins = {
    sifruno: 'd75426f7e1358b175e544c60667ef3b028bba2c75996d50b59684a03e7db01ad',
    panelctl: '18a4b4e45c24e0045d5c4a86a7f99d19544a4f2d8cbd515c86ec0f319d34e07b',
    hostbroker: 'eb19376976893b9cd2b948176c874b692d8541a82d377c906c7ade6432e94760',
  };
  for (const [name, digest] of Object.entries(bins)) entry(`.cache/alma9-account-payload-policy-v4/${name}`, `payload/${name}`, digest);
  entry('.cache/alma-web-payload/web-render', 'payload/web-render');
  entry('lab/web_runtime_fixture.py', 'payload/qualifier.py');
} else entry('lab/web_package_prepare.py', 'payload/prepare.py');

const sourceFiles = ['scripts/alma-web-runtime.mjs', 'scripts/alma-web-iso.py',
  phase === 'qualify' ? 'lab/web_runtime_fixture.py' : 'lab/web_package_prepare.py'];
if (phase === 'qualify') {
  sourceFiles.push('lab/hostweb-render/main.go');
  for (const name of fs.readdirSync(path.join(root, 'internal/hostweb')).filter(n => /\.(go|md)$/.test(n))) sourceFiles.push(`internal/hostweb/${name}`);
}
const sourcePins = sourceFiles.map(source => ({source, sha256: sha(fs.readFileSync(input(source)))}));
const env = {};
for (const name of ['SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA']) if (process.env[name] !== undefined) env[name] = process.env[name];
env.PATH = qdir + ';' + path.join(env.SystemRoot ?? env.SYSTEMROOT, 'System32');
const overlay = path.join(work, 'guest.qcow2');
const made = spawnSync(qemuImage, ['create', '-f', 'qcow2', '-F', 'qcow2', '-b', input(backingSource, 2 * 1024 * 1024 * 1024), overlay],
  {cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 30000, maxBuffer: 65536});
assert.equal(made.status, 0);
const reportName = `${phase}-report.json`;
const script = `#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
trap '/sbin/poweroff' EXIT
mkdir -p /mnt/sifruno-web-payload /opt/sifruno-web-qualification
mount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-web-payload
cp /mnt/sifruno-web-payload/payload/* /opt/sifruno-web-qualification/
chmod 0555 /opt/sifruno-web-qualification/*.py
${phase === 'qualify' ? 'chmod 0555 /opt/sifruno-web-qualification/sifruno /opt/sifruno-web-qualification/panelctl /opt/sifruno-web-qualification/hostbroker /opt/sifruno-web-qualification/web-render' : ''}
printf 'trusted-disposable-alma9-web\\n' >/run/sifruno-web-admission
chmod 0600 /run/sifruno-web-admission
set +e
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C ${phase === 'qualify' ? '' : '/usr/bin/setpriv --bounding-set=-net_admin,-net_raw,-net_bind_service,-net_broadcast -- '}/usr/bin/python3 /opt/sifruno-web-qualification/${phase === 'qualify' ? 'qualifier.py --disposable-alma-guest --qualification-files-only-nss --qualification-no-mail-spool-default' : `prepare.py --phase ${phase}`} --report /opt/sifruno-web-qualification/${reportName}
fixture_status=$?
echo SIFRUNO_WEB_REPORT_BEGIN_${run}
if test -f /opt/sifruno-web-qualification/${reportName}; then cat /opt/sifruno-web-qualification/${reportName}; fi
echo
echo SIFRUNO_WEB_REPORT_END_${run}
echo SIFRUNO_WEB_FIXTURE_EXIT_$fixture_status
`;
fs.writeFileSync(path.join(work, 'meta-data'), `instance-id: ${run}\nlocal-hostname: sifruno-web-qualification\n`, {flag: 'wx'});
fs.writeFileSync(path.join(work, 'network-config'), 'version: 2\nethernets: {}\n', {flag: 'wx'});
fs.writeFileSync(path.join(work, 'user-data'), '#cloud-config\nusers: []\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-web-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n' + script.split('\n').map(line => '      ' + line).join('\n') + '\nruncmd:\n  - ["/bin/sh", "/root/sifruno-web-proof.sh"]\n', {flag: 'wx'});
for (const name of ['user-data', 'meta-data', 'network-config']) entry(`${relative}/${name}`, name);
const plan = {schema_version: 1, phase, entries};
fs.writeFileSync(path.join(work, 'payload-plan.json'), JSON.stringify(plan, null, 2) + '\n', {flag: 'wx'});
const planSHA = sha(fs.readFileSync(input(`${relative}/payload-plan.json`, 256 * 1024)));
const python = path.join(env.LOCALAPPDATA, 'Programs/Python/Python312/python.exe');
const iso = spawnSync(python, ['-I', input('scripts/alma-web-iso.py'), '--plan', `${relative}/payload-plan.json`],
  {cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 90000, maxBuffer: 65536});
assert.equal(iso.status, 0, iso.stderr);
const isoResult = JSON.parse(iso.stdout);
const args = ['-L', path.join(qdir, 'share'), '-machine', 'pc', '-accel', 'tcg,thread=single', '-cpu', 'max', '-smp', '1', '-m', '1536',
  '-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-vga', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
  '-object', 'rng-builtin,id=rng0', '-device', 'virtio-rng-pci,rng=rng0', '-drive', `file=${overlay},if=virtio,format=qcow2,index=0`,
  '-drive', `file=${path.join(work, 'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
const started = new Date().toISOString();
const child = spawn(input('.tools/linuxguest/qemu-20260811/qemu-system-x86_64.exe'), args,
  {cwd: qdir, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
const fd = fs.openSync(path.join(work, 'serial.log'), 'wx');
let serial = '', count = 0, outputLimit = false, timedout = false;
const timer = setTimeout(() => { timedout = true; child.kill(); }, 600000);
const capture = bytes => {
  if (outputLimit) return;
  if (count + bytes.length > 2 * 1024 * 1024) { outputLimit = true; child.kill(); return; }
  count += bytes.length; serial += bytes.toString('utf8'); fs.writeSync(fd, bytes);
  if (serial.includes('Kernel panic - not syncing') || serial.includes('Fatal glibc error')) child.kill();
};
child.stdout.on('data', capture); child.stderr.on('data', capture);
console.log(JSON.stringify({started: true, phase, run_id: run, pid: child.pid, inputs: entries.length, external_nic: false, host_shares: false}));
let result;
try { result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({code, signal})); }); }
finally { clearTimeout(timer); fs.closeSync(fd); }
const clean = serial.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r/g, '');
const begin = `SIFRUNO_WEB_REPORT_BEGIN_${run}\n`, end = `\nSIFRUNO_WEB_REPORT_END_${run}`;
const a = clean.indexOf(begin), b = clean.indexOf(end, a + begin.length);
let guest = null, guestReportError = null;
if (a >= 0 && b > a) { try { guest = JSON.parse(clean.slice(a + begin.length, b).trim()); } catch { guestReportError = 'invalid_guest_json'; } }
else guestReportError = 'missing_guest_report';
let stable = false;
try {
  stable = entries.every(e => sha(fs.readFileSync(input(e.source))) === e.sha256) && sourcePins.every(e => sha(fs.readFileSync(input(e.source))) === e.sha256)
    && sha(fs.readFileSync(input(`${relative}/payload-plan.json`, 256 * 1024))) === planSHA
    && sha(fs.readFileSync(input(backingSource, 2 * 1024 * 1024 * 1024))) === backingSHA && sha(fs.readFileSync(original)) === imageSHA;
} catch {}
const fixturePassed = /^SIFRUNO_WEB_FIXTURE_EXIT_0$/m.test(clean);
const passed = result.code === 0 && !outputLimit && !timedout && stable && fixturePassed && guest?.passed === true;
const record = {schema_version: 1, run_id: run, phase, passed, started_at: started, checked_at: new Date().toISOString(), ...result,
  timedout, output_limit: outputLimit, serial_bytes: count, input_stable: stable, guest_report_error: guestReportError, source_pins: sourcePins,
  image_sha256: imageSHA, image_checksum_signature_verified: true, backing_source: backingSource, backing_sha256: backingSHA,
  overlay_sha256: sha(fs.readFileSync(overlay)), payload_sha256: isoResult.sha256, payload_plan_sha256: planSHA, package_manifest: packageManifest,
  entries, qemu_args: args, external_nic: false, host_shares: false, hostile_guest_isolation_certified: false, global_install: false,
  production_mutated: false, cpanel_compatibility_certified: false};
const output = path.join(root, 'artifacts/runtime/alma-web-runs', run);
fs.mkdirSync(output, {recursive: true});
fs.writeFileSync(path.join(output, 'host-report.json'), JSON.stringify(record, null, 2) + '\n', {flag: 'wx'});
if (guest) {
  const encoded = JSON.stringify(guest, null, 2) + '\n';
  fs.writeFileSync(path.join(output, `${phase}-report.json`), encoded, {flag: 'wx'});
  // Host package admission reads only the bounded cache report, never arbitrary artifacts.
  fs.writeFileSync(path.join(work, `${phase}-report.json`), encoded, {flag: 'wx'});
}
console.log(JSON.stringify({passed, phase, run_id: run, guest_passed: guest?.passed ?? false, guest_failure: guest?.failure ?? guest?.failure_code ?? null,
  evidence: path.relative(root, output)}));
if (!passed) process.exitCode = 1;
