import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {digest, regular, pin, relative, portableSource, validateLayout, parseSerial, qemuArgs, createCapture} from './admission.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const owner = path.resolve(here, '../..');
const pins = JSON.parse(fs.readFileSync(path.join(here, 'pins.json')));

export function admit(primary) {
  assert.equal(process.platform, 'win32', 'This host harness is Windows/QEMU only');
  primary = validateLayout(primary, owner, here);
  const inventory = [];
  const add = (item, maximum) => { const found = pin(primary, item, maximum); inventory.push(found); return found; };
  pin(owner, pins.worker_dependency_catalog);
  const workerDependencies = JSON.parse(fs.readFileSync(regular(owner, pins.worker_dependency_catalog.path)));
  assert(workerDependencies.schema_version === 1 && workerDependencies.kind === 'worker-freeze2-local-dependencies' && workerDependencies.files.length === 25);
  const seenDependencies = new Set();
  for (const f of workerDependencies.files) {
    assert(/^(?:go\.(?:mod|sum)|internal\/(?:hostaccounts|hostweb|hostwebgeneration|securestate)\/[A-Za-z0-9_.-]+\.go)$/.test(f.path) && !seenDependencies.has(f.path));
    seenDependencies.add(f.path);
    add({...f, path: '.worktrees/native-web-executor-sol/' + f.path});
  }
  for (const key of ['prepared', 'verified', 'qemu_img', 'qemu', 'wheel', 'worker_manifest', 'review_manifest', 'review_overlay', 'review_report', 'historical_review_report', 'historical_review_manifest', 'historical_review_elf']) add(pins[key]);
  assert.equal(pins.historical_review_elf.sha256, pins.tests[1].sha256, 'Fresh/historical review ELF identity must agree');
  add(pins.image, 700 * 1024 * 1024);
  for (const t of pins.tests) {
    add(t);
    const b = fs.readFileSync(regular(primary, t.path));
    assert(b.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) && b[4] === 2 && b[5] === 1 && b.readUInt16LE(18) === 62, 'Linux amd64 ELF required');
  }
  const read = entry => JSON.parse(fs.readFileSync(regular(primary, entry.path), 'utf8'));
  const verified = read(pins.verified);
  assert(verified.checksum_signature_verified === true && verified.signer_fingerprint === 'BF18AC2876178908D6E71267D36CB86CB86B3716' && verified.sha256 === pins.image.sha256);
  const prepared = read(pins.prepared);
  assert(prepared.schema_version === 1 && prepared.files.length > 50 && prepared.files.length < 300);
  for (const f of prepared.files) {
    if (f.path.startsWith('.tools/linuxguest/qemu-20260811/')) add(f);
  }
  const worker = read(pins.worker_manifest), review = read(pins.review_manifest), evidence = read(pins.review_report);
  assert(worker.kind === 'unactivated-runtime-candidate' && worker.freeze === 2 && worker.linux_elf_sha256 === pins.tests[0].sha256 && worker.files.length === 10);
  assert(review.schema_version === 1 && review.freeze === 'worker-freeze-2' && review.package === 'hostwebruntime' && review.files.length === 10);
  for (const f of worker.files) {
    assert(/^internal\/hostwebruntime\/[A-Za-z0-9_.-]+$/.test(f.path));
    const peer = review.files.filter(r => r.name === path.posix.basename(f.path));
    assert.equal(peer.length, 1); assert.equal(peer[0].sha256, f.sha256);
    add({...f, path: '.worktrees/native-web-executor-sol/' + f.path});
    add({...f, path: '.worktrees/native-web-review-sol/lab/hostwebruntime-review/testdata/candidate/' + peer[0].name});
  }
  assert(evidence.schema_version === 2 && evidence.passed === true && evidence.source_pins_unchanged === true && evidence.source_pins.length === 43);
  assert(evidence.checks.length === 4 && evidence.checks.every(c => c.exit_code === 0));
  const historical = read(pins.historical_review_report), marker = '\\.worktrees\\native-web-review-sol\\go.mod';
  const module = historical.source_pins.find(p => p.path.endsWith(marker));
  assert(module && historical.source_pins.length === 42);
  const recordedRoot = module.path.slice(0, -marker.length);
  const sourceMap = new Map();
  for (const f of evidence.source_pins) {
    assert(['canonical', 'review', 'lab'].includes(f.scope));
    relative(f.path);
    const logical = (f.scope === 'canonical' ? '' : f.scope === 'review' ? '.worktrees/native-web-review-sol/' : '.worktrees/native-web-review-sol/lab/hostwebruntime-review/') + f.path;
    const rel = portableSource(recordedRoot, path.win32.join(recordedRoot, logical));
    assert(!sourceMap.has(rel)); sourceMap.set(rel, f.sha256); add({path: rel, sha256: f.sha256});
  }
  const provenanceChanges = [];
  for (const f of historical.source_pins) {
    const rel = portableSource(recordedRoot, f.path), current = sourceMap.get(rel);
    assert(current, 'Historical source absent from fresh review');
    if (current !== f.sha256) {
      assert(['.worktrees/native-web-review-sol/lab/hostwebruntime-review/run.ps1', '.worktrees/native-web-review-sol/lab/hostwebruntime-review/testdata/candidate-manifest.json'].includes(rel), 'Linked source drift since historical ELF');
      provenanceChanges.push({path: rel, historical_sha256: f.sha256, current_sha256: current, kind: 'portable-provenance-only'});
    }
  }
  assert.equal(provenanceChanges.length, 2);
  const dependencyComparison = {go_files: 0, raw_equal: 0, newline_normalized_equal: 0};
  for (const f of workerDependencies.files.filter(f => f.path.endsWith('.go'))) {
    assert(sourceMap.has(f.path));
    const workerBytes = fs.readFileSync(regular(primary, '.worktrees/native-web-executor-sol/' + f.path));
    const canonicalBytes = fs.readFileSync(regular(primary, f.path));
    dependencyComparison.go_files++;
    if (workerBytes.equals(canonicalBytes)) dependencyComparison.raw_equal++;
    assert.equal(workerBytes.toString('utf8').replaceAll('\r\n', '\n'), canonicalBytes.toString('utf8').replaceAll('\r\n', '\n'), 'Dependency content drift beyond newline encoding');
    dependencyComparison.newline_normalized_equal++;
  }
  for (const file of ['go.mod', 'go.sum']) add({path: '.worktrees/native-web-executor-sol/' + file, sha256: sourceMap.get('.worktrees/native-web-review-sol/' + file)});
  const overlay = read(pins.review_overlay);
  assert.deepEqual(Object.keys(overlay), ['Replace']);
  assert.equal(Object.keys(overlay.Replace).length, 35);
  for (const [from, to] of Object.entries(overlay.Replace)) {
    const fromRel = path.win32.relative(recordedRoot, from).replaceAll('\\', '/');
    relative(fromRel);
    assert(/^\.worktrees\/native-web-review-sol\/(?:internal\/(?:hostaccounts|hostweb|hostwebgeneration|securestate)\/[A-Za-z0-9_.-]+|lab\/hostwebruntime-review\/[A-Za-z0-9_.-]+)$/.test(fromRel));
    assert(sourceMap.has(portableSource(recordedRoot, to)), 'Unpinned overlay target');
  }
  const self = ['run.mjs', 'admission.mjs', 'guest.py', 'make_iso.py', 'pins.json', 'worker-dependencies.json'].map(name => {
    const p = regular(owner, 'lab/hostwebruntime-mechanics/' + name);
    return {path: 'lab/hostwebruntime-mechanics/' + name, sha256: digest(fs.readFileSync(p))};
  });
  return {primary, inventory, self, provenanceChanges, dependencyComparison};
}

function childEnv(qdir) {
  const env = {};
  for (const key of ['SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA']) if (process.env[key]) env[key] = process.env[key];
  assert(env.LOCALAPPDATA && (env.SystemRoot || env.SYSTEMROOT));
  env.PATH = qdir + ';' + path.join(env.SystemRoot || env.SYSTEMROOT, 'System32');
  return env;
}
function command(exe, args, cwd, env, timeout) {
  const r = spawnSync(exe, args, {cwd, env, windowsHide: true, timeout, maxBuffer: 64 * 1024, encoding: 'utf8'});
  assert(!r.error && r.status === 0, 'Bounded preparation command failed');
  return r.stdout;
}
function unchanged(state) {
  for (const entry of state.inventory) pin(state.primary, entry, entry.path === pins.image.path ? 700 * 1024 * 1024 : 64 * 1024 * 1024);
  for (const entry of state.self) pin(owner, entry);
}

async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 3 && args[0] === '--primary-root' && ['--check-only', '--prepare-only', '--run'].includes(args[2]), 'Use --primary-root ROOT and one fixed mode');
  const state = admit(args[1]);
  if (args[2] === '--check-only') {
    unchanged(state);
    console.log(JSON.stringify({admitted: true, evidence_kind: 'windows-input-admission-only', source_inputs: state.inventory, runner_sources: state.self, provenance_changes: state.provenanceChanges, dependency_comparison: state.dependencyComparison, qemu_launched: false}));
    return;
  }
  const nonce = randomBytes(12).toString('hex'), run = `mechanics-${Date.now()}-${nonce}`;
  const parent = path.join(owner, '.cache/hostwebruntime-mechanics');
  fs.mkdirSync(parent, {recursive: true});
  assert.equal(fs.realpathSync(parent).toLowerCase(), parent.toLowerCase());
  const work = path.join(parent, run); fs.mkdirSync(work);
  const qdir = path.join(state.primary, '.tools/linuxguest/qemu-20260811'), env = childEnv(qdir);
  const python = path.join(env.LOCALAPPDATA, 'Programs/Python/Python312/python.exe');
  assert(fs.lstatSync(python).isFile() && fs.realpathSync(python).toLowerCase() === python.toLowerCase());
  const entries = [];
  const write = (name, data) => { fs.writeFileSync(path.join(work, name), data, {flag: 'wx'}); entries.push({name, bytes: Buffer.byteLength(data), sha256: digest(data)}); };
  for (const [name, source] of [['worker.test', pins.tests[0]], ['review.test', pins.tests[1]], ['worker-manifest.json', pins.worker_manifest], ['review-manifest.json', pins.review_manifest], ['review-overlay.json', pins.review_overlay], ['review-source-report.json', pins.review_report]]) write(name, fs.readFileSync(regular(state.primary, source.path)));
  for (const name of ['guest.py', 'pins.json']) write(name, fs.readFileSync(regular(owner, 'lab/hostwebruntime-mechanics/' + name)));
  const script = `#!/bin/sh\nset -eu\nexec >/dev/ttyS0 2>&1\ntrap '/sbin/poweroff -f' EXIT\nmkdir -p /mnt/sifruno-runtime /opt/sifruno-runtime-mechanics\nmount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-runtime\nfor name in guest.py pins.json worker.test review.test worker-manifest.json review-manifest.json review-overlay.json review-source-report.json; do cp /mnt/sifruno-runtime/$name /opt/sifruno-runtime-mechanics/$name; done\nchmod 0700 /opt/sifruno-runtime-mechanics /opt/sifruno-runtime-mechanics/*.test\nprintf '%s\\n' '${nonce}' >/run/sifruno-runtime-admission\nchmod 0600 /run/sifruno-runtime-admission\nset +e\nenv -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I /opt/sifruno-runtime-mechanics/guest.py\nstatus=$?\necho SIFRUNO_RUNTIME_EXIT_${nonce}_$status\nexit $status\n`;
  write('user-data', '#cloud-config\nusers: []\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-runtime-mechanics.sh\n    permissions: \'0700\'\n    owner: root:root\n    content: |\n' + script.split('\n').map(l => '      ' + l).join('\n') + '\nruncmd:\n  - [sh, /root/sifruno-runtime-mechanics.sh]\n');
  write('meta-data', `instance-id: ${run}\nlocal-hostname: sifruno-mechanics\n`);
  write('network-config', 'version: 2\nethernets: {}\n');
  fs.writeFileSync(path.join(work, 'payload-plan.json'), JSON.stringify({schema_version: 1, entries}), {flag: 'wx'});
  unchanged(state);
  const isoReadback = JSON.parse(command(python, ['-I', path.join(here, 'make_iso.py'), state.primary, work], work, env, 90000));
  assert(isoReadback.entries === 11 && isoReadback.iso_readback.length === 11);
  const image = regular(state.primary, pins.image.path, 700 * 1024 * 1024);
  command(regular(state.primary, pins.qemu_img.path), ['create', '-f', 'qcow2', '-F', 'qcow2', '-b', image, path.join(work, 'overlay.qcow2')], work, env, 30000);
  const isoSHA = digest(fs.readFileSync(regular(work, 'payload.iso', 128 * 1024 * 1024)));
  const report = {schema_version: 1, run, nonce, scope: pins.scope, passed: false, evidence_kind: 'preparation-only', qemu_launched: false, source_inputs: state.inventory, runner_sources: state.self, provenance_changes: state.provenanceChanges, dependency_comparison: state.dependencyComparison, payload: entries, iso_readback: isoReadback.iso_readback, iso_sha256: isoSHA, daemon_serving_qualified: false, guest: null};
  const reportPath = path.join(work, 'report.json');
  if (args[2] === '--prepare-only') { unchanged(state); fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), {flag: 'wx'}); console.log(reportPath); return; }
  unchanged(state);
  report.qemu_launched = true; report.evidence_kind = 'disposable-alma-linux-synthetic-runtime-mechanics';
  const serialFD = fs.openSync(path.join(work, 'serial.log'), 'wx');
  let timedOut = false;
  const child = spawn(regular(state.primary, pins.qemu.path), qemuArgs(qdir, work), {cwd: qdir, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
  const kill = () => {
    try { if (child.exitCode === null) child.kill(); }
    catch (e) { report.cleanup_error = String(e.code || e.name || 'ChildKillError'); }
  };
  const abort = () => { report.interrupted = true; kill(); };
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  const timer = setTimeout(() => { timedOut = true; kill(); }, 600000);
  const capture = createCapture(b => fs.writeSync(serialFD, b), kill);
  child.stdout.on('data', capture.accept); child.stderr.on('data', capture.accept);
  try {
    // Capture/spawn errors never bypass owned-child close or the deadline timer.
    const exit = await new Promise(resolve => {
      child.once('error', e => { report.qemu_error = String(e.code || e.name || 'ChildError'); kill(); });
      child.once('close', (code, signal) => resolve({code, signal}));
    });
    report.qemu_exit = exit; report.timed_out = timedOut; report.output_limited = capture.outputLimited; report.capture_error = capture.error;
    assert(exit.code === 0 && !timedOut && !capture.outputLimited && !capture.error && !report.interrupted && !report.qemu_error && !report.cleanup_error, 'Guest process/capture did not finish cleanly');
    unchanged(state);
    assert.equal(digest(fs.readFileSync(regular(work, 'payload.iso', 128 * 1024 * 1024))), isoSHA);
    for (const entry of entries) pin(work, {path: entry.name, sha256: entry.sha256, bytes: entry.bytes});
    report.guest = parseSerial(capture.data.toString('utf8'), nonce, pins);
    report.passed = true; report.source_pins_unchanged = true;
  } catch (error) {
    report.failure = String(error.message).slice(0, 500);
    process.exitCode = 1;
  } finally {
    kill(); clearTimeout(timer); process.off('SIGINT', abort); process.off('SIGTERM', abort); fs.closeSync(serialFD);
    report.serial_sha256 = digest(capture.data); report.serial_bytes = capture.data.length; report.capture_error = capture.error;
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), {flag: 'wx'});
  }
  console.log(reportPath);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => { console.error('Runtime mechanics admission/preparation failed'); process.exitCode = 1; });
