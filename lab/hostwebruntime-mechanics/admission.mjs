import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const digest = b => createHash('sha256').update(b).digest('hex');
export function relative(p) {
  assert(typeof p === 'string' && /^[A-Za-z0-9_.+/-]+$/.test(p));
  assert(!path.posix.isAbsolute(p) && !p.split('/').some(s => ['', '.', '..'].includes(s)));
  return p;
}
export function regular(root, rel, max = 64 * 1024 * 1024) {
  const p = path.resolve(root, ...relative(rel).split('/'));
  const s = fs.lstatSync(p);
  assert(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.size > 0 && s.size <= max, `Invalid regular input: ${rel}`);
  assert.equal(fs.realpathSync(p).toLowerCase(), p.toLowerCase(), `Redirected input: ${rel}`);
  // Also refuse directory links/junctions even if a link points back to itself.
  for (let d = path.dirname(p); ; d = path.dirname(d)) {
    assert(!fs.lstatSync(d).isSymbolicLink());
    if (path.dirname(d) === d) break;
  }
  return p;
}
export function pin(root, entry, max) {
  const p = regular(root, entry.path, max);
  const b = fs.readFileSync(p);
  assert.equal(digest(b), entry.sha256, `Input hash mismatch: ${entry.path}`);
  if (entry.bytes !== undefined) assert.equal(b.length, entry.bytes);
  return {path: entry.path, sha256: entry.sha256, bytes: b.length};
}
export function validateLayout(primary, owner, here) {
  assert(path.isAbsolute(primary) && !/[\r\n,]/.test(primary));
  primary = path.resolve(primary);
  assert.equal(fs.realpathSync(primary).toLowerCase(), primary.toLowerCase());
  assert([primary, path.join(primary, '.worktrees/release-plan-sol')].some(p => p.toLowerCase() === owner.toLowerCase()), 'Canonical or assigned worktree required');
  assert.equal(here.toLowerCase(), path.join(owner, 'lab/hostwebruntime-mechanics').toLowerCase());
  for (const root of [primary, owner]) {
    const modules = [...fs.readFileSync(regular(root, 'go.mod', 65536), 'utf8').matchAll(/^module[ \t]+([^\r\n]+)\r?$/gm)];
    assert(modules.length === 1 && modules[0][1].trim() === 'sifruno', 'Exact primary module identity required');
  }
  return primary;
}
export function portableSource(recordedRoot, source) {
  const rel = path.win32.relative(recordedRoot, source).replaceAll('\\', '/');
  relative(rel);
  assert(/^(?:go\.(?:mod|sum)|internal\/(?:hostaccounts|hostweb|hostwebgeneration|securestate)\/[A-Za-z0-9_.-]+|\.worktrees\/native-web-review-sol\/(?:go\.(?:mod|sum)|lab\/hostwebruntime-review\/(?:(?:run|layout-challenge)\.ps1|testdata\/(?:[A-Za-z0-9_.-]+|candidate\/[A-Za-z0-9_.-]+))))$/.test(rel), `Unadmitted review source: ${rel}`);
  return rel;
}
export function parseSerial(serial, nonce, pins) {
  assert(/^[a-f0-9]{24}$/.test(nonce));
  assert(Buffer.byteLength(serial) <= 2 * 1024 * 1024);
  const clean = serial.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replaceAll('\r', '');
  const lines = clean.split('\n');
  const begin = `SIFRUNO_RUNTIME_REPORT_BEGIN_${nonce}`, end = `SIFRUNO_RUNTIME_REPORT_END_${nonce}`;
  assert.equal(lines.filter(l => l === begin).length, 1, 'Missing/duplicate report begin');
  assert.equal(lines.filter(l => l === end).length, 1, 'Missing/duplicate report end');
  const a = lines.indexOf(begin), b = lines.indexOf(end);
  assert(b === a + 2, 'Report must be one JSON line');
  const exits = lines.filter(l => l.startsWith(`SIFRUNO_RUNTIME_EXIT_${nonce}_`));
  assert.deepEqual(exits, [`SIFRUNO_RUNTIME_EXIT_${nonce}_0`]);
  assert(lines.indexOf(exits[0]) > b);
  const report = JSON.parse(lines[a + 1]);
  // The frozen guest emits compact canonical JSON. This also refuses duplicate
  // keys rather than accepting JSON.parse's last-key-wins behavior.
  assert.equal(JSON.stringify(report), lines[a + 1], 'Noncanonical/duplicate-key report');
  const exactKeys = (obj, keys) => assert.deepEqual(Object.keys(obj).sort(), [...keys].sort());
  exactKeys(report, ['schema_version', 'kind', 'nonce', 'passed', 'daemon_serving_qualified', 'facts', 'tests']);
  assert.equal(report.schema_version, 1);
  assert.equal(report.daemon_serving_qualified, false);
  assert.equal(report.nonce, nonce);
  assert.equal(report.kind, pins.scope);
  assert.equal(report.passed, true);
  assert.equal(report.facts.os.ID, 'almalinux');
  assert.equal(report.facts.os.VERSION_ID, '9.8');
  assert.equal(report.facts.architecture, 'x86_64');
  assert.deepEqual(report.facts.uid, [0, 0, 0, 0]);
  assert.deepEqual(report.facts.gid, [0, 0, 0, 0]);
  exactKeys(report.facts, ['os', 'architecture', 'kernel', 'uid', 'gid', 'process_status', 'selinux_enforce', 'filesystems', 'boot_id']);
  assert(typeof report.facts.kernel === 'string' && report.facts.kernel.length > 0 && report.facts.kernel.length < 200);
  assert(/^[a-f0-9-]{36}$/.test(report.facts.boot_id));
  assert(['0', '1', 'not-mounted'].includes(report.facts.selinux_enforce));
  exactKeys(report.facts.process_status, ['Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp']);
  for (const key of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) assert(/^[a-f0-9]{16}$/.test(report.facts.process_status[key]));
  assert.equal(report.facts.filesystems.length, 3);
  assert.deepEqual(report.facts.filesystems.map(f => f.path), ['/', '/tmp', '/opt/sifruno-runtime-mechanics']);
  for (const f of report.facts.filesystems) {
    exactKeys(f, ['path', 'type_options', 'block_size', 'available_bytes']);
    assert(typeof f.type_options === 'string' && f.type_options.length > 0 && f.type_options.length < 4096);
    assert(Number.isSafeInteger(f.block_size) && f.block_size > 0 && Number.isSafeInteger(f.available_bytes) && f.available_bytes >= 0);
  }
  assert.equal(report.tests.length, pins.tests.length);
  for (const expected of pins.tests) {
    const matches = report.tests.filter(t => t.id === expected.id);
    assert.equal(matches.length, 1);
    const t = matches[0];
    exactKeys(t, ['id', 'exit_code', 'elf_sha256', 'arguments', 'output_sha256', 'output_bytes', 'timed_out', 'output_limited', 'passes', 'skips', 'passed']);
    assert.equal(t.elf_sha256, expected.sha256);
    assert.equal(t.exit_code, 0);
    assert.equal(t.passed, true);
    assert.deepEqual([...t.passes].sort(), [...expected.required].sort());
    assert.deepEqual([...t.skips].sort(), [...expected.allowed_skips].sort());
    assert(/^[a-f0-9]{64}$/.test(t.output_sha256));
    assert(Number.isSafeInteger(t.output_bytes) && t.output_bytes > 0 && t.output_bytes <= 512 * 1024);
    const expectedArgs = ['-test.v', '-test.count=1', '-test.timeout=' + expected.timeout];
    if (expected.run) expectedArgs.push('-test.run', expected.run);
    assert.deepEqual(t.arguments, expectedArgs);
    assert.equal(t.timed_out, false);
    assert.equal(t.output_limited, false);
    const start = `SIFRUNO_RUNTIME_TEST_BEGIN_${nonce}_${expected.id}`, stop = `SIFRUNO_RUNTIME_TEST_END_${nonce}_${expected.id}`;
    assert.equal(lines.filter(l => l === start).length, 1);
    assert.equal(lines.filter(l => l === stop).length, 1);
    const first = lines.indexOf(start), last = lines.indexOf(stop);
    assert(first >= 0 && last > first && last < a);
    const output = lines.slice(first + 1, last).join('\n') + '\n';
    assert.equal(Buffer.byteLength(output), t.output_bytes);
    assert.equal(digest(output), t.output_sha256, 'Raw transcript hash mismatch');
    const runs = [...output.matchAll(/^=== RUN   (Test\w+)$/gm)].map(m => m[1]);
    const done = [...output.matchAll(/^--- (PASS|SKIP|FAIL): (Test\w+) \([0-9.]+s\)$/gm)];
    assert.deepEqual(runs.sort(), [...expected.required, ...expected.allowed_skips].sort());
    assert.deepEqual(done.filter(m => m[1] === 'PASS').map(m => m[2]).sort(), [...expected.required].sort());
    assert.deepEqual(done.filter(m => m[1] === 'SKIP').map(m => m[2]).sort(), [...expected.allowed_skips].sort());
    assert.equal(done.length, expected.required.length + expected.allowed_skips.length);
    assert.equal(output.split('\n').filter(l => l === 'PASS').length, 1);
    assert(!/^\s*--- FAIL:|^FAIL$|^panic:/m.test(output));
  }
  return report;
}
export function qemuArgs(qdir, work) {
  return ['-L', path.join(qdir, 'share'), '-machine', 'pc', '-accel', 'tcg,thread=single', '-cpu', 'max', '-smp', '1', '-m', '1536', '-nodefaults', '-no-user-config', '-nic', 'none', '-display', 'none', '-vga', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-object', 'rng-builtin,id=rng0', '-device', 'virtio-rng-pci,rng=rng0', '-drive', `file=${path.join(work, 'overlay.qcow2')},if=virtio,format=qcow2,index=0`, '-drive', `file=${path.join(work, 'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
}

export function createCapture(write, kill, maximum = 2 * 1024 * 1024) {
  const chunks = [];
  let bytes = 0, error = null, outputLimited = false;
  const stop = () => { try { kill(); } catch (e) { error ||= String(e.code || e.name || 'CaptureKillError'); } };
  return {
    accept(chunk) {
      if (error || outputLimited) return;
      if (bytes + chunk.length > maximum) { outputLimited = true; stop(); return; }
      try {
        const written = write(chunk);
        if (written !== chunk.length) throw Object.assign(new Error('Short serial write'), {code: 'SHORT_WRITE'});
        chunks.push(chunk); bytes += chunk.length;
      } catch (e) { error = String(e.code || e.name || 'CaptureWriteError'); stop(); }
    },
    get data() { return Buffer.concat(chunks, bytes); },
    get error() { return error; },
    get outputLimited() { return outputLimited; },
  };
}
