import { spawn } from 'node:child_process';
import { readFile, mkdir, writeFile, lstat, realpath, rename } from 'node:fs/promises';
import { resolve, join, dirname, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { analysisEnvironment } from './analysis-environment.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const reportRoot = join(root, 'artifacts/rea');
const reportPath = name => join(reportRoot, name);
async function checkReportPaths() {
  let current = await realpath(root);
  for (const part of ['artifacts', 'rea']) {
    current = join(current, part);
    try { await mkdir(current); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(current) !== current) throw new Error('Analysis report directory is not a regular workspace directory.');
  }
  for (const name of ['doctor.json', 'doctor.upstream.json', 'doctor.stderr.log', 'analyze.json', 'analyze.stderr.log', 'analysis.snapshot.json']) {
    try {
      const info = await lstat(reportPath(name));
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error('Analysis report is not a regular independent file.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}
const [command, target, ...extra] = process.argv.slice(2);
if (!['doctor', 'analyze'].includes(command) || extra.length || (command === 'doctor' && target)) {
  console.error('Usage: npm run tools:doctor | npm run tools:analyze -- <owned shipped artifact>');
  process.exit(2);
}
if (command === 'analyze' && !target) {
  console.error('An explicit owned archive or executable is required. No cPanel artifact is supplied or analyzed automatically.');
  process.exit(2);
}
const pkgRoot = join(root, 'node_modules/rea-agents');
const pkg = JSON.parse(await readFile(join(pkgRoot, 'package.json'), 'utf8'));
const entry = resolve(pkgRoot, typeof pkg.bin === 'string' ? pkg.bin : pkg.bin.rea);
const args = [entry, command];
if (target) {
  const artifact = resolve(target);
  const info = await lstat(artifact);
  const canonical = await realpath(artifact);
  const within = relative(await realpath(root), canonical);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size < 1 || info.size > 32 * 1024 * 1024 || !within || isAbsolute(within) || within === '..' || within.startsWith('..' + sep)) throw new Error('Pass a regular owned workspace artifact of at most 32 MiB; source repositories use ordinary code tools.');
  args.push(artifact, '--snapshot', reportPath('analysis.snapshot.json'));
}
args.push('--format', 'json');
await checkReportPaths();
if (command === 'analyze') {
  try { await rename(reportPath('analysis.snapshot.json'), reportPath(`analysis.snapshot.previous.${randomUUID()}.json`)); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const { env } = await analysisEnvironment(root);
const run = childArgs => new Promise((yes, no) => {
  const child = spawn(process.execPath, childArgs, { cwd: root, env, windowsHide: true, shell: false });
  const stdout = []; const stderr = []; let length = 0; let failure = null; let done = false; let grace;
  const finish = code => {
    if (done) return;
    done = true; clearTimeout(timer); clearTimeout(grace);
    yes(failure ? { code: 1, stdout: Buffer.from(JSON.stringify({ healthy: false, error: { code: failure, cleanup_verified: false } })), stderr: Buffer.alloc(0) } : { code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
  };
  const stop = reason => {
    if (failure || done) return;
    failure = reason;
    grace = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish(1); }, 3000);
    if (child.exitCode !== null) return; // A departed parent's PID is no longer cleanup authority.
    if (process.platform === 'win32' && child.pid) {
      const killer = spawn(join(env.SystemRoot ?? 'C:\\Windows', 'System32/taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { env, windowsHide: true, shell: false, stdio: 'ignore' });
      const fallback = () => { if (child.exitCode === null) child.kill(); };
      killer.once('error', fallback);
      killer.once('close', code => { if (code !== 0) fallback(); });
      killer.unref();
    } else child.kill('SIGTERM');
  };
  const timer = setTimeout(() => stop('analysis_deadline_exceeded'), command === 'doctor' ? 90000 : 390000);
  const collect = list => data => { length += data.length; if (length > 8 * 1024 * 1024) stop('analysis_output_limit'); else list.push(data); };
  child.stdout.on('data', collect(stdout)); child.stderr.on('data', collect(stderr));
  child.once('error', error => { if (!done) { done = true; clearTimeout(timer); clearTimeout(grace); no(error); } });
  child.once('close', finish);
});
const result = await run(args);
const report = reportPath(`${command}.json`);
let finalResult = result;
if (command === 'doctor' && process.platform === 'win32' && result.code !== 0 && result.stdout.includes('spawn EINVAL')) {
  await writeFile(reportPath('doctor.upstream.json'), result.stdout);
  finalResult = await run([join(root, 'scripts/rea-doctor.mjs')]);
}
await checkReportPaths();
await writeFile(report, finalResult.stdout);
await writeFile(reportPath(`${command}.stderr.log`), finalResult.stderr);
console.log(`REA ${pkg.version} ${command}: exit ${finalResult.code}; local report: artifacts/rea/${command}.json`);
console.log('Read the report for coverage and provider limitations. Tool readiness is not cPanel compatibility evidence.');
process.exitCode = finalResult.code ?? 1;
