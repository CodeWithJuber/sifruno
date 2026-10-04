// Compatibility adapter for pinned REA 3.2.1's read-only doctor. Its Windows
// runtime inventory throws on npm/npx batch launchers. Preserve failed probes
// explicitly instead of pretending those tools or providers are ready.
import { runDoctor } from '../node_modules/rea-agents/dist/application/Doctor.js';
import { createSystemDoctorHost } from '../node_modules/rea-agents/dist/doctorRuntime.js';
import { dirname, join } from 'node:path';

const host = createSystemDoctorHost();
const probe = host.runtimeExecutables;
let adapterFailure = null;
host.runtimeExecutables = async () => {
  try { return await probe(); }
  catch (error) {
    if (process.platform !== 'win32' || error.code !== 'EINVAL') throw error;
    adapterFailure = { code: 'windows_batch_probe_einval', upstream_version: '3.2.1', remediation: 'Repair upstream Windows npm/npx batch-wrapper version probing. No readiness is inferred for these unprobed tools.' };
    return { launcher_node: process.execPath, candidates: [
      { tool: 'node', lexical_path: process.execPath, canonical_path: process.execPath, path_index: null, selection: 'rea-launcher', version: process.version, healthy: true, failure: null },
      ...['npm', 'npx'].map(tool => ({ tool, lexical_path: join(dirname(process.execPath), tool + '.cmd'), canonical_path: join(dirname(process.execPath), tool + '.cmd'), path_index: null, selection: 'path-primary', version: null, healthy: false, failure: { code: 'runtime_spawn_failed', exit_code: null, signal: null, dependency: null, stderr: 'Upstream Windows batch-wrapper probe failed EINVAL; this executable was not probed.' } })),
    ] };
  }
};
try {
  const report = await runDoctor(undefined, host);
  if (adapterFailure) { report.healthy = false; report.environment_healthy = false; report.sifruno_adapter_failure = adapterFailure; }
  console.log(JSON.stringify(report, null, 2));
  if (!report.healthy) process.exitCode = 1;
} catch (error) {
  console.log(JSON.stringify({ healthy: false, error: { code: error.code ?? 'doctor_failed', message: error.message } }));
  process.exitCode = 1;
}
