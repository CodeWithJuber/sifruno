import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analysisEnvironment } from './analysis-environment.mjs';

const root = await realpath(join(dirname(fileURLToPath(import.meta.url)), '..'));
const cache = join(root, '.cache');
await mkdir(cache, { recursive: true });
const fixture = await mkdtemp(join(cache, 'analysis-environment-'));
const base = join(fixture, '.tools/analysis');
await mkdir(base, { recursive: true });
const manifest = { schema_version: 1, platform: 'windows-amd64', ghidra_version: '12.1.4', required_jdk_major: 21, headless_launch_verified: true };
for (const name of ['ghidra_dir', 'java_home', 'application_home', 'application_settings', 'application_cache', 'application_temp']) {
  manifest[name] = join(base, name);
  await mkdir(manifest[name]);
}
const manifestPath = join(base, 'manifest.json');
const inherited = { ...process.env, SIFRUNO_TEST_SECRET: 'non-secret-isolation-canary', NODE_OPTIONS: '--inspect', JAVA_TOOL_OPTIONS: '-Dinvalid=true' };
try {
  await writeFile(manifestPath, JSON.stringify(manifest));
  if (process.platform === 'win32' && process.arch === 'x64') {
    const { env } = await analysisEnvironment(fixture, inherited);
    for (const name of ['SIFRUNO_TEST_SECRET', 'NODE_OPTIONS', 'JAVA_TOOL_OPTIONS', 'OPENCLAW_HOOKS_TOKEN', 'TYPESAFE_API_KEY']) assert.equal(name in env, false, 'Unexpected inherited application or injection variable.');
    assert.equal(env.TEMP, manifest.application_temp);
    assert.equal(env.USERPROFILE, manifest.application_home);
    assert.equal(inherited.SIFRUNO_TEST_SECRET === 'non-secret-isolation-canary', true);
    await writeFile(manifestPath, JSON.stringify({ ...manifest, java_home: fixture }));
    await assert.rejects(analysisEnvironment(fixture, inherited), /leaves its installation/);
  } else {
    await assert.rejects(analysisEnvironment(fixture, inherited), /verified host/);
  }
  await writeFile(manifestPath, 'x'.repeat(65537));
  await assert.rejects(analysisEnvironment(fixture, inherited), /Invalid local analysis manifest/);
  console.log(JSON.stringify({ credential_and_injection_variables_excluded: true, manifest_escape_rejected: true, oversized_manifest_rejected: true, provider_calls: 0 }));
} finally {
  const target = await realpath(fixture);
  const confined = relative(await realpath(cache), target);
  if (!confined || confined === '..' || confined.startsWith('..' + sep)) throw new Error('Refusing fixture cleanup outside task cache.');
  await rm(target, { recursive: true, force: true });
}
