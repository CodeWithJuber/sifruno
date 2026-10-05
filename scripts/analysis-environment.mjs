import { lstat, readFile, realpath } from 'node:fs/promises';
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

// Analysis children receive OS launch paths only. Application credentials,
// Node injection flags and user Java options never cross this boundary.
const osNames = ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'PATH', 'LANG', 'LC_ALL'];
const inside = (base, target) => {
  const path = relative(base, target);
  return path !== '' && !isAbsolute(path) && path !== '..' && !path.startsWith('..' + sep);
};

export async function analysisEnvironment(root, inherited = process.env) {
  const workspace = await realpath(root);
  const env = {};
  for (const name of osNames) if (typeof inherited[name] === 'string') env[name] = inherited[name];
  const base = resolve(workspace, '.tools/analysis');
  const manifestPath = join(base, 'manifest.json');
  let info;
  try { info = await lstat(manifestPath); }
  catch (error) { if (error.code === 'ENOENT') return { env, installation: null }; throw error; }
  if (!info.isFile() || info.isSymbolicLink() || info.size > 65536) throw new Error('Invalid local analysis manifest.');
  if (!inside(workspace, await realpath(base))) throw new Error('Analysis installation leaves the workspace.');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.schema_version !== 1 || manifest.platform !== 'windows-amd64' || process.platform !== 'win32' || process.arch !== 'x64' || manifest.ghidra_version !== '12.1.4' || manifest.required_jdk_major !== 21 || manifest.headless_launch_verified !== true) throw new Error('Local analysis manifest does not match this verified host.');
  for (const name of ['ghidra_dir', 'java_home', 'application_home', 'application_settings', 'application_cache', 'application_temp']) {
    const value = manifest[name];
    if (typeof value !== 'string' || !isAbsolute(value) || !inside(base, value) || !inside(base, await realpath(value))) throw new Error('Analysis path leaves its installation.');
    const pathInfo = await lstat(value);
    if (!pathInfo.isDirectory() || pathInfo.isSymbolicLink()) throw new Error('Analysis path is not a regular directory.');
  }
  env.PATH = [join(manifest.java_home, 'bin'), dirname(process.execPath), env.PATH].filter(Boolean).join(delimiter);
  Object.assign(env, {
    GHIDRA_INSTALL_DIR: manifest.ghidra_dir, JAVA_HOME: manifest.java_home,
    HOME: manifest.application_home, USERPROFILE: manifest.application_home,
    APPDATA: join(manifest.application_home, 'appdata'), LOCALAPPDATA: join(manifest.application_home, 'localappdata'),
    TEMP: manifest.application_temp, TMP: manifest.application_temp, TMPDIR: manifest.application_temp,
    XDG_CONFIG_HOME: manifest.application_settings, XDG_CACHE_HOME: manifest.application_cache,
    XDG_DATA_HOME: manifest.application_home, REA_ANALYSIS_PROVIDER: 'ghidra',
    REA_PROCESS_CAPTURE_ENABLED: 'false', REA_PROCESS_ALLOW_EXTERNAL_NETWORK: 'false',
    REA_BROWSER_OBSERVE_ENABLED: 'false', REA_ELECTRON_OBSERVE_ENABLED: 'false',
  });
  return { env, installation: manifest };
}
