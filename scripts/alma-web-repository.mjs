import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

/*
 * Host-side, offline repository admission for the disposable AlmaLinux web
 * runtime lab.  The only network names accepted here are the two fixed
 * official AlmaLinux 9.8 repositories.  Guest execution is deliberately
 * separate: this file only stages bytes and later fetches the exact RPMs
 * named by a bounded guest resolve report.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RELEASE = '9.8';
const ARCH = 'x86_64';
const IMAGE_SHA256 = '6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b';
const ALMA_KEY_FINGERPRINT = 'BF18AC2876178908D6E71267D36CB86CB86B3716';
const HOST = 'repo.almalinux.org';
const REPOSITORIES = Object.freeze({
  BaseOS: Object.freeze({
    id: 'BaseOS',
    baseUrl: `https://${HOST}/almalinux/${RELEASE}/BaseOS/${ARCH}/os/`,
    required: Object.freeze(['primary', 'filelists', 'other']),
  }),
  AppStream: Object.freeze({
    id: 'AppStream',
    baseUrl: `https://${HOST}/almalinux/${RELEASE}/AppStream/${ARCH}/os/`,
    required: Object.freeze(['primary', 'filelists', 'other', 'modules']),
  }),
});
const MAX_REPORT_BYTES = 64 * 1024;
const MAX_PACKAGES = 200;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_STAGE_BYTES = 512 * 1024 * 1024;
const STAGED_METADATA_TYPES = new Set(['primary', 'filelists', 'other', 'modules', 'group', 'comps', 'updateinfo']);

function fail(code) {
  throw new Error(code);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isSafePart(part) {
  return part !== '' && part !== '.' && part !== '..' && !part.includes('\\');
}

function safeRelative(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || path.posix.isAbsolute(value)) {
    fail(`${label}_path_invalid`);
  }
  if (!/^[A-Za-z0-9._~+@/-]+$/.test(value)) fail(`${label}_path_invalid`);
  const parts = value.split('/');
  if (!parts.every(isSafePart)) fail(`${label}_path_invalid`);
  return parts.join('/');
}

function assertRegularFile(file, label, maxBytes = MAX_FILE_BYTES) {
  const stat = fs.lstatSync(file, {throwIfNoEntry: false});
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes) {
    fail(`${label}_not_regular`);
  }
  return stat;
}

function runIdOf(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value)) fail('run_id_invalid');
  return value;
}

function workspace(runId, create = false) {
  const id = runIdOf(runId);
  let root = ROOT;
  if (fs.realpathSync(root) !== root) fail('workspace_parent_invalid');
  for (const part of ['.cache', 'alma-web-repositories']) {
    root = path.join(root, part);
    if (create && !fs.existsSync(root)) fs.mkdirSync(root);
    const info = fs.lstatSync(root, {throwIfNoEntry: false});
    if (!info || !info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(root) !== root) fail('workspace_parent_invalid');
  }
  const run = path.join(root, id);
  if (create) {
    fs.mkdirSync(run, {recursive: false});
    if (fs.realpathSync(run) !== run) fail('workspace_realpath_changed');
  } else {
    assertRegularFile(path.join(run, 'manifest.json'), 'repository_manifest', MAX_REPORT_BYTES);
    if (fs.realpathSync(run) !== run) fail('workspace_realpath_changed');
  }
  return run;
}

function sourceFile(run, relative, label, maxBytes = MAX_FILE_BYTES) {
  const parts = safeRelative(relative, label).split('/');
  let current = run;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    const info = fs.lstatSync(current, {throwIfNoEntry: false});
    if (!info || !info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(current) !== current) fail(`${label}_parent_invalid`);
  }
  const file = path.join(current, parts.at(-1));
  assertRegularFile(file, label, maxBytes);
  if (fs.realpathSync(file) !== file) fail(`${label}_path_invalid`);
  return file;
}

function destination(run, relative) {
  const safe = safeRelative(relative, 'destination');
  const file = path.join(run, ...safe.split('/'));
  const resolved = path.resolve(file);
  if (resolved !== run && !resolved.startsWith(`${run}${path.sep}`)) fail('destination_escape');
  const parent = path.dirname(file);
  fs.mkdirSync(parent, {recursive: true});
  let cursor = run;
  if (fs.realpathSync(cursor) !== cursor) fail('destination_parent_invalid');
  for (const part of path.relative(run, parent).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const stat = fs.lstatSync(cursor, {throwIfNoEntry: false});
    if (!stat || !stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(cursor) !== cursor) fail('destination_parent_invalid');
  }
  return file;
}

function writeExclusive(file, bytes, label, maxBytes = MAX_REPORT_BYTES) {
  if (bytes.length > maxBytes) fail(`${label}_too_large`);
  const fd = fs.openSync(file, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, bytes);
  } finally {
    fs.closeSync(fd);
  }
}

function writeJson(run, relative, value, label) {
  const encoded = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  writeExclusive(destination(run, relative), encoded, label);
}

function publishLatest(runId, run, manifest) {
  const cache = path.join(ROOT, '.cache', 'alma-web-repositories');
  const source = path.join(run, 'payload', 'repository-manifest.json');
  const index = {
    schema_version: 1,
    kind: 'alma-web-repository-latest',
    run_id: runId,
    manifest_relative_path: `.cache/alma-web-repositories/${runId}/payload/repository-manifest.json`,
    manifest_sha256: sha256(fs.readFileSync(source)),
    release: manifest.release,
    architecture: manifest.architecture,
  };
  const temporary = path.join(cache, `latest-${randomBytes(8).toString('hex')}.tmp`);
  writeExclusive(temporary, Buffer.from(`${JSON.stringify(index, null, 2)}\n`, 'utf8'), 'latest_index');
  fs.renameSync(temporary, path.join(cache, 'latest.json'));
}

function xmlValue(block, tag) {
  const found = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]+)</${tag}>`));
  if (!found) fail(`repomd_${tag}_missing`);
  return found[1].replaceAll('&amp;', '&').replaceAll('&quot;', '"').replaceAll('&apos;', "'");
}

function xmlAttribute(block, tag, attribute) {
  const found = block.match(new RegExp(`<${tag}\\s+[^>]*\\b${attribute}="([^"]+)"[^>]*/?>`));
  if (!found) fail(`repomd_${tag}_${attribute}_missing`);
  return found[1];
}

function validateRepoUrl(url, baseUrl) {
  const parsed = new URL(url);
  const base = new URL(baseUrl);
  if (parsed.protocol !== 'https:' || parsed.hostname !== HOST || parsed.port || parsed.username || parsed.password) {
    fail('official_url_rejected');
  }
  if (!parsed.pathname.startsWith(base.pathname) || parsed.search || parsed.hash) fail('official_url_rejected');
  return parsed;
}

async function fetchOfficial(url, expectedLength = null, expectedSha = null) {
  const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(90_000)});
  if (!response.ok) fail(`https_status_${response.status}`);
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_FILE_BYTES)) fail('download_too_large');
  const reader = response.body?.getReader();
  if (!reader) fail('download_body_missing');
  const chunks = [];
  let total = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > MAX_FILE_BYTES) { await reader.cancel(); fail('download_too_large'); }
    chunks.push(Buffer.from(part.value));
  }
  const bytes = Buffer.concat(chunks, total);
  if (bytes.length > MAX_FILE_BYTES) fail('download_too_large');
  if (expectedLength !== null && bytes.length !== expectedLength) fail('declared_length_mismatch');
  if (expectedSha !== null && sha256(bytes) !== expectedSha) fail('declared_checksum_mismatch');
  return bytes;
}

function metadataEntries(repomd, repo) {
  const entries = [];
  const expression = /<data\s+type="([^"]+)">([\s\S]*?)<\/data>/g;
  let match;
  while ((match = expression.exec(repomd)) !== null) {
    const type = match[1];
    const block = match[2];
    if (!/^[A-Za-z0-9._-]+$/.test(type)) fail('metadata_type_invalid');
    // DNF/libdnf consumes the XML metadata below.  SQLite primary_db and
    // related entries can exceed the per-file admission bound and are not
    // needed by this fixed XML-only solve, so they are explicitly excluded.
    if (!STAGED_METADATA_TYPES.has(type)) continue;
    let href = xmlAttribute(block, 'location', 'href');
    if (href.startsWith('./')) href = href.slice(2);
    const relativePath = safeRelative(href, 'metadata');
    if (!relativePath.startsWith('repodata/') || !/\.(?:gz|xz|zst|zck|bz2|xml)$/.test(relativePath)) fail('metadata_path_invalid');
    if (xmlAttribute(block, 'checksum', 'type').toLowerCase() !== 'sha256') fail('metadata_checksum_type_invalid');
    const checksum = xmlValue(block, 'checksum').toLowerCase();
    const length = Number(xmlValue(block, 'size'));
    if (!/^[a-f0-9]{64}$/.test(checksum) || !Number.isSafeInteger(length) || length <= 0 || length > MAX_FILE_BYTES) {
      fail('metadata_declaration_invalid');
    }
    entries.push({type, relativePath, checksum, length});
  }
  if (entries.length === 0 || entries.length > 32) fail('metadata_count_invalid');
  if (new Set(entries.map(entry => entry.type)).size !== entries.length || new Set(entries.map(entry => entry.relativePath)).size !== entries.length) fail('metadata_duplicate');
  const byType = new Map(entries.map(entry => [entry.type, entry]));
  for (const required of repo.required) if (!byType.has(required)) fail(`metadata_${repo.id}_${required}_missing`);
  return [...byType.values()];
}

function selfTest() {
  const digest = 'a'.repeat(64);
  const repomd = [
    '<repomd>',
    '<data type="primary"><location href="repodata/primary.xml.gz"/><checksum type="sha256">' + digest + '</checksum><size>1</size></data>',
    '<data type="filelists"><location href="repodata/filelists.xml.gz"/><checksum type="sha256">' + digest + '</checksum><size>1</size></data>',
    '<data type="other"><location href="repodata/other.xml.gz"/><checksum type="sha256">' + digest + '</checksum><size>1</size></data>',
    '<data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/><checksum type="sha256">' + digest + '</checksum><size>1</size></data>',
    '<data type="group"><location href="repodata/comps.xml"/><checksum type="sha256">' + digest + '</checksum><size>1</size></data>',
    '<data type="primary_db"><location href="repodata/primary.sqlite.bz2"/><checksum type="sha256">' + digest + '</checksum><size>67129766</size></data>',
    '</repomd>',
  ].join('');
  const entries = metadataEntries(Buffer.from(repomd, 'utf8'), REPOSITORIES.BaseOS);
  const types = new Set(entries.map(entry => entry.type));
  if (!types.has('updateinfo') || !types.has('group') || types.has('primary_db') || entries.find(entry => entry.type === 'group').relativePath.endsWith('.gz')) fail('self_test_metadata_inventory_failed');
  const cloneChecks = cloneSelfTest();
  return {phase: 'self-test', metadata_entries: entries.length, optional_types: ['updateinfo', 'group'], excluded_types: ['primary_db'], clone_checks: cloneChecks, passed: true};
}

function cloneSelfTest() {
  const prefix = `clone-test-${randomBytes(6).toString('hex')}`;
  const sourceId = `${prefix}-source`;
  const cache = path.join(ROOT, '.cache', 'alma-web-repositories');
  const runs = new Set([sourceId]);
  const nextId = label => { const id = `${prefix}-${label}`; runs.add(id); return id; };
  const source = workspace(sourceId, true);
  try {
    const repositories = Object.values(REPOSITORIES).map(repo => {
      const files = repo.required.map(type => {
        const bytes = Buffer.from(`fixture-${repo.id}-${type}`);
        const relative = `repodata/${type}.xml.gz`;
        const target = `repositories/${repo.id}/${relative}`;
        writeExclusive(destination(source, target), bytes, 'test_metadata');
        return {type, relative_path: relative, url: new URL(relative, repo.baseUrl).toString(),
          length: bytes.length, bytes: bytes.length, checksum_sha256: sha256(bytes), checksum_type: 'sha256',
          source: `.cache/alma-web-repositories/${sourceId}/${target}`, destination: target};
      });
      const xml = Buffer.from('<repomd>' + files.map(file => `<data type="${file.type}"><location href="${file.relative_path}"/><checksum type="sha256">${file.checksum_sha256}</checksum><size>${file.length}</size></data>`).join('') + '</repomd>');
      const relative = 'repodata/repomd.xml', target = `repositories/${repo.id}/${relative}`;
      writeExclusive(destination(source, target), xml, 'test_repomd');
      files.unshift({type: 'repomd', relative_path: relative, url: new URL(relative, repo.baseUrl).toString(),
        length: xml.length, bytes: xml.length, checksum_sha256: sha256(xml), checksum_type: 'sha256',
        source: `.cache/alma-web-repositories/${sourceId}/${target}`, destination: target});
      return {id: repo.id, base_url: repo.baseUrl, required_metadata: [...repo.required], files};
    });
    const manifest = {schema_version: 1, kind: 'alma-web-repository-stage', phase: 'stage', run_id: sourceId,
      release: RELEASE, architecture: ARCH, cloud_image_sha256: IMAGE_SHA256, signing_key_fingerprint: ALMA_KEY_FINGERPRINT,
      network_policy: 'host_https_official_only_guest_none', repositories};
    writeJson(source, 'manifest.json', manifest, 'test_manifest');
    writeJson(source, 'payload/repository-manifest.json', manifest, 'test_payload');
    const original = fs.readFileSync(path.join(source, 'manifest.json'));
    const metadata = sourceFile(source, repositories[0].files[1].destination, 'test_source');
    const bytes = fs.readFileSync(metadata);
    const destinationId = nextId('success');
    const result = clone(destinationId, sourceId, false);
    const cloned = workspace(destinationId);
    const observed = readStageManifest(cloned);
    assert.equal(result.source_manifest_sha256, sha256(original));
    assert.equal(observed.from_run, sourceId);
    assert(fs.readFileSync(path.join(cloned, 'manifest.json')).equals(fs.readFileSync(path.join(cloned, 'payload/repository-manifest.json'))));
    for (const repo of observed.repositories) for (const file of repo.files) {
      assert(file.source.includes(`/${destinationId}/`));
      assert.equal(fs.lstatSync(sourceFile(cloned, file.destination, 'test_clone')).nlink, 1);
    }
    assert.throws(() => clone(destinationId, sourceId, false), /EEXIST/);
    fs.writeFileSync(metadata, Buffer.alloc(bytes.length, 120));
    const corruptId = nextId('corrupt');
    assert.throws(() => clone(corruptId, sourceId, false), /staged_file_checksum_invalid/);
    assert(!fs.existsSync(path.join(cache, corruptId)));
    fs.writeFileSync(metadata, bytes);
    const hardlink = path.join(source, 'hardlink-fixture');
    fs.linkSync(metadata, hardlink);
    assert.throws(() => clone(nextId('hardlink'), sourceId, false), /staged_file_not_regular/);
    fs.unlinkSync(hardlink);
    const replaceManifest = value => {
      const encoded = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
      fs.writeFileSync(path.join(source, 'manifest.json'), encoded);
      fs.writeFileSync(path.join(source, 'payload/repository-manifest.json'), encoded);
    };
    const changed = structuredClone(manifest);
    changed.repositories[0].files[1].relative_path = '../escape.xml';
    replaceManifest(changed);
    assert.throws(() => clone(nextId('traversal'), sourceId, false), /manifest_path_invalid/);
    changed.repositories[0].files[1].relative_path = manifest.repositories[0].files[1].relative_path;
    changed.signing_key_fingerprint = '0'.repeat(40);
    replaceManifest(changed);
    assert.throws(() => clone(nextId('provenance'), sourceId, false), /repository_manifest_untrusted/);
    fs.writeFileSync(path.join(source, 'manifest.json'), original);
    fs.writeFileSync(path.join(source, 'payload/repository-manifest.json'), original);
    const repodata = path.dirname(metadata), moved = `${repodata}-fixture`;
    fs.renameSync(repodata, moved);
    try {
      fs.symlinkSync(moved, repodata, process.platform === 'win32' ? 'junction' : 'dir');
      assert.throws(() => clone(nextId('symlink'), sourceId, false), /staged_file_parent_invalid/);
      fs.unlinkSync(repodata);
    } finally {
      if (!fs.existsSync(repodata)) fs.renameSync(moved, repodata);
    }
    assert(fs.readFileSync(path.join(source, 'manifest.json')).equals(original));
    assert(fs.readFileSync(metadata).equals(bytes));
    assert.throws(() => parseArgs(['clone', '--run-id', 'x', '--run-id', 'y', '--from-run', 'z']), /argument_duplicate/);
    assert.throws(() => parseArgs(['clone', '--run-id', 'x', '--from-run', 'z', '--url', 'https://example.test']), /argument_invalid/);
    assert.throws(() => parseArgs(['clone', '--run-id', 'x']), /from_run_required/);
    return ['copy_hashes', 'payload_identity', 'source_unchanged', 'existing_destination', 'corruption', 'traversal', 'provenance', 'hardlink', 'symlink', 'strict_arguments'];
  } finally {
    for (const id of runs) {
      const target = path.resolve(cache, runIdOf(id));
      if (target !== path.join(cache, id) || !target.startsWith(`${cache}${path.sep}`) || !id.startsWith(prefix)) fail('test_cleanup_outside_cache');
      fs.rmSync(target, {recursive: true, force: true});
    }
  }
}

async function stageRepository(run, runId, repo) {
  const repomdUrl = new URL('repodata/repomd.xml', repo.baseUrl).toString();
  const repomd = await fetchOfficial(validateRepoUrl(repomdUrl, repo.baseUrl).toString());
  const files = [{
    type: 'repomd',
    relative_path: 'repodata/repomd.xml',
    url: repomdUrl,
    length: repomd.length,
    bytes: repomd.length,
    checksum_sha256: sha256(repomd),
    checksum_type: 'sha256',
    source: `.cache/alma-web-repositories/${runId}/repositories/${repo.id}/repodata/repomd.xml`,
    destination: `repositories/${repo.id}/repodata/repomd.xml`,
  }];
  writeExclusive(destination(run, `repositories/${repo.id}/repodata/repomd.xml`), repomd, `${repo.id}_repomd`, MAX_FILE_BYTES);
  const entries = metadataEntries(repomd.toString('utf8'), repo);
  for (const entry of entries) {
    const url = new URL(entry.relativePath, repo.baseUrl).toString();
    const bytes = await fetchOfficial(validateRepoUrl(url, repo.baseUrl).toString(), entry.length, entry.checksum);
    writeExclusive(destination(run, `repositories/${repo.id}/${entry.relativePath}`), bytes, `${repo.id}_${entry.type}`, MAX_FILE_BYTES);
    files.push({
      type: entry.type,
      relative_path: entry.relativePath,
      url,
      length: bytes.length,
      bytes: bytes.length,
      checksum_sha256: entry.checksum,
      checksum_type: 'sha256',
      source: `.cache/alma-web-repositories/${runId}/repositories/${repo.id}/${entry.relativePath}`,
      destination: `repositories/${repo.id}/${entry.relativePath}`,
    });
  }
  return {
    id: repo.id,
    base_url: repo.baseUrl,
    required_metadata: [...repo.required],
    files,
  };
}

async function stage(runId) {
  const run = workspace(runId, true);
  const repositories = [];
  for (const repo of Object.values(REPOSITORIES)) repositories.push(await stageRepository(run, runId, repo));
  const stagedBytes = repositories.flatMap(repo => repo.files).reduce((total, file) => total + file.length, 0);
  if (stagedBytes > MAX_STAGE_BYTES) fail('repository_stage_too_large');
  const manifest = {
    schema_version: 1,
    kind: 'alma-web-repository-stage',
    phase: 'stage',
    run_id: runId,
    release: RELEASE,
    architecture: ARCH,
    cloud_image_sha256: IMAGE_SHA256,
    signing_key_fingerprint: ALMA_KEY_FINGERPRINT,
    network_policy: 'host_https_official_only_guest_none',
    repositories,
  };
  writeJson(run, 'manifest.json', manifest, 'repository_manifest');
  writeJson(run, 'payload/repository-manifest.json', manifest, 'repository_payload_manifest');
  for (const repo of repositories) writeJson(run, `repositories/${repo.id}/manifest.json`, {
    schema_version: 1,
    kind: 'alma-web-repository',
    phase: 'stage',
    run_id: runId,
    release: RELEASE,
    architecture: ARCH,
    repository: repo,
  }, `${repo.id}_manifest`);
  publishLatest(runId, run, manifest);
  return {phase: 'stage', run_id: runId, repositories: repositories.map(repo => ({id: repo.id, files: repo.files.length})), manifest: `.cache/alma-web-repositories/${runId}/payload/repository-manifest.json`};
}

function readJson(file, label, maxBytes = MAX_REPORT_BYTES) {
  const stat = assertRegularFile(file, label, maxBytes);
  let value;
  try { value = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { fail(`${label}_json_invalid`); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label}_shape_invalid`);
  if (stat.size > maxBytes) fail(`${label}_too_large`);
  return value;
}

function readStageManifest(run) {
  const manifestFile = sourceFile(run, 'manifest.json', 'repository_manifest', MAX_REPORT_BYTES);
  const manifest = readJson(manifestFile, 'repository_manifest');
  if (manifest.schema_version !== 1 || manifest.kind !== 'alma-web-repository-stage' || manifest.phase !== 'stage' || manifest.run_id !== path.basename(run) || manifest.release !== RELEASE || manifest.architecture !== ARCH || manifest.cloud_image_sha256 !== IMAGE_SHA256 || manifest.signing_key_fingerprint !== ALMA_KEY_FINGERPRINT) fail('repository_manifest_untrusted');
  if (!['host_https_official_only_guest_none', 'offline_verified_metadata_clone_guest_none'].includes(manifest.network_policy)) fail('repository_manifest_network_invalid');
  if (manifest.network_policy === 'offline_verified_metadata_clone_guest_none' && (runIdOf(manifest.from_run) === manifest.run_id || !/^[a-f0-9]{64}$/.test(manifest.source_manifest_sha256))) fail('repository_manifest_clone_invalid');
  const payload = sourceFile(run, 'payload/repository-manifest.json', 'repository_payload_manifest', MAX_REPORT_BYTES);
  if (!fs.readFileSync(manifestFile).equals(fs.readFileSync(payload))) fail('repository_payload_manifest_mismatch');
  if (!Array.isArray(manifest.repositories) || manifest.repositories.length !== 2) fail('repository_manifest_repositories_invalid');
  const seenRepos = new Set();
  let total = 0;
  for (const repo of manifest.repositories) {
    if (!repo || !Object.prototype.hasOwnProperty.call(REPOSITORIES, repo.id) || seenRepos.has(repo.id) || repo.base_url !== REPOSITORIES[repo.id].baseUrl || !Array.isArray(repo.files) || repo.files.length === 0 || repo.files.length > 33 || JSON.stringify(repo.required_metadata) !== JSON.stringify(REPOSITORIES[repo.id].required)) fail('repository_manifest_entry_invalid');
    seenRepos.add(repo.id);
    const seenTypes = new Set(), seenPaths = new Set();
    for (const file of repo.files) {
      if (!file || typeof file.relative_path !== 'string' || typeof file.url !== 'string' || !/^[a-f0-9]{64}$/.test(file.checksum_sha256) || file.checksum_type !== 'sha256' || !Number.isSafeInteger(file.length) || file.length <= 0 || file.length > MAX_FILE_BYTES || file.bytes !== file.length || (file.type !== 'repomd' && !STAGED_METADATA_TYPES.has(file.type)) || seenTypes.has(file.type) || seenPaths.has(file.relative_path)) fail('repository_manifest_file_invalid');
      const relative = safeRelative(file.relative_path, 'manifest');
      if (!relative.startsWith('repodata/') || (file.type === 'repomd' ? relative !== 'repodata/repomd.xml' : !/\.(?:gz|xz|zst|zck|bz2|xml)$/.test(relative))) fail('repository_manifest_file_invalid');
      const destinationPath = `repositories/${repo.id}/${relative}`;
      if (file.destination !== destinationPath || file.source !== `.cache/alma-web-repositories/${manifest.run_id}/${destinationPath}` || file.url !== new URL(relative, repo.base_url).toString()) fail('repository_manifest_file_provenance_invalid');
      seenTypes.add(file.type);
      seenPaths.add(relative);
      validateRepoUrl(file.url, repo.base_url);
      const staged = sourceFile(run, destinationPath, 'staged_file');
      const actual = assertRegularFile(staged, 'staged_file', MAX_FILE_BYTES);
      if (actual.size !== file.length || sha256(fs.readFileSync(staged)) !== file.checksum_sha256) fail('staged_file_checksum_invalid');
      total += actual.size;
      if (total > MAX_STAGE_BYTES) fail('repository_stage_too_large');
    }
    if (!seenTypes.has('repomd')) fail('repository_repomd_missing');
    const repomd = sourceFile(run, `repositories/${repo.id}/repodata/repomd.xml`, 'staged_repomd');
    const declared = metadataEntries(fs.readFileSync(repomd, 'utf8'), REPOSITORIES[repo.id]);
    if (declared.length !== repo.files.length - 1 || declared.some(entry => !repo.files.some(file => file.type === entry.type && file.relative_path === entry.relativePath && file.length === entry.length && file.checksum_sha256 === entry.checksum))) fail('repository_metadata_inventory_mismatch');
  }
  return manifest;
}

function clone(runId, fromRun, publish = true) {
  runIdOf(runId);
  runIdOf(fromRun);
  if (runId === fromRun) fail('clone_same_run_rejected');
  const source = workspace(fromRun);
  // Validate every byte and its fixed provenance before creating a destination.
  const original = readStageManifest(source);
  const sourceManifest = fs.readFileSync(sourceFile(source, 'manifest.json', 'repository_manifest', MAX_REPORT_BYTES));
  const run = workspace(runId, true);
  const repositories = original.repositories.map(repo => ({
    ...repo,
    files: repo.files.map(file => ({...file, source: `.cache/alma-web-repositories/${runId}/${file.destination}`})),
  }));
  for (const repo of repositories) for (const file of repo.files) {
    const bytes = fs.readFileSync(sourceFile(source, file.destination, 'clone_source'));
    if (bytes.length !== file.length || sha256(bytes) !== file.checksum_sha256) fail('clone_source_changed');
    writeExclusive(destination(run, file.destination), bytes, 'clone_metadata', MAX_FILE_BYTES);
  }
  const manifest = {...original, run_id: runId, from_run: fromRun, source_manifest_sha256: sha256(sourceManifest),
    network_policy: 'offline_verified_metadata_clone_guest_none', repositories};
  for (const repo of repositories) writeJson(run, `repositories/${repo.id}/manifest.json`, {
    schema_version: 1, kind: 'alma-web-repository', phase: 'stage', run_id: runId,
    release: RELEASE, architecture: ARCH, repository: repo,
  }, `${repo.id}_manifest`);
  writeJson(run, 'payload/repository-manifest.json', manifest, 'repository_payload_manifest');
  // The admission marker is last: a failed copy never becomes a valid stage.
  writeJson(run, 'manifest.json', manifest, 'repository_manifest');
  if (publish) publishLatest(runId, run, manifest);
  return {phase: 'clone', run_id: runId, from_run: fromRun, source_manifest_sha256: manifest.source_manifest_sha256,
    repositories: repositories.map(repo => ({id: repo.id, files: repo.files.length})),
    manifest: `.cache/alma-web-repositories/${runId}/payload/repository-manifest.json`};
}

function reportPath(run, reportArg) {
  if (reportArg === undefined) return path.join(run, 'payload', 'resolve-report.json');
  const relative = safeRelative(reportArg, 'report');
  const allowedRoots = ['alma-web-repositories', 'alma-web-packages', 'alma-web-runtime'].map(name => path.join(ROOT, '.cache', name));
  const file = path.resolve(ROOT, ...relative.split('/'));
  if (!allowedRoots.some(root => file.startsWith(`${root}${path.sep}`))) fail('report_outside_cache');
  return file;
}

function validateResolveReport(file, expectedRepositoryManifestSha256) {
  const report = readJson(file, 'resolve_report');
  if (report.schema_version !== 1 || report.kind !== 'alma-web-package-resolve' || report.phase !== 'resolve' || report.passed !== true || report.release !== RELEASE || report.architecture !== ARCH || report.repository_manifest_sha256 !== expectedRepositoryManifestSha256) fail('resolve_report_untrusted');
  if (!Array.isArray(report.packages) || report.packages.length === 0 || report.packages.length > MAX_PACKAGES) fail('resolve_report_packages_invalid');
  for (const pkg of report.packages) {
    if (!pkg || typeof pkg !== 'object' || !Object.prototype.hasOwnProperty.call(REPOSITORIES, pkg.repository) || typeof pkg.nevra !== 'string' || !pkg.nevra || typeof pkg.relative_path !== 'string' || !/^[a-f0-9]{64}$/.test(pkg.checksum_sha256) || !Number.isSafeInteger(pkg.size) || pkg.size <= 0 || pkg.size > MAX_FILE_BYTES) fail('resolve_report_package_invalid');
    const relative = safeRelative(pkg.relative_path, 'rpm');
    if (!relative.startsWith('Packages/') || !relative.endsWith('.rpm')) fail('resolve_report_package_path_invalid');
  }
  return report;
}

async function download(runId, reportArg) {
  const run = workspace(runId, false);
  readStageManifest(run);
  const sourceReport = reportPath(run, reportArg);
  const payloadReport = path.join(run, 'payload', 'resolve-report.json');
  const sourceBytes = fs.readFileSync(sourceReport);
  const report = validateResolveReport(sourceReport, sha256(fs.readFileSync(path.join(run, 'payload', 'repository-manifest.json'))));
  if (path.resolve(sourceReport) !== path.resolve(payloadReport)) writeExclusive(payloadReport, sourceBytes, 'resolve_report');
  const rpmEntries = [];
  let total = 0;
  for (const [index, pkg] of report.packages.entries()) {
    const repo = REPOSITORIES[pkg.repository];
    const relative = safeRelative(pkg.relative_path, 'rpm');
    const url = new URL(relative, repo.baseUrl).toString();
    validateRepoUrl(url, repo.baseUrl);
    total += pkg.size;
    if (total > MAX_STAGE_BYTES) fail('rpm_download_set_too_large');
    const bytes = await fetchOfficial(url, pkg.size, pkg.checksum_sha256);
    const safeNevra = pkg.nevra.replace(/[^A-Za-z0-9._+~-]/g, '_');
    if (!/^[A-Za-z0-9][A-Za-z0-9._+~-]{0,240}$/.test(safeNevra)) fail('rpm_nevra_invalid');
    const filename = `${safeNevra}.rpm`;
    const target = `packages/${filename}`;
    if (rpmEntries.some(entry => entry.file === target)) fail('rpm_nevra_collision');
    writeExclusive(destination(run, target), bytes, 'rpm', MAX_FILE_BYTES);
    rpmEntries.push({
      repository: pkg.repository,
      nevra: pkg.nevra,
      relative_path: relative,
      checksum_sha256: pkg.checksum_sha256,
      checksum_type: 'sha256',
      size: bytes.length,
      bytes: bytes.length,
      file: target,
      source: `.cache/alma-web-repositories/${runId}/${target}`,
      destination: target,
      url,
    });
  }
  const rpmManifest = {
    schema_version: 1,
    kind: 'alma-web-rpm-stage',
    phase: 'download',
    run_id: runId,
    release: RELEASE,
    architecture: ARCH,
    cloud_image_sha256: IMAGE_SHA256,
    signing_key_fingerprint: ALMA_KEY_FINGERPRINT,
    packages: rpmEntries,
  };
  writeJson(run, 'payload/package-manifest.json', rpmManifest, 'rpm_manifest');
  return {phase: 'download', run_id: runId, packages: rpmEntries.length, payload: `.cache/alma-web-repositories/${runId}/payload/package-manifest.json`};
}

function parseArgs(argv) {
  const [phase, ...rest] = argv;
  if (phase === 'self-test') {
    if (rest.length) fail('self_test_arguments_invalid');
    return {phase};
  }
  if (!['stage', 'download', 'clone'].includes(phase)) fail('phase_must_be_stage_download_or_clone');
  const args = {phase};
  const seen = new Set();
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    if (seen.has(flag)) fail('argument_duplicate');
    seen.add(flag);
    if (flag === '--run-id' && rest[index + 1]) args.runId = rest[++index];
    else if (phase === 'download' && flag === '--report' && rest[index + 1]) args.report = rest[++index];
    else if (phase === 'clone' && flag === '--from-run' && rest[index + 1]) args.fromRun = rest[++index];
    else fail('argument_invalid');
  }
  if (!args.runId) fail('run_id_required');
  if (phase === 'clone' && !args.fromRun) fail('from_run_required');
  runIdOf(args.runId);
  if (args.fromRun) runIdOf(args.fromRun);
  return args;
}

try {
  const args = parseArgs(process.argv.slice(2));
  const result = args.phase === 'self-test' ? selfTest() : args.phase === 'stage' ? await stage(args.runId) : args.phase === 'clone' ? clone(args.runId, args.fromRun) : await download(args.runId, args.report);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`Alma web repository preparation failed: ${error instanceof Error ? error.message : 'operation_failed'}\n`);
  process.exitCode = 1;
}
