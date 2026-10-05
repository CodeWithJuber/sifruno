import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {digest, regular, relative} from '../hostwebruntime-mechanics/admission.mjs';

export function layout(primary, owner, here) {
  assert(path.isAbsolute(primary) && !/[\r\n,]/.test(primary));
  primary = path.resolve(primary);
  assert.equal(fs.realpathSync(primary).toLowerCase(), primary.toLowerCase());
  assert([primary, path.join(primary, '.worktrees/release-plan-sol')].some(p => p.toLowerCase() === owner.toLowerCase()));
  assert.equal(here.toLowerCase(), path.join(owner, 'lab/hostwebruntime-serving-host').toLowerCase());
  for (const root of [primary, owner]) {
    const modules = [...fs.readFileSync(regular(root, 'go.mod', 65536), 'utf8').matchAll(/^module[ \t]+([^\r\n]+)\r?$/gm)];
    assert(modules.length === 1 && modules[0][1].trim() === 'sifruno');
  }
  return primary;
}
export function logicalSource(recordedRoot, old) {
  const rel = path.win32.relative(recordedRoot, old).replaceAll('\\', '/');
  relative(rel.replaceAll('@', '_'));
  assert(/^(?:internal\/(?:hostaccounts|hostweb|hostwebgeneration|securestate)\/[A-Za-z0-9_.-]+\.go|\.worktrees\/native-web-executor-sol\/(?:internal\/hostwebruntime\/[A-Za-z0-9_.-]+|lab\/hostwebruntime-serving\/[A-Za-z0-9_.-]+|\.cache\/hostwebruntime-serving\/(?:canonical-overlay\.json|canonical-pins\.json|dependencies\.json|canonical\.go\.(?:mod|sum)))|\.cache\/go-mod\/(?:golang.org\/x\/sys@v0.48.0\/unix|go.etcd.io\/bbolt@v1.5.0(?:\/errors|\/internal\/(?:common|freelist))?)\/[A-Za-z0-9_.-]+)$/.test(rel), 'Unadmitted serving dependency');
  return rel;
}
export function filePin(root, entry, max = 64 * 1024 * 1024) {
  // '@' occurs only in the two admitted module-cache roots, never CLI input.
  relative(entry.path.replaceAll('@', '_'));
  const abs = path.join(root, ...entry.path.split('/'));
  const p = regular(path.dirname(abs), path.basename(abs), max);
  const b = fs.readFileSync(p);
  assert.equal(digest(b), entry.sha256, 'Serving input hash mismatch: ' + entry.path);
  if (entry.bytes !== undefined) assert.equal(b.length, entry.bytes);
  return {path: entry.path, bytes: b.length, sha256: entry.sha256};
}
export function buildAdmission(pins,nonce,packageBytes) {
  assert(/^[a-f0-9]{24}$/.test(nonce));
  const result={schema_version:1,kind:'trusted-disposable-alma9-runtime-serving',nonce,prepared_image_sha256:pins.prepared_image.sha256,fixture_sha256:pins.fixture.sha256,helper_sha256:pins.helper.sha256,source_catalog_sha256:pins.serving_manifest.sha256,package_report_sha256:digest(packageBytes),driver_sha256:pins.driver.sha256,test_sha256:pins.test_elf.sha256,zero_external_nics:true};
  for(const [key,value] of Object.entries(result))if(key.endsWith('sha256'))assert(/^[a-f0-9]{64}$/.test(value));
  return result;
}
export function preparedPackages(manifest) {
  assert(manifest.schema_version === 1 && manifest.kind === 'alma-web-rpm-stage' && manifest.release === '9.8' && manifest.architecture === 'x86_64' && manifest.packages.length === 18);
  assert.equal(manifest.signing_key_fingerprint, 'BF18AC2876178908D6E71267D36CB86CB86B3716');
  const seen = new Set(), packages = manifest.packages.map(p => {
    const match = /^([A-Za-z0-9._+-]+)-[0-9]+:/.exec(p.nevra);
    assert(match && /^packages\/[A-Za-z0-9_.+-]+\.rpm$/.test(p.file));
    assert(p.source === '.cache/alma-web-repositories/webrepo-20261005-php83/' + p.file && p.destination === p.file);
    assert(/^[a-f0-9]{64}$/.test(p.checksum_sha256) && p.checksum_type === 'sha256' && p.size === p.bytes && Number.isSafeInteger(p.bytes) && p.bytes > 0 && p.bytes < 32 * 1024 * 1024);
    assert(!seen.has(match[1])); seen.add(match[1]);
    return {name: match[1], nevra: p.nevra, filename: path.posix.basename(p.file), sha256: p.checksum_sha256, bytes: p.bytes};
  });
  assert.deepEqual([...seen].sort(), ['almalinux-logos-httpd','apr','apr-util','apr-util-bdb','apr-util-openssl','httpd','httpd-core','httpd-filesystem','httpd-tools','mod_http2','mod_lua','mod_ssl','nginx-filesystem','php-common','php-fpm','php-process','sscg','mailcap'].sort());
  return {schema_version: 1, kind: 'alma9-prepared-web-packages', packages};
}
export function validateLineage(host, install, pins, original) {
  assert(host.schema_version === 1 && host.phase === 'install' && host.passed === true && host.code === 0 && host.timedout === false && host.output_limit === false && host.input_stable === true);
  assert.equal(host.image_sha256, original.sha256); assert.equal(host.backing_sha256, original.sha256);
  assert.equal(host.backing_source, original.path); assert.equal(host.overlay_sha256, pins.prepared_image.sha256);
  assert(host.image_checksum_signature_verified === true && host.external_nic === false && host.host_shares === false && host.global_install === false && host.production_mutated === false);
  assert.equal(host.package_manifest.sha256, pins.package_manifest.sha256); assert.equal(host.package_manifest.packages, 18);
  assert(install.schema_version === 1 && install.kind === 'alma-web-package-install' && install.passed === true && install.release === '9.8' && install.architecture === 'x86_64' && install.resolved_packages === 18 && install.installed.length === 18 && install.signatures.length === 18);
  assert(install.network.guest_external_nic === false && install.network.external_network === false && install.network.repositories === 'disabled_local_rpms_only');
  for (const p of [install.privilege_profile.before, install.privilege_profile.after]) assert(p.selinux_enforce === 1 && p.no_new_privs === 0 && p.network_capabilities_present.length === 0 && p.profile === 'install_stock_nnp0_signed_pinned_rpms');
  assert(install.signatures.every(s => s.verification === 'ok' && s.key_id === 'B86B3716'));
}
export function verifySources(primary, pins, add) {
  const read = entry => JSON.parse(fs.readFileSync(regular(primary, entry.path), 'utf8'));
  const m = read(pins.serving_manifest);
  assert(m.kind === 'serving-driver-candidate' && m.freeze === 1 && m.runtime_freeze === 2 && m.runtime_pins_unchanged === true && m.canonical_pins_unchanged === true);
  assert.equal(m.driver_sha256, pins.driver.sha256); assert.equal(m.linux_test_sha256, pins.test_elf.sha256);
  assert.equal(m.runtime_manifest_sha256, '5fffdaada446ca5068258d43888ed34e15cb4492465bce4e9ffb1f27463f066c');
  assert(m.source_files.length === 7 && m.runtime_files.length === 10 && m.canonical_files.length === 17 && m.build_metadata.length === 5 && m.dependency_count === 90);
  const tool = m.go_tool_path.replaceAll('/', '\\'), suffix = '\\.tools\\go\\bin\\go.exe';
  assert(tool.endsWith(suffix)); const recordedRoot = tool.slice(0, -suffix.length);
  add({path: '.tools/go/bin/go.exe', sha256: m.go_tool_sha256});
  for (const f of [...m.source_files, ...m.runtime_files]) {
    assert(/^(?:lab\/hostwebruntime-serving|internal\/hostwebruntime)\/[A-Za-z0-9_.-]+$/.test(f.path));
    add({...f, path: '.worktrees/native-web-executor-sol/' + f.path});
  }
  const known = new Map();
  for (const f of [...m.canonical_files, ...m.build_metadata]) {
    const rel = logicalSource(recordedRoot, f.path); add({...f, path: rel}); known.set(rel, f.sha256);
  }
  const metadataRoot = '.worktrees/native-web-executor-sol/.cache/hostwebruntime-serving/';
  const dependencies = read({path: metadataRoot + 'dependencies.json'});
  assert(dependencies.length === 90);
  for (const f of dependencies) add({...f, path: logicalSource(recordedRoot, f.path)});
  const overlay = read({path: metadataRoot + 'canonical-overlay.json'});
  assert.deepEqual(Object.keys(overlay), ['Replace']); assert.equal(Object.keys(overlay.Replace).length, 17);
  for (const [from, to] of Object.entries(overlay.Replace)) {
    const origin = path.win32.relative(recordedRoot, from).replaceAll('\\', '/');
    assert(/^\.worktrees\/native-web-executor-sol\/internal\/(?:hostaccounts|hostweb|hostwebgeneration|securestate)\/[A-Za-z0-9_.-]+\.go$/.test(origin));
    const target = logicalSource(recordedRoot, to); assert(known.has(target));
  }
  add({path: 'go.mod', sha256: known.get(metadataRoot + 'canonical.go.mod')});
  add({path: 'go.sum', sha256: known.get(metadataRoot + 'canonical.go.sum')});
  return m;
}
