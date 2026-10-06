import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const ROLES = ['broker_state', 'managed_homes', 'socket_parent', 'controller_state'];
export const ROOT_TESTS = ['TestControllerLayoutNativeFreshPreparation', 'TestControllerLayoutNativeExistingNoAdoption', 'TestControllerLayoutNativeRefusalNoAdditions', 'TestControllerLayoutNativePartialCancellationPreserves', 'TestControllerLayoutNativePinnedOwnership', 'TestControllerLayoutNativeRestrictiveUmask'];
export const CASES = ['controller_populated', 'socket_parent_populated', 'controller_wrong_mode', 'controller_symlink', 'socket_nontraversable_parent', 'unknown_argument'];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

export function decodeLayoutSerial(serial, nonce) {
  assert(/^[0-9a-f]{32}$/.test(nonce) && Buffer.byteLength(serial) <= 2*1024*1024);
  const clean = serial.toString().replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replaceAll('\r', '');
  const begin = `\nSIFRUNO_LAYOUT_BEGIN_${nonce}\n`, end = `\nSIFRUNO_LAYOUT_END_${nonce}\n`;
  assert.equal(clean.split(begin).length, 2);
  assert.equal(clean.split(end).length, 2);
  const a = clean.indexOf(begin) + begin.length, b = clean.indexOf(end, a);
  assert(b >= a);
  const raw = clean.slice(a, b).trimEnd();
  assert(raw.length <= 131072);
  const guest = JSON.parse(raw);
  assert.equal(JSON.stringify(guest), raw); // Duplicates and alternate encodings refused.
  assert(guest.passed === true && guest.nonce === nonce && guest.schema_version === 1 && guest.scope === 'fresh_existing_controller_layout_NSS_only_adapted_Alma9_8');
  const exitLines = clean.split('\n').filter(l => l.startsWith(`SIFRUNO_LAYOUT_EXIT_${nonce}`));
  assert.deepEqual(exitLines, [`SIFRUNO_LAYOUT_EXIT_${nonce}_0`]);
  assert(clean.indexOf(`\n${exitLines[0]}\n`) >= b + end.length - 1);
  assert(guest.stock.exit_code === 1 && guest.stock.before_sha256 === guest.stock.after_sha256 && guest.stock.report.ready === false);
  assert(guest.plan.exit_code === 0 && guest.plan.before_sha256 === guest.plan.after_sha256 && guest.plan.report.read_only === true);
  assert(guest.apply.exit_code === 0 && guest.apply.report.read_only === false && guest.apply.report.directories.length === 4 && guest.apply.report.directories.every(d => d.action === 'created'));
  assert.deepEqual(guest.prepared_directories.map(x => x.role), ROLES);
  assert.deepEqual(guest.prepared_directories.map(x => x.uid), [0,0,0,65534]);
  assert.deepEqual(guest.prepared_directories.map(x => x.mode), ['0700','0755','0755','0700']);
  assert(guest.prepared_directories.every(x => x.empty === true));
  assert(guest.repeat.exit_code === 0 && guest.repeat.before_sha256 === guest.repeat.after_sha256 && guest.repeat.report.directories.length === 4 && guest.repeat.report.directories.every(d => d.action === 'admitted_existing'));
  assert.deepEqual(guest.conflicts.map(x => x.case), CASES);
  assert(guest.conflicts.every(x => x.before_sha256 === x.after_sha256 && x.owned_child_exited === true && x.exit_code === (x.case === 'unknown_argument' ? 2 : 1)));
  assert(guest.core_tests.exit_code === 0 && guest.core_tests.skips === 0);
  assert.deepEqual(guest.core_tests.required, ROOT_TESTS);
  assert.equal(typeof guest.core_tests.stdout_base64, 'string');
  const testLog = Buffer.from(guest.core_tests.stdout_base64, 'base64');
  assert.equal(testLog.toString('base64'), guest.core_tests.stdout_base64);
  assert.equal(sha(testLog), guest.core_tests.stdout_sha256);
  const testLines = testLog.toString().split('\n');
  assert(testLog.length < 131072 && !testLog.toString().includes('--- SKIP:'));
  for(const name of ROOT_TESTS) assert.equal(testLines.filter(l => new RegExp('^--- PASS: '+name+' \\(\\d+(?:\\.\\d+)?s\\)$').test(l)).length, 1);
  assert.equal(testLines.filter(l => l === 'PASS').length, 1);
  assert.equal(testLines.at(-2), 'PASS');
  assert(guest.stock_mail_and_identities_unchanged === true && guest.inputs_unchanged === true && guest.account_created === false && guest.socket_created === false);
  return guest;
}
