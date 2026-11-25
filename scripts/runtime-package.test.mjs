import test from 'node:test';
import assert from 'node:assert/strict';
import {commandsForTarget, commandMetadata, executableFixup, layoutQuickstart} from './runtime-package.mjs';

const base = ['sifruno', 'panelctl', 'panelpreview', 'hostbroker'];

test('Linux targets include hostsetup for compilation and package metadata', () => {
  for (const target of ['linux-amd64', 'linux-arm64']) {
    assert.deepEqual(commandsForTarget(target), [...base, 'hostsetup']);
    assert.deepEqual(commandMetadata(target), {included_commands: [...base, 'hostsetup'], unavailable_commands: []});
    assert.equal(executableFixup(target), 'If your archive extractor did not preserve executable modes, run chmod +x bin/sifruno bin/panelctl bin/panelpreview bin/hostbroker bin/hostsetup.');
  }
});

test('Windows and macOS preserve existing commands and declare hostsetup unavailable', () => {
  for (const target of ['windows-amd64', 'windows-arm64', 'darwin-amd64', 'darwin-arm64']) {
    assert.deepEqual(commandsForTarget(target), base);
    assert.deepEqual(commandMetadata(target), {included_commands: base, unavailable_commands: [{name:'hostsetup', reason:'native_linux_only'}]});
    assert.equal(layoutQuickstart(target), '');
    assert(!executableFixup(target).includes('hostsetup'));
    if (target.startsWith('windows-')) assert.equal(executableFixup(target), '');
  }
});

test('generated Linux instructions preserve exact five-pair plan then explicit apply grammar', () => {
  for (const target of ['linux-amd64', 'linux-arm64']) {
    const doc = layoutQuickstart(target);
    const lines = doc.split('\n').filter(line => line.startsWith('./bin/hostsetup '));
    assert.equal(lines.length, 2);
    for (const [index,line] of lines.entries()) {
      const args = line.split(' ').slice(1);
      assert.equal(args.length,11);
      assert.equal(args[0], index === 0 ? '--plan' : '--apply');
      assert.deepEqual(args.filter((_,i) => i > 0 && i % 2 === 1), ['--state','--socket','--homes','--controller-uid','--controller-state']);
      assert.equal(args[8], '"$CONTROLLER_UID"');
      assert(!line.includes('65534'));
      assert(!line.includes('sudo') && !line.includes('='));
    }
    assert(doc.indexOf('--plan') < doc.indexOf('--apply'));
    assert(doc.includes('4294967294)') && !doc.includes('4294967295'));
    for (const phrase of ['existing dedicated local nonroot controller UID','not execute it or qualify','no destructive automatic rollback','not broker startup permission','rewrites no NSS or host policy','qualify ARM64 execution']) assert(doc.includes(phrase));
  }
});

test('selection metadata returns independent values and rejects unknown targets', () => {
  const selected = commandsForTarget('linux-amd64'); selected.pop();
  const metadata = commandMetadata('windows-amd64'); metadata.included_commands.pop(); metadata.unavailable_commands[0].reason='changed';
  assert.deepEqual(commandsForTarget('linux-amd64'), [...base,'hostsetup']);
  assert.equal(commandMetadata('windows-amd64').unavailable_commands[0].reason,'native_linux_only');
  for (const target of ['linux','freebsd-amd64','windows-x64','linux-arm64;private','']) for (const fn of [commandsForTarget,commandMetadata,executableFixup,layoutQuickstart]) assert.throws(() => fn(target), /^Error: Unknown runtime package target$/);
});


test('pinned upstream notices retain exact canonical bytes in fresh checkouts', async () => {
  const fs = await import('node:fs/promises');
  const {createHash} = await import('node:crypto');
  const attrs = await fs.readFile(new URL('../.gitattributes', import.meta.url), 'utf8');
  for (const name of ['stylex']) {
    assert.equal(attrs.split(/\r?\n/).filter(line => line === 'web/licenses/' + name + '/LICENSE -text').length, 1);
    const bytes = await fs.readFile(new URL('../web/licenses/' + name + '/LICENSE', import.meta.url));
    const provenance = JSON.parse(await fs.readFile(new URL('../web/licenses/' + name + '/provenance.json', import.meta.url), 'utf8'));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), provenance.sha256);
    assert(!bytes.includes(13));
  }
  const builder = await fs.readFile(new URL('./build-runtime.mjs', import.meta.url), 'utf8');
  assert(builder.includes("['.gitattributes', 'LICENSE', 'LICENSING.md',"));
});
