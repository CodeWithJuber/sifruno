import assert from 'node:assert/strict';
export const TOPS=['TestInstallationFixedProfile','TestInstallationRefusesBeforeInspection','TestInstallationFinalCancellationAndScopedSuccess','TestInstallationLinuxReadOnlyAndDigestCompatibility','TestInstallationLinuxRefusalAndCancellation','TestInstallationLinuxRejectsLinksAndMissingInputs'];
export const SUBS=['symlink','hardlink','missing','bad_elf'].map(n=>'TestInstallationLinuxRejectsLinksAndMissingInputs/'+n);
// Independently verify actual Go test-binary output, never guest claimed counts.
export function verifyTestLog(bytes){
 assert(bytes.length>0&&bytes.length<=262144);const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes).replaceAll('\r','');const lines=text.split('\n');assert(!text.includes('--- SKIP:')&&!text.includes('--- FAIL:'));
 const expected=[...TOPS,...SUBS].sort();const runs=lines.filter(l=>/^=== RUN   /.test(l)).map(l=>l.slice(10)).sort();const passes=lines.filter(l=>/^\s*--- PASS: /.test(l)).map(l=>{const m=/^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$/.exec(l);assert(m);return m[1];}).sort();assert.deepEqual(runs,expected);assert.deepEqual(passes,expected);assert.equal(lines.filter(l=>l==='PASS').length,1);assert.equal(lines.at(-2),'PASS');return{top_level:6,subcases:4,skipped:0,failed:0};
}
