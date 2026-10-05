import assert from 'node:assert/strict';
import {test} from 'node:test';
import {jsonObjects} from './freeze.mjs';
test('sequential Go objects preserve quoted braces and escapes',()=>assert.deepEqual(jsonObjects('{"Dir":"a}b","X":[{"quote":"\\\"{"}]}\n{"Dir":"next"}'),[{Dir:'a}b',X:[{quote:'"{'}]},{Dir:'next'}]));
for(const raw of ['', '{', '{}{', '[]', '{"a":1}\ntrailing'])test('reject incomplete or unexpected metadata '+JSON.stringify(raw),()=>assert.throws(()=>jsonObjects(raw)));
