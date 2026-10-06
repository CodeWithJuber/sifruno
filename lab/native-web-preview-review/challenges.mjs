import assert from 'node:assert/strict';
// Pure serial mutation battery. The caller supplies a frozen decoder and valid,
// independent synthetic frame; this helper neither spawns nor imports run mode.
export function challengeFraming(decode, serial, nonce, labels) {
  assert.equal(decode(serial,nonce).passed,true);
  const {begin,end,exit}=labels;
  const cases={duplicate_frame:serial+serial,duplicate_exit:serial+exit+'\n',early_exit:exit+'\n'+serial,missing_exit:serial.replace(exit+'\n',''),nonzero_exit:serial.replace(exit,exit.replace(/_0$/,'_1')),exit_suffix:serial.replace(exit,exit+'_extra'),wrong_nonce:serial.replaceAll(nonce,'ff'.repeat(16)),missing_end:serial.replace(end,''),duplicate_json_key:serial.replace('"passed":true','"passed":false,"passed":true')};
  for(const [name,value] of Object.entries(cases)) assert.throws(()=>decode(value,nonce),name);
  return Object.keys(cases);
}
export function challengeMutations(validate, good, mutations) {
  validate(structuredClone(good));
  const names=[];
  for(const [name,change] of Object.entries(mutations)){const value=structuredClone(good);change(value);assert.throws(()=>validate(value),name);names.push(name);}
  return names;
}
