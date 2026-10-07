import assert from 'node:assert/strict';

// These identities are independent of the inventories they admit. Changing an
// approved tool/catalogue requires a reviewed source change, not a new self-pin.
export const TOOL_AUTHORITIES = Object.freeze({
 '.tools/linuxguest/prepared.json':'211e7d98ce793a4302be5f4826b9f61dcfcce0fb410e18ff551835d517456914',
 '.tools/linuxguest/alma9/verified.json':'1feae2b3ddf046edc6ab4ff65d57b78f9d1c9428174fc79eabe0c34de246368f',
 '.tools/linuxguest/qemu-20260811/qemu-system-x86_64.exe':'47d57a6072e0bb3bd98f87926eb129eb1736dfe818c67b3b81ef7ce4edd0b3cd',
 '.tools/linuxguest/qemu-20260811/qemu-img.exe':'9d930582d0d574bb106d89982c547688e10b8f356192d302cc3d0ae4e8674534',
});

// readPin is the runner's existing bounded regular-file/no-link admission.
// No partial set is returned if any input is absent or differs.
export function admitToolPins(readPin) {
 const pins=[];
 for(const [name,expected] of Object.entries(TOOL_AUTHORITIES)) {
  const actual=readPin(name);
  assert(actual&&actual.path===name&&actual.sha256===expected,'fixed_tool_identity');
  pins.push(actual);
 }
 return pins;
}
