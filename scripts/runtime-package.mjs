// Pure runtime package policy shared by compilation, notices and metadata.
const targets = new Set(['windows-amd64', 'windows-arm64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64']);
const existingCommands = ['sifruno', 'panelctl', 'panelpreview', 'hostbroker'];

export function commandsForTarget(target) {
  if (!targets.has(target)) throw new Error('Unknown runtime package target');
  return target.startsWith('linux-') ? [...existingCommands, 'hostsetup'] : [...existingCommands];
}

export function commandMetadata(target) {
  const included = commandsForTarget(target);
  return { included_commands: included,
    unavailable_commands: included.includes('hostsetup') ? [] : [{ name: 'hostsetup', reason: 'native_linux_only' }] };
}

export function executableFixup(target) {
  if (target.startsWith('windows-')) { commandsForTarget(target); return ''; }
  return `If your archive extractor did not preserve executable modes, run chmod +x ${commandsForTarget(target).map(name => `bin/${name}`).join(' ')}.`;
}

export function layoutQuickstart(target) {
  if (!commandsForTarget(target).includes('hostsetup')) return '';
  const flags = '--state /run/sifruno-broker --socket /run/sifruno-socket/broker.sock --homes /var/lib/sifruno-homes --controller-uid "$CONTROLLER_UID" --controller-state /var/lib/sifruno-controller';
  return `
## Optional Linux fresh layout preparation

hostsetup is included for this Linux compile/archive target. This builder does
not execute it or qualify this target's runtime. Run only as effective UID/GID 0,
with an explicitly verified existing dedicated local nonroot controller UID.
Set CONTROLLER_UID yourself to its observed canonical decimal UID (1 through
4294967294). This package supplies no default, fallback or identity lookup.
An unset/invalid value is refused; no controller identity is created.

Select four dedicated, nonoverlapping absent or exact-empty leaves. Their parents
must already exist with trusted root-owned, nonwritable, nonsymlink ancestors.
Socket/controller ancestors require other-execute; the socket leaf must be absent.
Required UID:GID/modes: broker state 0:0/0700, homes 0:0/0755, socket parent
0:0/0755, controller state selected UID:0/0700. No existing metadata is repaired.
Existing files-only NSS and supported host policy must pass unchanged. Untouched
stock NSS or mail defaults may refuse admission. This is not a stock-host
installer and rewrites no NSS or host policy.

First inspect the read-only plan. An apply is a separate explicit decision:

\`\`\`sh
# Set CONTROLLER_UID explicitly to the verified dedicated existing canonical UID.
./bin/hostsetup --plan ${flags}
# Run this only after reviewing the plan and deciding to create the declared leaves:
./bin/hostsetup --apply ${flags}
\`\`\`

Partial additions remain on refusal; there is no destructive automatic rollback.
A ready layout is not broker startup permission, persisted recovery certification,
service installation or full installer/vendor/all-OS acceptance. These commands
create no store or socket and start no service. Linux ARM64 remains a compile and
archive target here; the earlier narrow Alma9.8 AMD64 guest observations do not
qualify ARM64 execution. Separately check broker admission before any startup.
`;
}
