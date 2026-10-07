# Offline populated native preview composition

This is a qualification harness, not a hosting installer. It reuses the existing
signed cached AlmaLinux 9.8 image, pinned QEMU/pycdlib and startup subprocess/NSS
helpers. It never imports or invokes a crash-testing driver.

`node lab/native-web-preview-guest/run.mjs` and `--check` are inert check-only
entry points: they do not build, create an overlay, or start a guest. Pure tests:

```
node --test lab/native-web-preview-guest/report.test.mjs
node --test lab/native-web-preview-guest/tool-pins.test.mjs
```

Only `node lab/native-web-preview-guest/run.mjs --run` builds four Linux binaries
(hostbroker, sifruno, panelctl and supporting hostsetup), admits cached inputs,
builds and rereads the exact ten-entry ISO, and starts one owned offline guest.
Run this only after source freeze, independent review and root run approval.
No native run has been performed by the source author. Synthetic samples are
strictly decoder tests and cannot qualify native composition.

The guest has no NIC, forwarding or host shares. Its nonce marker admits one
fixture beneath `/run/wp<nonce>`. The unmodified stock NSS policy must first
refuse layout planning without adding paths. Only the disposable overlay's NSS
leaf is adapted to files-only; stock mail defaults remain unchanged. The setup
CLI prepares a dedicated root broker and existing UID 65534 controller layout.
Only this fresh controller's generated operator key is read inside the guest.
Keys, cookies and CSRF tokens are never serialized to reports or host logs.

Seven ordered cases cover preview opt-in off (503), unsigned panel API (401),
wrong Unix peer refusal, two actual managed accounts with one suspended,
activation changing the snapshot/bundle metadata, authenticated panelctl matching
API metadata, and owned account home-mode drift refusing preview. A direct
admitted peer preview must also match the populated API result. Native passwd
UID/GID and managed directory ownership/modes are checked. No account is deleted
or restored: all state belongs to the disposable overlay retained as evidence.

Metadata captures preserve bounded raw response bytes as base64 with SHA-256;
the decoder verifies their exact JSON formatting, parsed contents, canonical
account IDs, paired compiler paths, mode/byte/hash bounds, identities and ordered
nonce framing. Captured errors contain only the existing redacted API problem.
Runtime config/jail/TLS paths must remain absent. Existing snapshot recovery
bookkeeping on drift is allowed; this is not a global no-write assertion.

Host receipts bind Go dependency source and EmbedFiles for all four commands,
module go.mod files, tools, payloads and ELF hashes before and after execution.
The cached tool inventory and image-verification receipt have fixed SHA-256
identities, as do both QEMU executables. The runner admits those four identities
before interpreting either inventory or executing a child. Replacing an
inventory together with its file hashes cannot silently establish new trusted
tools. Updating an approved tool requires an independently reviewed pin change.
Helpers are explicitly hash pinned. Go's normal approved compilation cache may
change; shared dependency inputs may not. Outputs stay in the assigned tree's
`.cache/native-web-preview/<run>`; failures and raw private serial are retained.
Guest children and host QEMU have deadlines and owned-process cleanup. A forced
guest-child cleanup fails qualification. Guest failures expose only a fixed
phase name, never arbitrary exception text. The VM powers off after the fixture.

This proves only the observations of an actual successful run. It does not
qualify browser-to-guest access, generated configuration syntax, Apache/FPM
activation, current serving health, stock-host provisioning, reboot, CloudLinux,
tenant authentication, original cPanel compatibility or all supported systems.
Recovery is to stop the owned run and discard its disposable overlay after
preserving evidence. Shared image, live host state and services are never changed.

The tool-identity regression delivery uses local Node checks only. It does not
rerun or extend the historical native qualification. Recover the earlier runner
by reverting the tool-pins change; no live state migration is involved.
