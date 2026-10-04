# Disposable Linux guest runtime qualification

This Linux-only Go runner executes an extracted Sifruno runtime in a trusted,
disposable guest. It does not provision a guest, install packages, manage host
accounts/services, restore original backups, change firewalls, or certify vendor
compatibility. Cross-compilation establishes build verification only. A successful
guest report covers its recorded kernel, architecture and scratch filesystem;
tmpfs execution does not establish ext4 or reboot durability. QEMU TCG is not a
security boundary for hostile workloads.

Root stages a matching-architecture Linux bundle with its complete manifest,
an independent output from `lab/cpanel_backup_fixture.py`, and the runner binary.
Read-only ISO inputs are supported. Binaries must be executable where staged;
if the ISO is mounted `noexec`, root must stage an identical verified executable
bundle on a guest filesystem before running. No dependency installation occurs.
The existing dedicated run parent must be a guest-owned filesystem, never a
host/shared mount. Paths must be absolute, normalized, disjoint and free of
symlink components. Inputs must remain unchanged throughout qualification.

```sh
./linuxruntime --guest-qualification \
  --bundle /mnt/sifruno-data/bundle \
  --fixtures /mnt/sifruno-data/fixtures \
  --run-parent /root/sifruno-qualification \
  --run-id qualification-001 \
  --manifest-sha256 ROOT_PINNED_MANIFEST_SHA256 \
  --expected-sha256 ROOT_PINNED_EXPECTED_JSON_SHA256 \
  --timeout 8m
```

The runner exclusively creates `run-parent/run-id` with mode0700. Reusing an
existing run fails. A fixed credential-free subprocess environment uses its own
HOME/TMPDIR; inherited application credentials, proxies and configuration are
never forwarded. Commands run without a shell, with bounded output and timeouts.
HTTP only dials the newly started loopback server, without proxies or redirects.
The owned server process group receives SIGTERM, then bounded SIGKILL cleanup.

The actual packaged CLI catalogs independently produced synthetic TAR and gzip
inputs. Checks include Python expected payload/source hashes, exact logical
names/link metadata, Linux identity/mode/time/PAX metadata, JSONL/catalog hash,
complete footer, output overwrite refusal, corrupt-input output cleanup and
absence of application state before server startup. Synthetic private values are
read only for comparison and never included in reports or logs. Inventory does
not extract or restore the source archive.

The packaged server then starts with exclusively new `server-state`, and the
runner observes UI/OpenAPI startup, Host/Origin/mutation/private-path guards and
actual sampled CPU/memory/history. Other telemetry availability remains explicit.
Alpine/OpenRC may correctly report systemd service inventory unavailable; that
does not become service support. Only numeric telemetry summaries are recorded;
service names, raw responses, subprocess output, keys, cookies and environment
values are omitted. State is inspected for0700directories and0600single-link
files without opening private file contents.

`report.json` is an exclusive0600file in the owned run directory, including
sanitized commands/statuses, manifest/input/binary/runner hashes and exact
OS/kernel/architecture/filesystem provenance. A failure records its fixed phase
and `passed:false`; `complete` means the runner finished recording, not that
checks passed. Reports always retain synthetic/reference-observedfalse,
compatibility-certifiedfalse and restore-implementedfalse. Keep private scratch
state inside the guest; export only the sanitized report. Removing the disposable
guest is the recovery path. No restart/persistence or vendor qualification is
claimed by this runner.

From the Windows source workspace, use the primary Go wrapper with this worktree
as the working directory and child-only `GOOS=linux`, `GOARCH=amd64`,
`CGO_ENABLED=0` to build `./lab/linuxruntime`. Save output in this worktree.
Linux compilation/vet evidence must remain separate from actual guest execution.

The independent Unix challenges executed in the observed guest are preserved
verbatim as `reviewer_linux_test.go`. They cover bounded/hash admission, exclusive
run reports, real Unix links/modes, catalog/privacy tampering, exact negative
exit classification and actual owned command deadline cleanup. Compile them with
Linux-targeted `go test -c ./lab/linuxruntime`; run only in fresh disposable guest
scratch with `-test.run '^TestReviewer' -test.timeout=60s`. The actual prior
overlay-built executable and tracked-copy cross-build have distinct provenance;
see `docs/linux-runtime-review.md` and `docs/linux-guest-toolchain.md`.
