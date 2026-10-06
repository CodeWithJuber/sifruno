# Restricted corrected fixture review

Verdict: CLEAR for source correctness and synthetic data/mock checks at guest
commit `4c81b2c96cd6eaf3987b6b7db1c994c61dae0b8f`. This is not native execution
authority. The original provisional CLEAR for `2ab283a5` remains withdrawn.

`node lab/startup-preflight-isolation-review/run-review.mjs` exited 0:

- Reused pure decoder challenges: 91 checks passed; cloned test-name arrays
  preserve the earlier independent synthetic array-alias correction.
- New fully mocked authority/environment setup challenges: 40 checks passed.
  They cover symlink/regular/writable/nonroot/special-mode refusal at every
  ancestor, restricted path grammar, inode and device drift, nofollow flags,
  closure, exact test-only environment, refusal before spawn, exclusive setup
  and distinct core/review descriptor-relative directories.
- Corrected fixture Python `-I -B` test file: 13 tests passed.
- Existing Node contract suite: 9 tests passed, 0 failed/skipped/todo.

All run environments explicitly set TEMP/TMP/TMPDIR to this worktree's ignored
private cache. New isolation challenges mock all subprocess and Linux APIs;
existing suites launch only synthetic Node/Python children. No Go rerun, native
utility, account operation, guest boot, provider/network call, live state or
service action occurred. Earlier reviewer sources/receipt were read-only and
their bytes checked unchanged; original logs remain in that worker's directory.

Source inspection confirms the nine-stage first-refusal schema and fresh
nonempty-state not_checked rule, unknown-provider redaction, nonce-bound strict
framing and metadata equality. The correction routes each actual test binary to
its own admitted temp root, keeps diagnostic/peer/broker environments unchanged,
and makes no recursive cleanup request. Test directories intentionally remain
in the disposable guest. Child sessions/pipes/timeouts/output remain bounded.

Linux kernel authority, actual compiled native test success, hostile concurrent
root writers and atomic host-policy stability remain unverified. Root must
review/adopt sequentially; any actual execution has separate gates. Recovery is
to reject adoption or revert the correction before that execution, retaining
existing failure and positive evidence.

`receipt.json` pins raw and canonical Git source bytes, commands, local raw logs
and challenge source. Logs are in `.cache/startup-preflight-isolation-review/`.
The runner uses exclusive log/receipt writes: subsequent runs need a separate
owned output location, rather than overwriting the recorded evidence.
