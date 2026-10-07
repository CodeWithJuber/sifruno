# Preserved independent test-log checks

These two unchanged files were written during the unfinished runtime-input batch.
They check a synthetic Go test log: one positive example and six rejection cases.
They are independent preliminary tests, not the missing guest report decoder,
and are not wired into the incomplete guest runner.

```text
node --test lab/runtime-input-review/test-log.test.mjs
```

Passing these checks provides no Go, guest, native input, serving or compatibility
qualification. The [guest source archive](../runtime-input-guest/README.md) remains
non-runnable and must not be executed. This preservation does not resolve or
bypass its outstanding parser-creation approval.
