# Hostweb independent challenges

`test_web_runtime_fixture.py` challenges the fixture's admission boundary with
an exact five-file two-account bundle, digest tampering, unsafe paths, the
private backend TLS requirements, and the client-DNS `Require host` mistake. It
does not start Apache, PHP-FPM, a broker, or a guest. The actual AlmaLinux run
belongs to the root coordinator after the compiler/helper/package freeze.

Run from this worktree:

```sh
python3 -m unittest lab/hostweb-review/test_web_runtime_fixture.py
```

The challenge uses only temporary files and synthetic bytes. It never reads
global credentials or mutates `.state`, live process state, or host mounts.
