# Native hostweb compiler

`hostweb.Compile(Profile, []hostaccounts.Account) (Bundle, error)` is a pure
configuration compiler for the bounded `restricted-chroot-v1` slice. It sorts
accounts by ID, validates the account identity and exact home/public_html
relationship, rejects more than 100 accounts and duplicate IDs, UIDs, GIDs or
domains, and returns a deterministic bundle. It does not read the filesystem,
create a directory, write a certificate, start Apache/PHP-FPM, or claim host
activation or cPanel compatibility.

The profile fields are:

| JSON field | Meaning |
| --- | --- |
| `name` | Stable bundle label. |
| `managedRoot` | Root for generated compiler output and front PID metadata. |
| `managedHomeRoot` | Existing hostaccounts home parent; every `home` is exactly `<root>/<username>`. |
| `frontChroot` | Root prepared for the shared front Apache configuration. |
| `apacheModuleRoot` | Root-owned Apache modules referenced by absolute path. |
| `backendChrootRoot` | Parent of one immutable jail per account ID. |
| `runtimeRoot` | Parent of one root-prepared runtime mapping per account ID. |
| `apacheBinary`, `fpmBinary` | Root-owned executable paths recorded by the profile; never executed by Compile. |
| `tlsRoot` | Root-owned per-account `cert.pem` and `key.pem` parent. |
| `caFile` | Root-owned CA file; it must be below `tlsRoot`. |
| `frontendIP`, `frontendPort` | Numeric IPv4 plain-HTTP front listener; defaults to `127.0.0.1:80`. |
| `backendPort` | Must be 18443. |
| `frontUID`, `frontGID` | Nonroot numeric identity below 20000 for the shared front; defaults to Alma's `48:48`. |
| `controllerUID` | Existing panel controller identity; defaults to `2000` and must differ from front UID/GID. |

The generated relative files are exactly `apache/front.conf`,
`apache/backends/<32-hex-account-id>.conf` and `fpm/<32-hex-account-id>.conf`
for each active account. A suspended account has only an explicit denied
front virtual host. Every file is mode `0600`, carries its SHA-256, and the
bundle carries a digest over the ordered file manifest.

Each account home must equal `managedHomeRoot/<username>` and its public root
must equal that home plus `/public_html`; UID and GID must be in the existing
foundation range `20000..60000`, and revision must be greater than zero.

## Runtime contract for a future installer

The shared front Apache may read its own front jail and generated metadata. It
must not have a path, bind mount, or traversal permission into any tenant home,
tenant public_html, tenant backend jail, or tenant runtime directory. Its
unknown/default virtual host denies all requests. Foreign `Host` values must
therefore remain denied, and suspended primary domains remain denied.

Each active account gets one root-prepared backend jail at
`<backendChrootRoot>/<account-id>` and one root-prepared runtime mapping at
`<runtimeRoot>/<account-id>`. The only tenant mappings are that account's exact
absolute `home` (including `home/public_html`) and its exact runtime directory.
No sibling tenant path, host `/etc`, host `/proc`, host `/sys`, host `/dev`,
socket directory, certificate directory, or arbitrary host path may be mapped
into the jail. The jail root and mount sources are immutable after preparation;
the compiler only emits references and cannot enforce or certify those mounts.

The backend Apache runs with numeric account UID/GID and `ChrootDir`. Its
document root is the account's exact `public_html`; `AllowOverride None` and
explicit options disable indexes, CGI, includes and symlink following. The
installer must independently reject symlinks/reparse points and verify mount
boundaries; `Options -FollowSymLinks` alone is not an isolation proof.

The per-account PHP-FPM pool runs with numeric account UID/GID, `chroot`,
`clear_env = yes`, `security.limit_extensions = .php`, a tenant-owned Unix
socket mode `0600`, ondemand process management with at most two workers, and
bounded request/idle timeouts. FPM must not be reachable from an untrusted
network.

The front proxy is plain HTTP in this bounded slice; public HTTPS certificate
termination is outside this compiler's contract. It uses the unique loopback backend address
`127.73.(UID>>8).(UID&255):18443`. Root-generated certificates live outside
the jail, are owned by root, and must contain only that account's backend IP in
their SAN set. The front config requires the configured CA and enables
`SSLProxyVerify require`, `SSLProxyCheckPeerName on`, and
`SSLProxyCheckPeerExpire on`.

On AlmaLinux/SELinux, a future installer must fail closed unless the prepared
paths have explicit labels: tenant read-only web content uses
`httpd_sys_content_t`, narrowly scoped tenant writable directories use
`httpd_sys_rw_content_t`, and runtime/socket paths use the platform's
`httpd_var_run_t` equivalent. No `unconfined_t`, broad `chcon -R`, permissive
mode, or cross-account label is acceptable. The compiler does not invoke
`semanage`, `restorecon`, mount, systemd, firewall, or SELinux commands.

The required backend Apache modules are `mod_mpm_event`, `mod_unixd`,
`mod_ssl`, `mod_proxy`, `mod_proxy_fcgi`, `mod_authz_core`, `mod_authz_host`,
`mod_dir`, `mod_mime`, and `mod_log_config`. The backend explicitly uses the
trusted AlmaLinux stock `/etc/mime.types` through `TypesConfig`; an installer
that needs to reload or execute the child inside its chroot must make that
file visible there from a root-owned immutable source. The front only proxies
requests and therefore omits `mod_mime` and `TypesConfig`. PHP-FPM is the only PHP
runtime assumed. Module presence, package provenance, jail preparation,
SELinux labels, certificate SAN/expiry, daemon activation, request serving and
reboot durability remain separate host evidence requirements.

The backend PHP handler uses Apache's Unix-socket handler form
`proxy:unix:<socket>|fcgi://localhost/`, allowing `mod_proxy_fcgi` to derive the
canonical script filename from the normal URL-to-file mapping. The compiler
does not use `ProxyPassMatch` and does not append the tenant document-root path
to that handler URI.

## Offline JSON helper

`lab/hostweb-render` accepts one UTF-8 JSON document on stdin, bounded to
1 MiB, and emits one JSON document on stdout. It rejects duplicate object keys,
unknown fields, trailing values, and any schema other than:

```json
{
  "schemaVersion": 1,
  "compatibility": false,
  "activation": false,
  "profile": { "name": "restricted-chroot-v1", "managedRoot": "...", "managedHomeRoot": "...", "frontChroot": "...", "apacheModuleRoot": "...", "backendChrootRoot": "...", "runtimeRoot": "...", "apacheBinary": "...", "fpmBinary": "...", "tlsRoot": "...", "caFile": "...", "frontendIP": "127.0.0.1", "frontendPort": 80, "backendPort": 18443, "frontUID": 48, "frontGID": 48, "controllerUID": 2000 },
  "accounts": []
}
```

Account objects use the existing `hostaccounts.Account` JSON fields exactly.
Output contains `schemaVersion: 1`, `compatibility: false`,
`activation: false`, and bundle files with plain configuration strings. It
contains no credential or certificate bytes. The helper is a fixture renderer,
not a release binary and not an activation path.
