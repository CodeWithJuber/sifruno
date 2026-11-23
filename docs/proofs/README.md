# Phase 0 proofs

Transcripts of the Phase 0 proofs from [the plan](../PRODUCT-PLAN.md), run on 2026-11-22 on a fresh dev VM built with [scripts/devvm](../../scripts/devvm/README.md): AlmaLinux 9.9, SELinux enforcing, OpenLiteSpeed 1.9.4, LSPHP 8.3.37, MariaDB 10.11.18, under QEMU software emulation (no KVM). Each `PASS` or `FAIL` line with two spaces is a check the script made against the running system; lines with one space are the verify tool's own report. A run passes only with zero `FAIL  ` lines.

| Plan item | Transcript | Result |
| --- | --- | --- |
| 7. Proof 1: WordPress on OpenLiteSpeed from config, own user, namespace container, quota | [phase0-proof1-wordpress-ols.txt](phase0-proof1-wordpress-ols.txt) | 26 passed, 0 failed |
| 8. Proof 2: the broker creates a real Linux user with SFTP sign-in; the 100-account bound is gone | [phase0-proof2-broker-sftp.txt](phase0-proof2-broker-sftp.txt) | 44 passed, 0 failed |
| 9. Proof 3 rehearsal: verify report with closed-URL checks | [phase0-proof3-rehearsal-migrate-verify.txt](phase0-proof3-rehearsal-migrate-verify.txt) | 15 passed, 0 failed |

What the Proof 3 rehearsal shows: a site with a password folder and a `<Files>` deny rule, copied unchanged to OpenLiteSpeed, serves both with 200, because OpenLiteSpeed reads only rewrite rules from `.htaccess`. The scan sends the site to the Compat tier, and verify keeps the cutover gate closed against the OpenLiteSpeed copy and opens it against an Apache copy.

What these runs do not show:

- **Proof 3 on a real cPanel site.** The rehearsal uses an Apache site built in the VM. The plan's proof copies one of HostLelo's own cPanel sites over root SSH; that needs the owner's server.
- **Speed on real hardware.** Without KVM, timings are upper bounds, not the plan's "2 minutes" gate: about 19 s per account create, 24 s to list 107 accounts, 259 s from account creation to a live WordPress site. An earlier run on a busier host needed more than two minutes for WordPress's first page after a restart.
- **Broker operations that do not exist yet.** In Proof 1 the script, not the broker, gives the web server access to the home (an ACL) and sets the XFS quota.
