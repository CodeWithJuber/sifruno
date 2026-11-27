# UX audit: every owner journey on a real server

Walked on 2026-11-27 as a new owner would, in Chrome at 390 px and 1440 px wide, on a new AlmaLinux 9 server made by `scripts/ci/nightly-fresh-install.sh` and installed from the branch head with `--panel-host panel.SERVER_IP.sslip.io` and `--acme-email`. The first run went through an SSH tunnel to the panel's loopback address, as `docs/installation.md` says. Screenshots are in [proofs/ux-guided/](proofs/ux-guided/), with every address written `SERVER_IP`; the transcript is [proofs/ux-guided/transcript.txt](proofs/ux-guided/transcript.txt).

Effort: S is under an hour of UI work, M is a day or less, L needs a server change or a new dependency.

## 1. First sign-in

Steps: open `http://127.0.0.1:8080/` through the tunnel, find the setup, type the access key, choose a username and password, add the authenticator key, type a code.

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| The first page is Home with the full menu, live readings and five tiles, although the panel has no admin yet. Setup appears only after opening Websites. | The owner sees a working panel, clicks around, and every page asks for a key it never mentioned. The installer says "Open Websites", which is easy to miss. | Before the first admin exists, every page shows the setup form. | S |
| "It is in `operator/access.key` inside the panel's state folder on this server." | A non-specialist does not know where the state folder is or how to open a root-only file. | Give the full path and the command: `sudo cat /var/lib/sifpanel/state/operator/access.key`. | S |
| The authenticator step shows a 32-letter key and an "Open in authenticator app" link, with no QR code. | Most people add an account by scanning a code. Typing 32 letters on a phone is slow and error-prone, and the link works only on the same device. | Show a QR code of the `otpauth://` address. Fixed in the follow-ups with our own encoder. | L |
| After setup, nothing says that the panel should now be used at its name, `https://panel…:8443/`. | The owner keeps using the SSH tunnel, or never learns that customers use the name. | A "Get started" step for the panel's own address. | S |

## 2. Home

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| No next step. The subtitle says "Your websites and this server at a glance", but Home shows module tiles and CPU charts, not websites or what to do. | The owner asks "what am I doing?": nothing on Home says what a ready server needs. | A "Get started" checklist that reads the server's real state. | M |
| Tile words: "Open a module to work on this server", "Local panel", "A configured, admitted Linux broker is required for native account actions." | Internal terms ("module", "broker", "admitted", "native") where a job name would do. | Name each tile by its job and drop the broker note on Linux. | S |
| The "Customers" tile opens Hosting accounts (Linux accounts), not customer logins. | The tile says one thing and opens another. | Open Customers. | S |
| A tile for "Static site backups (old)". | The old model takes a fifth of Home. | Replace it with Backups (backup storage). | S |
| 122 system services (`apt-daily.service`, cloud-init stages) on Home. | Noise for a hosting owner. | Keep monitoring under Get started; the list stays on Server. Not changed in this slice. | S |
| On the server itself, an admin who is not signed in sees Home's tiles and readings but no Get started and no sign-in prompt (found after the fix). | The next step appears only after a tile asks for sign-in. | A "Sign in to see what is next" line. Fixed in the follow-ups ([proofs/ux-followups/](proofs/ux-followups/)). | S |

## 3. Create a WordPress site with the wizard

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| Field hints in bytes: "Up to 200 bytes: a plain letter is 1, letters with accents… are 2 to 4", "12 to 128 bytes". | Bytes are a programmer's unit. | Say characters, and that accented letters count more. | S |
| The finished screen's last action is "Go to Websites"; nothing leads to the new site's own page, where domains, SSL and backups are. | The owner's next jobs (certificate, backups, a customer login) start on the site's page. | "Manage this website" as the one primary action. | S |
| "Turn on https: Skipped. The certificate authority could not be reached or did not issue a certificate… The panel tries again every few hours." On this run the real cause was that Let's Encrypt refused the contact address `admin@example.com`. | The message blames the network; the owner checks DNS and firewalls that are fine, then waits hours. | The ACME client should name the refusal (contact address, rate limit, DNS) and the installer should check the address. Fixed in the follow-ups. | L |

| A PHP site's finished screen tells the admin "Ask whoever runs this server to add your public key". | The admin is whoever runs the server, and the panel has no screen for SFTP keys. | A key form, or the command for the server. Not in this slice. | M |

The wizard's progress screen is good: five named steps, a progress bar, "You can leave this page".

## 4. A site's tabs

| Tab | Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- | --- |
| Websites list | The website's name is plain text; its page opens from a quiet "Details" link. | The main way to manage a site looks like the least important control. | The name links to the site; "Manage" is a button. | S |
| Websites list | "Static sites (old)" sits next to "New website"; "Move a website here" is missing. With no websites, "New website" shows twice. | The old model competes with the real one; moving, the most common start for a hosting business, is hidden in the menu. | "Move a website here" beside "New website"; the old link moves to the page's foot; the empty state carries the actions alone. | S |
| Every tab | The header's "Open site" is a primary button, and so is each tab's own action ("Back up now", "Add domain"). | Two primary buttons compete on every tab. | "Open site" becomes an outline button. | S |
| Overview | Good: a health list with a button per problem. "restore drill" in Recent activity. | One internal word. | "restore test". | S |
| Domains and SSL | The tab is named SSL but shows no certificate state, only an `http` badge. The HTTPS switch shows on but cannot be pressed. The next step for the owner says "ask whoever runs this server". | The owner is whoever runs the server: a dead end. The switch looks broken. | A Certificate line (valid until, none yet, expired); for an admin, a next step with what to check on the server; "On: starts once the site has a certificate". | S |
| Always use HTTPS | Cannot be tried until a certificate exists (see above). | — | Covered by the Domains fix and Get started. | — |
| Files | Opens the home folder, which lists `.lsns` (OpenLiteSpeed's namespace folder) with Rename and Delete; permissions as `rwxr-xr-x`. | A system folder looks like the owner's. (On the follow-ups' server, OpenLiteSpeed made `.lsns` again after it was deleted and PHP kept working, so "breaks the site" was not reproduced.) | Lock system folders; show permissions in words. Fixed in the follow-ups: `.lsns` is locked in the page and refused by the server. | M |
| Databases, phpMyAdmin | "Open phpMyAdmin" opens the panel's name on port 8444; while the panel's certificate is self-signed the browser shows "Your connection is not private". | The panel sends the owner into a security warning without saying why. | Get started shows the panel's certificate state; a note on this button is the next step. Fixed in the follow-ups. | M |
| Backups | "Run restore drill now" is disabled with no reason before the first backup. "Started by local-operator." | "Drill" and "local-operator" are internal; a greyed button with no reason is a dead end. | "Test a restore now", with "Make a backup first"; "Started by an admin". | S |
| Cron jobs | Crontab fields ("Five fields: minute, hour…", `>> ~/cron.log 2>&1`). The "When" presets help. | Shell terms. | Acceptable in Advanced view; not changed. | S |
| Logs | Raw log lines, newest last. | Expected for logs. | None. | — |
| Settings | Clear: PHP version, scheduled jobs, logs, suspend, delete. | — | None. | — |

## 5. Move a website here

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| Good five-step outline with "What happens" for each. Terms: "SSH fingerprint", "root's SSH keys". | Some words need a sysadmin. | Keep the outline; terms are explained where they are confirmed. Not changed. | S |
| After an unreachable WHM address the error says what, why and next, but shows both "Try again" and "Connect". | Two buttons that do the same. | Keep one. Not changed (the migration back end belongs to another agent). | S |
| Not reachable from the Websites page or Home. | The owner who has sites elsewhere must find it in the menu. | A button on Websites, a tile on Home and a Get started step. | S |

## 6. Backups and backup storage

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| "restic encrypts the backups", "restic is ready", "An SFTP server", `ssh-keyscan -p 22 HOST`, "Host key", `authorized_keys`, "A new backup repository was made". | The page is written for a sysadmin; the owner does not know what a storage server is or where to get one. | Say what it is first: another server you can sign in to with SSH. Keep the commands as help. | S |
| "Last restore drill: No restore drill has run yet. The first runs after the first nightly backup." | A drill sounds like a fire alarm; the owner can run one now from a site's Backups tab, and nothing says so. | "Restore test", and Get started leads to "Test a restore now". | S |
| The password dialog after saving storage is good: it says why, and asks to confirm it was saved. | — | None. | — |

## 7. Customers and logins

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| The setup link starts with the panel's name. While the panel's certificate is self-signed the customer's browser warns first. | The customer's first sight of the owner's service is a security warning. | Get started shows the certificate state first; a note beside the link is the next step. | M |
| "Hosting accounts" sits under Customers: "Linux account identities", "Inventory web configuration preview", "Broker snapshot", "native identity drift", UID, GID, Revision, "Create Linux account", and its own "Sign out locally". | It has nothing to do with customer logins and looks like a second way to make a website. | Move it to an "Advanced" group at the bottom of the menu. | S |
| "It signs in with its own password", for a person. | Odd wording. | Not changed. | S |

## 8. Security, sessions, API tokens and passkeys

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| "Local operator access to this Sifruno server", "Signed in locally", "Sign out locally", "Operator sessions", "Sessions belong to the single local operator", "Revoke". | "Operator" and "revoke" are internal; there are admins and customers, not one operator. | "Signed-in sessions", "Sign out", "Sign out other sessions". | S |
| API tokens: clear, with what a token can do and an empty state. | — | None. | — |
| Passkeys live on Account, with a note when the panel is not at its name. Good. | — | None. | — |

## 9. Account

Clear: the login, passkeys, password, authenticator app, each with what it needs. No change.

## 10. Server pages

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| Services: "Native systemd · read-only inventory" of 122 units. | For a sysadmin. | Not changed. | S |
| Storage: "Volume 1", "Volume 2" without mount points. | The owner cannot tell which is `/home`. | Name the mount point. Server work. | M |

## 11. The old static-site screens and other leftovers

| Problem | Why it confuses | Fix | Effort |
| --- | --- | --- | --- |
| "Static sites (old)" and "Static site backups (old)" are in the Websites menu and on Home, with "Import native ZIP", "Create website" and "New website" side by side, "Sign out locally", "local HTTP preview. DNS, TLS, PHP, mail and databases are unavailable." | Two ways to make a website, and the old one cannot host a real site. | Move both to the Advanced group; one quiet link on Websites. | S |
| Activity: "Experimental scoped file recovery… Create and apply a scoped checkpoint through the local CLI". | A main-menu page that only a command-line user can fill. | Move to the Advanced group. | S |
| Settings: "AI spending", "USD ledger", "Operator approval required", "Provider billing reconciliation". | Nothing an owner can set. | Not changed in this slice. | S |

## Ranked top 15

Ranked by how many owners meet it, how early, and whether it stops them.

| Rank | Problem | Fix | Status |
| --- | --- | --- | --- |
| 1 | Home gives no next step: an owner cannot tell what a ready server needs. | Get started checklist from the server's real state. | Fixed |
| 2 | The first open shows the panel, not the setup; the access key's place is vague. | Setup on every page until an admin exists; full path and command. | Fixed |
| 3 | The panel's own certificate state is invisible in the panel; customers' setup links and phpMyAdmin open on browser warnings. | Get started step for the panel's address and certificate, with what to do. | Fixed (the warnings beside the link and the phpMyAdmin button in the follow-ups) |
| 4 | Domains and SSL shows no certificate state, a switch that is on but disabled, and "ask whoever runs this server" to the owner. | Certificate line, admin next step, switch explained. | Fixed |
| 5 | Certificate failures name the wrong cause (this run: a refused contact address reported as "could not be reached"). | Name the real refusal; check `--acme-email` in the installer. | Fixed in the follow-ups |
| 6 | Old static-site screens in the main menu and on Home. | Advanced group, one quiet link. | Fixed |
| 7 | Hosting accounts (Linux, broker, UID) under Customers, and Home's Customers tile opens it. | Advanced group; the tile opens Customers. | Fixed |
| 8 | The site's own page is hard to find from Websites; Move is missing there; "New website" twice when empty. | Name links, "Manage", Move beside New website. | Fixed |
| 9 | The wizard's last screen does not lead to the new site's page. | "Manage this website" as the primary action. | Fixed |
| 10 | Home's tiles use internal words ("module", "broker", "admitted", "native"). | Job names. | Fixed |
| 11 | "Restore drill", "local-operator", and a disabled drill button with no reason. | "Restore test", "an admin", the reason. | Fixed |
| 12 | Backup storage is written for a sysadmin (restic, SFTP, host key). | Plain first sentence; commands stay as help. | Fixed |
| 13 | Security page: "operator", "locally", "revoke". | Plain words. | Fixed |
| 14 | No QR code for the authenticator app. | QR code. | Fixed in the follow-ups: our own encoder, no new dependency |
| 15 | Wizard limits in bytes. | Characters. | Fixed |
