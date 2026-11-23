# operator: panel sign-in

This package decides who may use the panel's private pages and API. It is security code: a person reads every change line by line before merge (AGENTS.md).

## Two ways in

| Credential | Who it is for | Where it works |
| --- | --- | --- |
| Access key (`operator/access.key`, 43 random characters) | Whoever controls the server: the CLI, first-run setup, recovery | Loopback only |
| Username, password and a 6-digit authenticator code | People | Loopback, and the HTTPS listener (`--https-listen`) |

The access key is not weaker than the admin login for the people it serves. Reading it needs the panel's own OS user, and that user can already read `session.keys` and forge sessions. The admin login is the one for people, and the only one accepted off loopback.

## Over the network

`--https-listen` serves the same panel over TLS for the host names in `--panel-host`. `Remote` (remote.go) marks a request remote only when it came through that listener, over TLS, for one of those names; anything else gets 421 before the API sees it. For a remote request:

- Every API and OpenAPI route needs an admin session, including the monitoring readings that loopback serves openly. The WHM transport is not served there (it has its own listener).
- The access key login is refused (403), and a session opened with the key on the server is refused too, even if its cookie is carried over (403 `admin_sign_in_required`).
- First-run setup is refused; it needs the key, so it happens on the server.
- Origin must be exactly `https://` plus the Host the browser used. Cookies are Secure.
- Network sign-ins have their own limits: a global 20-attempt burst refilling every 3 seconds, and 5 tries per username and caller IP refilling one a minute (4096 keyed-hash buckets). Nothing from the network can use up the server's own limits, so the access key always works on the server, and one outside address cannot lock the admin out of other addresses. Many addresses together can still use up the network-wide limit for a while.
- `GET /api/v1/session/setup` answers without a session over the network, so the panel can say that setup has to happen on the server. It reveals only whether an admin exists.

The certificate is the operator's (`--tls-cert`, `--tls-key`, which must cover every panel host) or a self-signed one kept in `tls/` in the state directory, recreated when the host names change or within 30 days of expiry. `sifruno` prints its SHA-256 fingerprint at start so it can be compared with what the browser shows. HSTS is not sent yet: with a self-signed certificate it does nothing, and it would make a later certificate problem impossible to click through.

Sites and other stores still record the actor as `local-operator`. The admin's username appears in the session only; per-person audit comes later.

## What is stored

All in the private state directory (0700, owner only, no symlinks), next to `access.key` and `session.keys`:

- `admins.json` (0600, at most 64 KiB, 16 admins): username, Argon2id hash, authenticator secret, last used code step, creation time. Written atomically (new file, fsync, rename).
- Passwords: Argon2id, 19 MiB memory, 2 passes, 1 lane, 16-byte salt, 32-byte key (the OWASP Password Storage Cheat Sheet minimum). Parameters are stored per hash, bounded on read, so they can be raised later.
- Authenticator: RFC 6238, HMAC-SHA1, 6 digits, 30-second steps, one step of drift either way. The secret is 160 random bits. It is stored in the clear because the server must compute codes; the file's permissions are its protection, as for `session.keys`.

The plan moves this file into the single SQLite store with the broker rework.

## Rules the code enforces

- One answer for every wrong username, password or code (401 `invalid_credentials`). Unknown usernames are checked against a dummy hash so they take the same time.
- A code works once. The step it belongs to is saved before the session starts, so it cannot be replayed, even after a restart.
- Rate limits on the server: the existing 20-attempt burst refilling every 3 seconds, plus 5 attempts per username refilling one per minute (network limits are separate, below). Every name, existing or not, uses one of 256 buckets chosen by a keyed hash, so a 429 does not reveal whether a name exists, and memory stays fixed. Someone can lock an admin out for a while by guessing; the access key still works locally.
- At most two Argon2id computations run at once, bounding memory under a burst.
- First-run setup needs an access-key session, works only while no admin exists, and issues the authenticator secret to that one session for 10 minutes. The admin is created only after a correct code proves the app is set up, and only if that session is still active at that moment. The session then becomes the admin's.
- Lock order: `adminMu`, then `mu`. `mu` is never held while taking `adminMu` or writing the file.
- Sessions, cookies, CSRF and Origin checks are unchanged: 15 minutes, HttpOnly, SameSite=Strict, Secure on TLS, at most 128.

## Not done yet

- More than one admin, password change, 2FA reset from the UI, passkeys, API tokens, customer logins.
- Sliding session renewal; sessions still end after 15 minutes.
- An outside review of this package and the broker, which the plan requires before a paying customer.
