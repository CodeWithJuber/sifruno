# operator: panel sign-in

This package decides who may use the panel's private pages and API. It is security code: a person reads every change line by line before merge (AGENTS.md).

## Two ways in

| Credential | Who it is for | Where it works |
| --- | --- | --- |
| Access key (`operator/access.key`, 43 random characters) | Whoever controls the server: the CLI, first-run setup, recovery | Loopback only |
| Username, password and a 6-digit authenticator code | People | Loopback today; the same login will face the network once HTTPS lands |

The access key is not weaker than the admin login for the people it serves. Reading it needs the panel's own OS user, and that user can already read `session.keys` and forge sessions. The admin login is the one for people, and it is the only one that will be offered off loopback.

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
- Rate limits: the existing 20-attempt burst refilling every 3 seconds for all sign-ins, plus 5 attempts per username refilling one per minute. Every name, existing or not, uses one of 256 buckets chosen by a keyed hash, so a 429 does not reveal whether a name exists, and memory stays fixed. Someone can lock an admin out for a while by guessing; the access key still works locally.
- At most two Argon2id computations run at once, bounding memory under a burst.
- First-run setup needs an access-key session, works only while no admin exists, and issues the authenticator secret to that one session for 10 minutes. The admin is created only after a correct code proves the app is set up, and only if that session is still active at that moment. The session then becomes the admin's.
- Lock order: `adminMu`, then `mu`. `mu` is never held while taking `adminMu` or writing the file.
- Sessions, cookies, CSRF and Origin checks are unchanged: 15 minutes, HttpOnly, SameSite=Strict, Secure on TLS, at most 128.

## Not done yet

- Serving the panel off loopback over HTTPS (next slice).
- More than one admin, password change, 2FA reset from the UI, passkeys, API tokens, customer logins.
- Sliding session renewal; sessions still end after 15 minutes.
- An outside review of this package and the broker, which the plan requires before a paying customer.
