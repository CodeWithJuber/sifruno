# operator: panel sign-in

This package decides who may use the panel's private pages and API. It is security code: a person reads every change line by line before merge (AGENTS.md).

## Two ways in

| Credential | Who it is for | Where it works |
| --- | --- | --- |
| Access key (`operator/access.key`, 43 random characters) | Whoever controls the server: the CLI, first-run setup, recovery | Loopback only |
| Username, password and a 6-digit authenticator code | People: admins, and customers (site owners), who reach only their own websites | Loopback, and the HTTPS listener (`--https-listen`) |
| API token (`Authorization: Bearer sfr_…`) | Programs, such as the WHMCS module | Loopback, and the HTTPS listener; never on `/api/v1/session/*` |

The access key is not weaker than the admin login for the people it serves. Reading it needs the panel's own OS user, and that user can already read `session.keys` and forge sessions. The admin login is the one for people, and the only one accepted off loopback.

## API tokens

A signed-in session creates, lists and revokes tokens at `/api/v1/session/tokens` (the panel's Security › API tokens page). Code in `tokens.go`.

- A token is `sfr_` and 43 base64url characters: 32 bytes from `crypto/rand`. It is in the create response only. The list shows its first 10 characters (`sfr_` and 6 more), the name, and when it was created, expires and was last used.
- Expiry is required: 90 days unless the request asks for 1 to 365. Expired tokens stay listed, marked expired, until revoked. Revoking removes the token at once. At most 32 tokens; names are unique regardless of case.
- `Authorize` treats any request with an `Authorization` header as a token request. A valid token gets what an admin session gets on every route `Authorize` guards, on loopback and over HTTPS, with no cookie, Origin or CSRF token. Off loopback a plain-HTTP request is refused (403 `https_required`); `Remote` already only marks TLS requests.
- Every `/api/v1/session` route refuses a request with an `Authorization` header (403 `token_not_allowed`), and those handlers check sessions only. So a token cannot sign in, list or end sessions, run setup, or create, list or revoke tokens. Future credential routes (admins, passwords, 2FA) belong under that prefix.
- A token sent together with the session cookie is refused (400 `invalid_request`).
- A wrong, malformed, expired or revoked token gets one answer: 401 `invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"`.
- Failed attempts are limited like sign-ins, with their own limiters: on the server a 20-attempt burst refilling every 3 seconds; over the network a separate burst of 20, plus 5 per caller IP refilling one a minute (4096 keyed-hash buckets). Only failures count, and only failures are refused: while a limit is used up, a wrong token gets 429 with `Retry-After`, but a valid, unexpired token is still admitted. A 256-bit token cannot be guessed, so holding back valid ones would add no safety and would let anyone who can send wrong tokens (a customer's script on the server, or many addresses) lock out the real client.
- The last-used time is saved at most once a minute per token. If that write fails, the request still succeeds and the time stays in memory until the next successful write.
- Routes that loopback serves without a session (`/api/v1/server`, `/status` and the like) do not check a token there.
- There is no audit log for admin actions yet. The change trail (`internal/trail`) is a file checkpoint journal with rollback, which could bring a revoked token back, so tokens are not recorded in it. Creation time and last use are kept per token; the name and prefix are what identify it.

## Customer logins

A customer (a site owner) signs in on the same form as an admin and reaches only the websites (hosting accounts) an admin gave it. Code in `customers.go` (the store), `customer_admin.go` (an admin's routes), `customer_setup.go` (the setup link), `principal.go` (who a session acts for) and `viewas.go`. What a customer may do on each route is in the API's table, `internal/api/customer_routes.go`.

- An admin gives a customer a login for 1 to 64 websites (`POST /api/v1/session/customers`). The answer holds a one-time setup link, `https://<panel host>/setup#<secret>` (the address is the HTTPS listener's when it is set, else the path only); the secret is 256 random bits in the fragment, so the browser does not send it in a request line or Referer. The server keeps its SHA-256 only. The link works for 24 hours (Jev chose this, 0.75).
- The customer opens the link: `customer-setup/begin` issues an authenticator secret for 10 minutes, and `customer-setup/finish` takes a password (the admin rules: 12 characters or more) and a current code, saves the Argon2id hash and the secret, retires the link and starts a customer session. Both need the exact Origin and no session, and work on the server and over HTTPS. A wrong, used, expired or turned-off link gets one answer (404 `setup_link_invalid`). Wrong links are limited like wrong API tokens: failures only, on the server a 20-attempt burst refilling every 3 seconds, over the network a separate burst of 20 plus 5 per caller IP refilling one a minute; a valid link always works.
- Sign-in is the admin sign-in (`passwordLogin`): the same per-username buckets, the same Argon2id limit, the same replay rule for codes, and the same 401 for a wrong password, an unknown name, a login not set up yet or a turned-off one. Admins and customers never share a username (checked when either is made, and when the files are read).
- An admin changes the websites (they apply on the next request), turns the login off or on (off ends its sessions at once), makes a new setup link (which clears the password and authenticator and ends its sessions: how a customer who lost its phone gets back in), or removes it. A deleted website leaves every customer's list (the API calls `ForgetWebsite` after a delete succeeds); if that save fails the ID stays listed and gives nothing, because hosting account IDs are random and never reused.
- A customer session never manages the panel: sessions, tokens, setup, customer logins and view-as need an admin's own session (403 `admin_only`). An admin's session list and "sign out everywhere else" leave customers' sessions alone. Customers hold at most 96 of the 128 sessions, each customer at most 4 (a new sign-in ends that customer's oldest), so customers signing in cannot keep an admin out.
- **View as customer** (`POST /api/v1/session/view-as`, `/view-as/end`): the admin's own session carries the customer's name (Jev chose this over a second session or a request header, 0.67). While it does, the session has exactly that customer's access, and nothing of the admin's; going back clears it. Removing the customer takes its viewers back.
- **Who a request acts for** (`Principal`): the broker records the actor of every change in the account's history. An admin is `local-operator` (per-admin names come with the audit log), a customer `customer:<name>`, and an admin viewing as a customer `admin:<name> as customer:<customer>` (`admin:local-operator as …` for the access key), so a change made while viewing is the admin's. The older static sites, which accept only `local-operator`, are admin-only.
- The API checks a restricted session twice: a gate on every request (`Scope`), so a customer cookie meets the table even on routes loopback serves without a session, and again inside Authorize, because an admin's session can start or stop viewing between the two.
- A restricted session's answers (sign-in, setup finish, `GET /api/v1/session`, view-as) carry `routes`: the routes the table allows, which the API hands over at start (`SetCustomerRoutes`). The panel shows a restricted viewer only the controls these allow, so it cannot drift from the table; the list decides nothing on the server. An admin's own session carries none. `web/src/lib/customer-routes.json` is the table for the panel's tests; a Go test keeps it equal (`go test ./internal/api -run TestCustomerRoutesFileMatchesTable -update` rewrites it).

## Your own password and authenticator app

A signed-in admin or customer changes its own password, or moves its codes to a new authenticator app (the panel's Account page). Code in `credentials.go`.

- Both start like a sign-in: the current password and a current code from the app in use. Every try takes one from the username's sign-in bucket first (the same keyed limiter as sign-in, so a stolen session cookie gets no more password guesses than the sign-in form, and the two share the limit; Jev chose counting every try, 0.86), the Argon2id work is bounded the same way, a wrong password and a wrong code get one answer (422 `invalid_credentials`), and the code's step is saved with the change, so a code works once.
- `POST /api/v1/session/password` takes the current password, a code and the new password (the setup rules, and not the current one), saves the new Argon2id hash and ends every other session of that login (an admin's, viewing as a customer or not); this one stays. A sign-in that checked the old password while the change was saved is refused when it records its code.
- `POST /api/v1/session/authenticator/begin` takes the current password and a code and issues a new key to this session for 10 minutes; the old app keeps working until `/authenticator/finish` gets a code from the new key, which then replaces the old one. Other sessions stay (Jev, 0.62).
- They need the person's own session with Origin and CSRF, signed in with a username: not an API token, not the access key (403 `admin_sign_in_required`; it has no password), and not an admin viewing as a customer (403 `viewing_as_customer`; the login is the customer's). A customer's whose login was turned off has no session left.
- A customer that lost its phone still asks an admin for a new setup link: re-enrolling needs a code from the app in use.

## Over the network

`--https-listen` serves the same panel over TLS for the host names in `--panel-host`. `Remote` (remote.go) marks a request remote only when it came through that listener, over TLS, for one of those names; anything else gets 421 before the API sees it. For a remote request:

- Every API and OpenAPI route needs a session, including the monitoring readings that loopback serves openly: an admin's, or a customer's on the routes the customer table allows. The WHM transport is not served there (it has its own listener).
- The access key login is refused (403), and a session opened with the key on the server is refused too, even if its cookie is carried over (403 `admin_sign_in_required`).
- First-run setup is refused; it needs the key, so it happens on the server.
- Origin must be exactly `https://` plus the Host the browser used. Cookies are Secure.
- Network sign-ins have their own limits: a global 20-attempt burst refilling every 3 seconds, and 5 tries per username and caller IP refilling one a minute (4096 keyed-hash buckets). Nothing from the network can use up the server's own limits, so the access key always works on the server, and one outside address cannot lock the admin out of other addresses. Many addresses together, customers' included, can still use up the network-wide limit for a while.
- `GET /api/v1/session/setup` answers without a session over the network, so the panel can say that setup has to happen on the server. It reveals only whether an admin exists.

The certificate is the operator's (`--tls-cert`, `--tls-key`, which must cover every panel host) or a self-signed one kept in `tls/` in the state directory, recreated when the host names change or within 30 days of expiry. `sifruno` prints its SHA-256 fingerprint at start so it can be compared with what the browser shows. HSTS is not sent yet: with a self-signed certificate it does nothing, and it would make a later certificate problem impossible to click through.

An admin's changes are still recorded as `local-operator`; the admin's username appears in the session, and in the actor of changes made while viewing as a customer. Per-person audit comes later.

## What is stored

All in the private state directory (0700, owner only, no symlinks), next to `access.key` and `session.keys`:

- `admins.json` (0600, at most 64 KiB, 16 admins): username, Argon2id hash, authenticator secret, last used code step, creation time. Written atomically (new file, fsync, rename).
- Passwords: Argon2id, 19 MiB memory, 2 passes, 1 lane, 16-byte salt, 32-byte key (the OWASP Password Storage Cheat Sheet minimum). Parameters are stored per hash, bounded on read, so they can be raised later.
- Authenticator: RFC 6238, HMAC-SHA1, 6 digits, 30-second steps, one step of drift either way. The secret is 160 random bits. It is stored in the clear because the server must compute codes; the file's permissions are its protection, as for `session.keys`.
- `tokens.json` (0600, at most 64 KiB, 32 tokens), written the same way as `admins.json`: per token a public ID, name, shown prefix, HMAC-SHA256 of the token, creation, expiry and last-use times. Never the token.
- `customers.json` (0600, at most 1 MiB, 500 customers), written the same way: per customer the username, its websites (hosting account IDs, sorted), whether it is turned off, the creation time, and either the SHA-256 and expiry of its setup link or, once set up, its Argon2id hash, authenticator secret and last used code step. Never the link.
- `tokens.key` (0600, 32 random bytes): the HMAC key. Tokens carry 256 random bits, so a keyed hash compared in constant time is enough; Argon2id would slow every API call for no gain. Deleting the key makes every token fail.
- `sessions.json` (0600, at most 256 KiB), written the same way: the sessions opened with a password and a code, sealed with AES-256-GCM under a key derived from `session.keys` (HMAC-SHA256), so moving `session.keys` aside ends saved sessions too. Inside, per session: the cookie's session ID, the SHA-256 of its CSRF token (never the token), the management handle, the creation, hard-limit and last-activity times, the username, and whether it is a customer's, kept signed in, or viewing as a customer. Sessions opened with the access key are never saved.

## Sessions survive a restart

A panel restart no longer signs people out (Jev, 0.81). Code in `saved_sessions.go`.

- A background saver (`StartSaving`) takes a snapshot of the session table under `mu` every 30 seconds and writes `sessions.json` only when the snapshot changed. Ending a session (sign-out, revoke, sign out everywhere else, a password change, turning a customer off, a new setup link, removing a customer) and starting or ending view-as wake it at once, so a crash right after a sign-out cannot bring the session back. `Close` saves once more after the listeners have stopped; `cmd/sifruno` calls it as its last deferred step.
- At start the panel loads the file. Every entry is checked as strictly as the panel makes it (IDs, handles, times, the 128 and customer limits), or none is loaded. Sessions that ended while the panel was stopped (idle or hard limit), and sessions of an admin or customer that is no longer in its file, are left out. The idle time keeps counting while the panel is stopped.
- A damaged file, one with the wrong mode, or one sealed with other session keys does not stop the panel: it starts with no saved sessions, logs one plain line, and the next save replaces the file.
- Access-key sessions stay in memory only, so a restart ends them, as before.

The plan moves this file into the single SQLite store with the broker rework.

## Rules the code enforces

- One answer for every wrong username, password or code (401 `invalid_credentials`). Unknown usernames are checked against a dummy hash so they take the same time.
- A code works once. The step it belongs to is saved before the session starts, so it cannot be replayed, even after a restart.
- Rate limits on the server: the existing 20-attempt burst refilling every 3 seconds, plus 5 attempts per username refilling one per minute (network limits are separate, below). Every name, existing or not, uses one of 256 buckets chosen by a keyed hash, so a 429 does not reveal whether a name exists, and memory stays fixed. Someone can lock an admin out for a while by guessing; the access key still works locally.
- At most two Argon2id computations run at once, bounding memory under a burst.
- First-run setup needs an access-key session, works only while no admin exists, and issues the authenticator secret to that one session for 10 minutes. The admin is created only after a correct code proves the app is set up, and only if that session is still active at that moment. The session then becomes the admin's.
- Lock order: `adminMu`, then `mu`; `tokenMu`, then `mu`; `saveMu`, then `mu`. `adminMu` and `tokenMu` are never held together, `saveMu` is never held with either, and `mu` is never held while taking any of them or writing a file. Customer logins change under `adminMu` and are published as a read-only snapshot, which session checks read without a lock.
- Cookies, CSRF and Origin checks: HttpOnly, SameSite=Strict, Secure on TLS, at most 128 sessions.
- A session ends after 30 minutes without a request and at 12 hours in any case, and its cookie ends with the browser. "Keep me signed in on this device" (`remember` at sign-in, with a password and code only; the access key refuses it) makes those 24 hours and 7 days, and only then does the cookie get a Max-Age. Jev chose these (0.81). Activity is any request a session check admits except `GET /api/v1/session`, which the panel asks once a minute: an open tab must still go idle. Pages that refresh by themselves still count: off loopback the Home page's readings need a session, so an open Home page stays signed in until the hard limit. The last activity is kept in `seen`, outside `activeSession`, because `authorizingSessionLocked` compares whole entries and one request's activity must not void a parallel request. `expires_at` is the hard limit; the idle limit is enforced on the server.

## Not done yet

- More than one admin, a reset for an admin who lost its password or phone, passkeys. A customer cannot see its own sessions yet.
- Resellers and plans (Phase 2).
- Token scopes: every token has full admin API access. An audit log of admin actions, including token use.
- An outside review of this package and the broker, which the plan requires before a paying customer.
