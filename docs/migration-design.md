# Moving a website here from anywhere

Status: design for Phase 1, written 2026-11-27. Jev decided (1.0): one
intermediate website model, source adapters that fill it, converters from
it into the OpenLiteSpeed configuration Sifruno renders, and an export so a
website can leave again.

## Why

Plesk Migrator and cPanel's Transfer Tool each import only into their own
panel, from a fixed list of source panels. A hosting company that moves to
Sifruno has websites on cPanel, Plesk, DirectAdmin, CyberPanel, HestiaCP and
plain servers. Sifruno already moves one website from a cPanel server over
root SSH or with the WHM login (`internal/hostaccounts` README, Migration).
This design keeps that path and puts every other source behind the same
model, so each new source is an adapter and not a new migration engine.

## The model: `internal/sitemodel`

A `sitemodel.Site` is one website as Sifruno will host it, read from any
source. It holds no password, no private key and no file contents; those
stay where the adapter found them (the old server, the uploaded archive)
until a broker step copies them.

| Part | What it holds |
| --- | --- |
| Account | The account name the site keeps, and the disk it used and was allowed |
| Domain | The main domain, its aliases, and whether `www.` answered too |
| Files | Where the site's home and document root are on the source, relative paths only once inside the model |
| Databases | Each database's name, its users with their `mysql_native_password` hashes kept out of the model, the grants, and where its dump comes from |
| Cron | Each job's schedule and command |
| PHP | The source's version string, the version this server runs it with, and the PHP settings (`memory_limit`, `upload_max_filesize` and the like) |
| Certificate | Whether the source has one for the domain, never the key |
| Rules | Access rules and rewrite rules: the `.htaccess` files' verdict, or the nginx lines converted, and the redirects and protected folders they become |
| Not carried | Everything the adapter saw and cannot carry, each with a plain reason and the line or file it came from |

`Site.Check` refuses a model that names something Sifruno cannot host
(a domain or account name outside the rules the wizard uses, a database
name another account owns, a PHP version outside 8.1 to 8.4). An adapter
never drops something silently: what it cannot carry goes into
`NotCarried`, and the panel shows that list before anything is created.

## Adapters

Each adapter fills the model. Every root step stays one of the broker's
fixed, typed operations; adapters that run in the panel only read.

1. **cPanel server (exists).** `internal/cpsource`, `internal/whmsource`,
   the broker's migration operations and `internal/wizard/migrate.go`. The
   wizard now builds a `sitemodel.Site` from the broker's `MigrationPlan`
   (`wizard.cpanelSite`), and the notes about aliases, grants and cron lines
   it could not carry come from the model's `NotCarried`. Its behaviour and
   tests stay as they were.
2. **cPanel backup file (this design, first).** The person uploads a
   `cpmove-USER.tar.gz` (or `USER.tar.gz`, `backup-…_USER.tar.gz`). The
   panel streams it to the broker (`POST /v1/migrations/archive`), which
   keeps it root-only in the migration's own folder for 24 hours, the same
   folder and lifetime an SSH migration has. `cpmove.Read` reads it once:
   - the same framing guards as `cpmove.Inspect`: one TAR stream, gzip
     checked, total, per-member and expanded sizes bounded, entry count and
     path length bounded, a context deadline;
   - every name must stay inside the archive (no `..`, no absolute path,
     no duplicate), and symbolic links must point inside the home; hard
     links, devices and FIFOs are refused;
   - metadata files (`cp/USER`, `userdata/main`, `userdata/DOMAIN`,
     `cron/USER`, `mysql.sql`, `sslcerts/`, `sslkeys/`, `apache_tls/`,
     `version`) are read into memory with a 1 MiB bound each;
   - `homedir/` is written through an `os.Root` (Go's confined directory
     handle) into a root-only staging folder, modes without setuid, setgid
     or sticky bits; `mysql/DB.sql` dumps go to the same staging folder.
   From there the copy is the SSH path's: the `.htaccess` scan and
   conversion on the staged copy, protected folders live first, `cp` as the
   site's user, database dumps loaded as the site's user through a
   temporary MariaDB user. The "remove the key" step deletes the archive.
   The parse runs in the broker process, in Go, with no shell and no
   external `tar`; the copy that reaches the tenant's home runs as the
   tenant. A separate unprivileged extraction process is left for later
   (see below).
3. **Another Linux server over SSH.** For Plesk, DirectAdmin, CyberPanel,
   HestiaCP and bare servers. The broker signs in with the migration key
   exactly as for cPanel, but reads the web server's own files instead of
   cPanel's API: the Apache (`/etc/httpd`, `/etc/apache2`) or nginx
   (`/etc/nginx`) virtual hosts, from a fixed list of directories, through
   `internal/sitesource`. It finds the domain's `server_name` or
   `ServerName`, its aliases and document root, and the owner of that root.
   WordPress sites name their database in `wp-config.php`; other PHP sites
   get their database name and credentials typed by the person, held in
   memory for the copy only. Files come with rsync, run on the source as
   the document root's owner (never as root unless root owns it); databases
   with `mysqldump` on the source, the password on standard input.
4. **Panel APIs for discovery.** DirectAdmin's and CyberPanel's public APIs
   list the accounts and domains, so the person picks a website instead of
   typing it. They only list: the copy itself goes over SSH (3).
   `internal/sitesource` holds the clients, with bounded answers and times.

## Converters into OpenLiteSpeed

Sifruno's OpenLiteSpeed config (`internal/olsweb`) holds domains, the
document root, the PHP version, redirects, protected folders and the
certificate. OpenLiteSpeed reads a site's `.htaccess` rewrite rules itself.

- **Apache `.htaccess`.** `internal/htaccess` decides, file by file, what
  OpenLiteSpeed acts on, and converts the access rules it knows into
  protected folders. The converter here does not change its tiers; it
  reports the refusals in the model's `NotCarried`.
- **nginx.** `internal/sitesource.ConvertNginx` reads a `server` block and
  turns:
  - `return 301|302 URL` (in the server or an exact `location`) into an
    olsweb redirect;
  - `location /path/ { deny all; }` into a closed protected folder;
  - `rewrite REGEX REPLACEMENT [last|break|redirect|permanent]` and the
    `try_files $uri $uri/ /index.php?$args` front-controller form into
    Apache rewrite lines that OpenLiteSpeed reads from the document root's
    `.htaccess`;
  - `root`, `index`, `server_name` and the PHP `location ~ \.php$` block
    into the model's document root, domains and PHP.
  Anything else (`proxy_pass`, `if`, `alias`, `auth_basic`, regex
  locations other than PHP's, nested locations) is refused, naming the
  file, the line number and the directive, so the person sees exactly what
  does not move.
- **PHP settings.** `php_value` and `php_flag` from `.htaccess`, cPanel's
  `userdata` PHP version and nginx's `fastcgi_param PHP_VALUE` become a
  `.user.ini` in the document root, which LSPHP reads per directory.
  `disable_functions`, `open_basedir` and other settings only the server
  may set are not carried.

## Export: the way back

`cpmove.Write` writes a Sifruno website as a cPanel-format backup:
`cpmove-USER/` with `version`, `cp/USER`, `userdata/main`,
`userdata/DOMAIN`, `homedir/` (the account's home as the site's user reads
it), `mysql/DB.sql` and `mysql.sql` (each database user's grant lines),
`cron/USER`, and `sslcerts/` with the certificate when there is one (the
key only when the person asks). The layout follows cPanel's public "Backup
Tarball Contents" page and the `restorepkg` page's accepted names. cPanel
says the layout can change and is not an integration endpoint, so a restore
into a real cPanel server is not certified until it has been tried on one.
`cpmove.Read` reads every archive `cpmove.Write` makes (the round-trip test).

## UI

"Move a website here" starts with one question: where is the website now?

- **cPanel server**: the existing guided path (WHM login or SSH key).
- **cPanel backup file**: upload, see what the file holds and what will
  not move, then the same copy, compare and cut over.
- **Another Linux server (Plesk, DirectAdmin, CyberPanel, HestiaCP or
  none)**: add the key over SSH, confirm the fingerprint, pick the website
  the server's own config names, then the same copy.

Errors say what happened, why and what to do next; the old server's own
output stays under Technical details.

## Security

- Every uploaded archive and every remote answer is untrusted: each read is
  bounded in bytes and time, and every name is checked before use.
- Credentials typed by the person (database passwords for a non-WordPress
  site, panel API keys) stay in the panel's memory for that move only and
  go to the broker on standard input or in a request body, never in a
  process argument, a log, a job record or the state directory.
- Nothing new runs as root outside a typed broker operation. The broker's
  new operations are `POST /v1/migrations/archive` and the generic source's
  read; files and databases reach the account through the existing copy
  steps.
- Commits that touch the broker, migration or credentials say
  "needs human review".

## Built so far (2026-11-27)

- The model (`internal/sitemodel`) and the cPanel adapter onto it.
- The backup file adapter end to end: `cpmove.Read`, the broker's
  `POST /v1/migrations/archive` and its copy steps, the panel's upload
  route, the move job, and the first question in "Move a website here".
- The nginx converter (`sitesource.ConvertNginx`), and the reading half of
  the SSH adapter: Apache virtual hosts (`ParseApache`) and wp-config.php
  (`ParseWPConfig`).
- The export writer (`cpmove.Write`), with a round trip through
  `cpmove.Read`.

Not built yet: the broker's steps for a server that is not cPanel (and so
the third answer to "where is the website now?"), the panel API clients
for DirectAdmin and CyberPanel (CyberPanel publishes no API for listing
websites; its source would have to be read), writing the carried PHP
settings as `.user.ini` during a copy (a site with `php_value` lines is
refused by the `.htaccess` tier check today), and an export button.

## Not in this design yet

- Running the archive's extraction in a separate process as an unprivileged
  user. The parse is memory-safe Go, confined by `os.Root`, into a
  root-only folder; a second process would also contain a parser bug.
- Mail, DNS zones, FTP accounts, PostgreSQL and addon or sub-domains with
  their own document roots: listed in `NotCarried`.
- Plesk's own API and HestiaCP's API for discovery: their servers are moved
  with the SSH adapter.
