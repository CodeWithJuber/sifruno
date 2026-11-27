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
- **PHP settings.** `php_value` and `php_flag` from the root `.htaccess`
  become the site's vhost `phpIniOverride`, written by the root broker
  (below). `disable_functions`, `open_basedir`, settings that name a file
  and every `php_admin_*` line are refused, naming the line.

## PHP settings

Many cPanel sites set PHP options in `.htaccess` (`php_value memory_limit
512M`), and cPanel's MultiPHP INI Editor writes a block of them for the
DSO and LSAPI handlers. PHP-FPM sites read the same from the document
root's `.user.ini`, where Wordfence's extended protection also loads its
firewall with `auto_prepend_file`.

**How PHP runs here, on a running server** (2026-11-27, a server the
nightly script made, AlmaLinux 9.8, OpenLiteSpeed 1.9.5, LSPHP 8.3.37; a
site made through the installed broker):

- The site's vhost has its own `lsapi` extprocessor,
  `/usr/local/lsws/lsphp83/bin/lsphp`, started through the CGI daemon as
  the account. PHP reports the SAPI `litespeed` and reads
  `/usr/local/lsws/lsphp83/etc/php.ini`.
- `user_ini.filename` is `.user.ini`, but the lsphp processes'
  environment has no `LSPHP_ENABLE_USER_INI` (only `PHP_LSAPI_CHILDREN`,
  `LSAPI_AVOID_FORK` and LSAPI's padding), and PHP reads a `.user.ini`
  only when it is `on` (php-src `sapi/litespeed/lsapi_main.c`). A
  `.user.ini` in the document root with `memory_limit = 77M` and an
  `auto_prepend_file` changed nothing after a restart: `memory_limit`
  stayed 128M and the file did not run.
- A `php_value upload_max_filesize 33M` line in `.htaccess` changed
  nothing (2M), as OpenLiteSpeed reads only rewrite rules there.
- A `phpIniOverride` block written into the site's `vhconf.conf` with
  `php_value` and `php_flag` lines set every value it named, read back
  through PHP: `memory_limit` 256M, `upload_max_filesize` and
  `post_max_size` 64M, `max_execution_time` 120, `max_input_vars` 3000,
  `display_errors` 1 (`php_flag ... on`), `short_open_tag` 0 (`off`),
  `date.timezone` Europe/Berlin, `error_reporting` 32767,
  `session.cookie_httponly` 1, `session.gc_maxlifetime` 7200. The site's
  code could still change `memory_limit` with `ini_set`, as with Apache's
  `.htaccess` lines.
- PHP's access levels for every setting on the list below are 6
  (`PHP_INI_PERDIR`) or 7 (`PHP_INI_ALL`); `disable_functions`,
  `sendmail_path`, `allow_url_fopen` and `file_uploads` are 4
  (`PHP_INI_SYSTEM`). The server's `maxReqBodySize` is 2047M.

**The one way:** the root broker writes the settings into the vhost's
`phpIniOverride` (`internal/olsweb` phpini.go), not a `.user.ini`.
Turning on `LSPHP_ENABLE_USER_INI` for every site would apply every
`.user.ini` in every folder of every site, with whatever it sets, outside
the settings and limits the broker checks; it is not done.

**What converts** (`internal/htaccess` phpsettings.go): a `php_value` or
`php_flag` line of the root `.htaccess`, at its top level or inside
`<IfModule>` sections Apache reads, of `memory_limit`,
`upload_max_filesize`, `post_max_size` (sizes), `max_execution_time`,
`max_input_time`, `max_input_vars`, `max_input_nesting_level`,
`max_file_uploads`, `session.gc_maxlifetime`, `session.cookie_lifetime`,
`default_socket_timeout`, `pcre.backtrack_limit`, `pcre.recursion_limit`,
`error_reporting` (whole numbers, -1 where PHP takes it),
`display_errors`, `display_startup_errors`, `log_errors`, `html_errors`,
`short_open_tag`, the session cookie flags (On, Off, 1 or 0),
`output_buffering`, `zlib.output_compression` (either) and
`date.timezone` (a time zone name). The later line for a setting wins; at
most 32 settings. cPanel's `session.save_path` for its own session folder
does nothing here (this server's PHP keeps sessions in its own), and Off
for a setting PHP 5.4 removed does nothing on either server; neither
refuses.

**What refuses, naming the line:** `auto_prepend_file`,
`auto_append_file`, `include_path`, `sendmail_path`, `session.save_path`
and any value that names a file or folder; `open_basedir` and
`disable_functions`; every `php_admin_value` and `php_admin_flag`; any
other setting or value; and a setting in a folder's `.htaccess` or a
`<Files>` section, which applied to part of the site only. Wordfence's
mod_php block is refused at its `php_value auto_prepend_file` line, not as
an access rule.

**Limits the server keeps:** `memory_limit` is written no larger than
the account's memory, the address space each of its lsphp processes gets
(`AccountLimits.MemoryMiB`, 1024 MiB unless a plan says otherwise; -1
becomes that too), and the plan names a larger one as a note.

**On a move:** the copy puts the settings into the recorded set with the
converted redirects and error pages (`placeFiles`, `setSiteFolders`),
live before `cp` makes the files reachable. The document root's
`.user.ini` comes with the tier check: an `auto_prepend_file` or
`auto_append_file` there is a note that keeps the cutover gate closed
until a person accepts it, because the file it ran (often a firewall) does
not run on the copy. The proof reads every carried setting back through
PHP on the old server and the copy
(`docs/proofs/real-server-2026-11-25/migrate-php-settings.txt`).

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
- PHP settings from the root `.htaccess` carried into the site's
  `phpIniOverride` on a move from a cPanel server or backup file, and the
  `.user.ini` firewall note.
- The SSH adapter end to end (adapter 3, the third answer to "where is the
  website now?"): the broker reads the web server's own view of its
  configuration (`nginx -T`, `httpd -S` or `apache2ctl -S`, then each
  virtual host file), PHP-FPM's pools and versions, each document root's
  owner and wp-config.php, through `sitesource`'s fixed commands
  (hostaccounts README, "From another Linux server"). An nginx site's
  converted rules are written as the `.htaccess` files the copy's own scan
  converts, so they reach OpenLiteSpeed and verify as an Apache site's do;
  the `.htaccess` files nginx never read stay behind. The panel adds the
  move's key with root's password or a private key (`internal/keyinstall`)
  besides the command the admin runs, and shows each website's summary
  before anything is made.

Choices made for the SSH adapter (2026-11-27), each reversible:

- **Database names here.** Sifruno names an account's databases and users
  `<account>_...`, and a plain server's are not, so a WordPress site's
  database `wordpress` becomes `<account>_wordpress` and its user `wpuser`
  `<account>_wpuser` (`sitemodel.Database.SourceName` keeps the old name).
  The user keeps its password: the broker makes its mysql_native_password
  hash from wp-config.php's `DB_PASSWORD` and keeps neither, and the copy
  points the staged wp-config.php at the new names (`DB_NAME`, `DB_USER`,
  `DB_HOST` 'localhost'), changing nothing else.
- **Where the password is not readable.** A site with no wp-config.php, one
  whose `DB_` values are built from code or the environment, or one whose
  database is on another server moves without its database, and the
  summary says so before anything is made. Typing the database's details
  in the panel, which this design names for such sites, is not built yet:
  their configuration names the old database and user, which the account's
  prefix renames, so a typed password alone would not keep the site
  working; the person copies such a database by hand.
- **Who reads the files.** rsync's sender, and the reads of wp-config.php,
  run as the document root's owner (`runuser -u`), as root only when root
  owns the folder; a document root outside `/var/www`, `/srv`, `/home` and
  `/usr/share/nginx/html` is refused, so a vhost pointed at `/` or `/etc`
  cannot hand system files to a tenant. A link on the way to the document
  root, or a folder on the way that another user could swap for one, is
  refused, and a root-owned document root holding anything another user
  can change is refused, so a tenant cannot lead root's reads elsewhere.
- **Whose database.** wp-config.php is the tenant's file, and the dump runs
  as the database's root, so the database it names moves only when the
  site proves it is its own: not one of the server's own schemas, and the
  named localhost user has the password wp-config.php gives
  (mysql_native_password) and a grant on that database. A user that signs
  in another way (MySQL 8's `caching_sha2_password`) cannot be checked
  this way, so its database does not move and the summary says so.
- **Two web servers.** A domain both nginx and Apache name (nginx in front
  of Apache, as Plesk and HestiaCP run them) is refused for now, as are
  two blocks for one domain that serve it differently.

Not built yet: the panel API clients for DirectAdmin and CyberPanel
(CyberPanel publishes no API for listing websites, and its OpenLiteSpeed
configuration is not read), a database typed in for a site that is not
WordPress, nginx in front of Apache, PHP settings on a move from another
Linux server (`.user.ini` and nginx's `fastcgi_param PHP_VALUE`: the model
reads them, `sitemodel.PHP`, but no copy applies them, and its own list is
wider than the converter's), and an export button.

## Not in this design yet

- Running the archive's extraction in a separate process as an unprivileged
  user. The parse is memory-safe Go, confined by `os.Root`, into a
  root-only folder; a second process would also contain a parser bug.
- Mail, DNS zones, FTP accounts, PostgreSQL and addon or sub-domains with
  their own document roots: listed in `NotCarried`.
- Plesk's own API and HestiaCP's API for discovery: their servers are moved
  with the SSH adapter.
