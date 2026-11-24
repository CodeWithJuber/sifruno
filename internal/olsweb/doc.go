// Package olsweb renders OpenLiteSpeed (OLS) configuration for Sifruno sites
// from a typed spec. It is pure: Render validates the spec and returns file
// bytes, MakePlan compares two rendered sets, and nothing here reads or
// writes the host, starts a process or restarts the server.
//
// # What it renders
//
// Paths are relative to ServerRoot (/usr/local/lsws):
//
//   - conf/sifruno.conf: one virtualhost block per site (vhRoot is the
//     user's home, or SuspendedDocRoot when suspended, setUIDMode 2 with
//     user and group set to the account, restrained 1, enableScript 0 when
//     suspended) and the Sifruno listeners
//     with their map lines. httpd_config.conf includes it with one line at
//     the top level, so Sifruno never rewrites the administrator's file.
//     A plain listener maps every site. A secure listener maps only the
//     sites with their own certificate and is left out while there are
//     none.
//   - conf/vhosts/sifruno-NAME/vhconf.conf: docRoot, index files, error and
//     access logs in LogRoot/NAME/, the optional vhssl certificate, the
//     site's own lsphp extprocessor (lsapi over uds://tmp/lshttpd/
//     sifruno-NAME.sock, started through the CGI daemon as extUser/extGroup =
//     the account, with rlimits and LSAPI children), the php script handler
//     that uses it, namespace 2 and cgroups 2 when an active site asks for
//     them, a static context that maps /.well-known/acme-challenge/ to
//     ACMEChallengeDir, a "module cache" block, and a rewrite
//     block with .htaccess autoload plus vhost-level deny rules. The cache
//     block turns LSCache on with the site's own store in
//     CacheRoot/sifruno-NAME and the stock values written out, enableCache
//     0 among them: a page is cached only when the site's response asks.
//     A suspended
//     site has no extprocessor or handler, the cache module off with nothing
//     to look up, autoLoadHtaccess 0 and one rule
//     answering 403 to everything, challenges included. Its docRoot is
//     SuspendedDocRoot, so no path it names is under the tenant's home and
//     the tenant cannot make its config test fail; SuspendedDocRoot must
//     exist before such a render is tested.
//
// # Certificates
//
// Render only names files; it never reads them. The paths it accepts are
// fixed by TLSRoot: a listener's certificate and key are files directly in
// TLSRoot, and a site's are files directly in TLSRoot/NAME/, so one site
// cannot name another's key. The root broker (internal/hostaccounts) writes
// them, root-owned 0600 in root-owned 0700 directories: TLSRoot/listener.crt
// and listener.key are the secure listener's self-signed default (CN
// "sifruno", ECDSA P-256), and TLSRoot/NAME/cert.pem (full chain, leaf
// first) and key.pem are the site's own. certChain 1 makes OpenLiteSpeed
// send the whole chain. The challenge context gives ACME HTTP-01 one shared
// directory outside every home: the panel writes one random-named file per
// token there and removes it after validation. The context is static only
// (forceType text/plain, autoIndex 0, its own rewrite block with enable 0),
// and the deny rules for other dot paths stay as they are.
//
// Server-level settings stay with the administrator: namespace containers
// need "namespace 1" (or 2) in httpd_config.conf, cgroups need "cgroups 1"
// (or 2) inside its CGIRLimit block, and LSCache needs the stock
// "module cache" block, which the installer adds when it is missing. A
// second server-level definition in the included file would compete with
// the administrator's, so none is emitted; each vhost's own block overrides
// it for that site.
//
// # Config grammar (OLS v1.9.4 src/main/plainconf.cpp)
//
// Lines are trimmed; a line starting with '#' is a comment. A line starting
// with "include" (any case) loads a file, a directory of *.conf files or a
// wildcard. "{" opens a block only as the last character of a line and "}"
// closes one only as the first. "<<<MARK" anywhere after the first character
// starts a heredoc value that ends at a line whose first word is MARK. A
// trailing backslash joins the next line. A line of 8192 bytes or more
// aborts the rest of the file. The key is everything before the first space
// or tab. Validation therefore refuses whitespace, braces, quotes, '$', '#',
// '<', '\', newline and NUL in every value, and Render checks line lengths.
//
// # Sources (all read 2026-11-22)
//
// Official documentation, docs.openlitespeed.org (page date in brackets):
//
//   - /config/advanced/includes/ [2024-07-27]: include is supported in the
//     config files but not by WebAdmin, only at the top level, with
//     wildcards. Quote: "Technically, you can use include files in the OLS
//     configuration, however this is not currently supported by the WebAdmin
//     Console." and "Include files are specified at the highest level and can
//     contain wildcards at any point in the specification."
//   - /config/advanced/namespaces/ [2026-11-18]: server "namespace" is 0 not
//     set (disabled), 1 off, 2 enabled; vhost "namespace" is 0 inherit,
//     1 off, 2 enabled, and cannot override a disabled server; namespaceConf
//     and namespaceConfVhAdd name template files; the default template binds
//     $HOMEDIR, read-only system directories and a private /tmp in
//     $HOMEDIR/.lsns/tmp and writes a minimal /etc/passwd; containers persist
//     in /var/lsns/<uid> until a graceful restart or unmount_ns; lsphp must be
//     killed after a configuration change. On lsphp, quote: "Note that
//     specifying a system program like PHP (lsphp) as a vhost namespace
//     container program can be done, however it is quite complex because you
//     must remove it from the overall configuration, both as an external app
//     and a script handler and define it specifically for each vhost you will
//     be using it for." This package defines both per vhost.
//   - /config/advanced/bubblewrap/ [2025-08-12]: bubbleWrap is 0 disabled,
//     1 off, 2 on, with bubbleWrapCmd; it is separate from namespace.
//   - /config/advanced/cgroups/ [2024-08-28]: cgroups v2 on kernel 5.2+ with
//     the unified hierarchy; applies only to apps started by the CGI daemon,
//     PHP included; the server setting lives in CGIRLimit; lssetup prepares
//     the host. Its value tables contradict each other (see Unverified).
//   - /config/php/externalapp/ [2024-07-12]: suEXEC per vhost via "External
//     App Set UID Mode: DocRoot UID" with suEXEC user and group; a vhost-level
//     lsphp needs a unique name and address such as
//     uds://tmp/lshttpd/lsphp-example.sock, Run As User/Group, and a script
//     handler pointing at the vhost-level app.
//   - /config/php/ [2025-03-20]: the plain-text extprocessor block,
//     lsphp83 at /usr/local/lsws/lsphp83/bin/lsphp, "Start By Server: Yes
//     (Through CGI Daemon)" (autoStart 2), "Run On Startup: Yes (Detached
//     mode)" as the default.
//   - /config/php/detached/ [2024-07-12]: detached lsphp survives server
//     restarts until it idles out or .lsphp_restart.txt is touched.
//   - /config/rewriterules/ [2024-07-29]: rewrite { enable 1,
//     autoLoadHtaccess 1 }; restart after changing rules.
//   - /security/access/ [2026-04-28]: "OpenLiteSpeed only supports .htaccess
//     for rewrite rules, and not for directives"; deny with RewriteRule [F,L].
//   - /config/lscache/ [2024-07-29]: "module cache" is registered at server
//     level with ls_enabled 1; enableCache is not offered at server level;
//     the WordPress plugin turns caching on per response.
//   - /security/ssl/ [2026-05-11]: vhost certificates override the
//     listener's; "Chained Certificate: Yes" for a full-chain file.
//   - /commands/ [2024-04-25]: "systemctl restart lsws" is described as a
//     zero-downtime graceful restart; "openlitespeed -t" checks the config.
//
// OLS v1.9.4 source (github.com/litespeedtech/openlitespeed, tag v1.9.4):
//
//   - src/main/plainconf.cpp: the grammar above.
//   - src/http/httpvhost.cpp: virtualhost keys allowSymbolLink, enableScript,
//     restrained, setUIDMode (0 server, 1 CGI file, 2 DocRoot UID), user and
//     group (which force DocRoot UID mode); vhost namespace and cgroups are
//     read from vhconf.conf; a vhost may not use another vhost's handler.
//   - src/main/httpserver.cpp: the server namespace setting is read only
//     when bubbleWrap is 0 or 1; httpdWorkers defaults to the CPU count
//     capped at 8.
//   - src/http/httpserverconfig.h, src/http/serverprocessconfig.h,
//     src/extensions/cgi/cgidworker.cpp: namespace 0/1/2 = disabled/off/on;
//     cgroups 0/1/2 = disallow/default off/default on, read from CGIRLimit
//     (serverprocessconfig.h:48-50, cgidworker.cpp:409-416); the vhost
//     value is 1 off or 2 on, and counts only when CGIRLimit's is not 0
//     (httpvhost.cpp:3401-3405). With it on, lscgid writes the new process
//     into user-<uid>.slice/litespeed-exec.scope and starts the slice
//     (src/extensions/cgi/lscgid.cpp:471-529, called at 620-622). Read, not
//     yet run.
//   - src/extensions/extworkerconfig.h, registry/extappregistry.cpp:
//     autoStart 0 off, 1 by the server, 2 through the CGI daemon (lscgid).
//   - src/extensions/localworkerconfig.cpp: PHP_LSAPI_CHILDREN or
//     LSAPI_CHILDREN mark lsphp self-managed and cap maxConns; runOnStartUp
//     defaults to 3 (detached); a process limit below
//     (3*maxConns+50)*httpdWorkers is raised with a notice; extUser and
//     extGroup set the suEXEC identity.
//   - src/util/rlimits.cpp: memSoftLimit/memHardLimit set RLIMIT_AS,
//     procSoftLimit/procHardLimit set RLIMIT_NPROC.
//   - src/http/vhostmap.cpp: mapping strips one leading "www."; lookup of
//     www.<host> falls back to <host>.
//   - src/http/httplogsource.cpp, src/main/configctx.cpp: "useServer 0" gives
//     the vhost its own log file; its directory must exist and be writable.
//   - src/http/rewriterule.cpp: [F] answers 403 and implies [L]; [NC] is
//     accepted on RewriteRule.
//   - src/main/lshttpdmain.cpp: "openlitespeed -t" parses and configures
//     without opening listeners; exit 1 if anything was logged (warnings
//     included), 2 if an [ERROR] was logged.
//   - dist/bin/lswsctrl: "restart" sends SIGUSR1 (graceful); "reload" is
//     the same.
//   - dist/conf/httpd_config.conf.in: stock "module cache" with ls_enabled 1
//     and enableCache 0, stock server-level lsphp, Example vhost.
//   - dist/admin/html.open/lib/LSWebAdmin: WebAdmin refuses root and lsadm
//     as extUser, root, sudo, wheel, shadow and lsadm as extGroup.
//
// Read 2026-11-23, same tag, for the challenge context:
//
//   - src/http/httpvhost.cpp configContext: a context without "type" is
//     static ("null"); "allowBrowse" defaults to 1 and 0 makes the context
//     inaccessible; a location that does not exist is an [ERROR] ("path is
//     not accessible"), so ACMEChallengeDir must exist before a render is
//     tested; with autoLoadHtaccess the context loads LOCATION/.htaccess.
//   - src/http/httpcontext.cpp config: a context reads autoIndex,
//     forceType and a rewrite block with enable, inherit and rules.
//   - src/http/httpsession.cpp processContextRewrite: vhost-level rules run
//     first; then the matched context's rules, or those of the nearest parent
//     with its own rewrite settings, run only if that context enables them.
//   - src/http/httpreq.cpp checkSymLink: restrained refuses only a path that
//     goes through a symlink to a target outside vhRoot and outside the
//     context's location, so a context outside the home is served.
//   - dist/conf/mime.properties: txt is text/plain, so forceType text/plain
//     names a known type.
//
// Read 2026-11-24, same tag and docs, for the cache module:
//
//   - /config/lscache/ [2024-07-29]: the vhost-level sample "module cache {
//     ls_enabled 1 storagePath ... enableCache 0 ... }", and "the most
//     important virtual host cache setting should be storagePath", so each
//     user purges only their own cache.
//   - src/modules/prelinkedmods.cpp: cache is built in, not a .so.
//   - src/main/plainconf.cpp: in a module block every key but ls_enabled
//     (and the block's own keys) becomes a line of its "param" value.
//   - src/http/httpvhost.cpp, src/lsiapi/modulemanager.cpp: vhconf.conf's
//     module blocks are parsed at vhost level over the server's; ls_enabled
//     0 turns the module's hooks off for that vhost.
//   - src/modules/cache/cache.cpp: the keys and their ranges; storagePath is
//     created as root with mode 2770 and chowned to the server user, and
//     purges act on the config's own store; a POST is never cached; the
//     lookup runs when the request headers arrive (checkAssignHandler at
//     LSI_HKPT_RCVD_REQ_HEADER), before rewrite rules.
//   - src/http/httpcgitool.cpp: every LSAPI request gets X-LSCACHE
//     "on,crawler", which the WordPress plugin reads as LSCache being there.
//   - openlitespeed-1.9.4-3.el9.x86_64.rpm (rpms.litespeedtech.com, unpacked,
//     not installed): httpd_config.conf has the stock "module cache" block
//     with ls_enabled 1 and enableCache 0, and cachedata is root-owned 0755.
//
// # Unverified
//
// Not confirmed on an official page or by running a server:
//
//   - The exact bytes Render produces have not been loaded by OpenLiteSpeed
//     from this package's tests; the tests check them against the grammar
//     above, not against a server.
//   - The cgroups docs give server values as 0 off, 1 on, 2 disabled and
//     vhost values as 1 on, 0 off; v1.9.4 source and WebAdmin use 0
//     disabled, 1 off, 2 on, and vhost 1 off, 2 on. This package follows the
//     source.
//   - What cgroups 2 does on a systemd cgroups-v2 host without lssetup and
//     lscgctl limits; Proof 1 does not need it.
//   - That runOnStartUp 0 makes a graceful restart replace running lsphp
//     processes; the docs say attached PHP restarts with the server.
//   - That the default namespace template is enough for WordPress and that
//     OLS namespaces need no SELinux change; the namespace page names no
//     SELinux or kernel prerequisite.
//   - That OLS matches vhost rewrite rules against the decoded,
//     normalised path, so that "%2e" spellings cannot bypass the deny rules.
//     The rules were tested only with Go's regexp.
//   - Whether a WebAdmin save keeps the include line; the 1.9.4 WebAdmin
//     parser has include handling, the docs say it is unsupported.
//   - That 256 MiB of address space is enough for lsphp 8.x with OPcache.
//   - HTTP/3: a secure listener serves QUIC when the stock quicEnable 1 is
//     set; nothing here configures it.
//   - That OpenLiteSpeed serves a challenge file through this context, and
//     that it loads root-only 0600 keys on a graceful restart; the source
//     reading above says so, and the dev VM proof is where it is run.
//   - That "openlitespeed -t" reports no warning for the vhost cache block,
//     that ls_enabled 0 keeps a suspended site's earlier cached pages from
//     being served, and that a WordPress page with the plugin answers
//     "X-LiteSpeed-Cache: hit"; the php-site dev VM proof checks the last
//     one.
package olsweb
