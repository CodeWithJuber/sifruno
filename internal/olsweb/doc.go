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
//     user's home, setUIDMode 2 with user and group set to the account,
//     restrained 1, enableScript 0 when suspended) and the Sifruno listeners
//     with their map lines. httpd_config.conf includes it with one line at
//     the top level, so Sifruno never rewrites the administrator's file.
//   - conf/vhosts/sifruno-NAME/vhconf.conf: docRoot, index files, error and
//     access logs in LogRoot/NAME/, the optional vhssl certificate, the
//     site's own lsphp extprocessor (lsapi over uds://tmp/lshttpd/
//     sifruno-NAME.sock, started through the CGI daemon as extUser/extGroup =
//     the account, with rlimits and LSAPI children), the php script handler
//     that uses it, namespace 2 and cgroups 2 when an active site asks for
//     them, and a rewrite
//     block with .htaccess autoload plus vhost-level deny rules. A suspended
//     site has no extprocessor or handler, autoLoadHtaccess 0 and one rule
//     answering 403 to everything.
//
// Server-level settings stay with the administrator: namespace containers
// need "namespace 1" (or 2) in httpd_config.conf, cgroups need "cgroups 1"
// (or 2) inside its CGIRLimit block, and LSCache uses the stock
// "module cache" block. A second definition in the included file would
// compete with the administrator's, so none is emitted.
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
//     cgroups 0/1/2 = disallow/default off/default on, read from CGIRLimit;
//     the vhost value is 1 off or 2 on.
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
package olsweb
