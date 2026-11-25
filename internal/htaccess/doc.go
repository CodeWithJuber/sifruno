// Package htaccess finds the Apache .htaccess directives that OpenLiteSpeed
// (OLS) would not act on, so a migration can tell which sites keep their
// behaviour on OLS (native), which need a converter to move directives into
// virtual host configuration (convertible), and which must stay on Apache with
// PHP-FPM (compat). Access-control directives and anything unrecognised send a
// file to compat: OLS silently ignoring a password or deny rule would open a
// closed directory. ConvertSite then decides whether a site whose only compat
// files hold a listed access pattern is Native after all, with those rules
// moved into the vhost (convert.go).
//
// The package is read-only. It parses, classifies and converts files; it
// does not rewrite or serve anything, and a verdict here is a pre-flight
// estimate, not proof of behaviour on a running server. A later migration
// verify step must still request the recorded access-rule URLs and compare
// responses.
//
// # What OpenLiteSpeed honours from .htaccess (evidence)
//
// All sources below were read on 2026-11-22.
//
//   - OLS source, tag v1.9.4 (commit aeba673f6cce6c9da892573d115e8c826a73d400,
//     the newest release tag on 2026-11-22),
//     https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/http/rewriteengine.cpp
//     RewriteEngine::parseRules is the only .htaccess loader. It acts on
//     RewriteEngine, RewriteCond, RewriteRule, RewriteBase, RewriteFile and
//     CacheKeyModify. Lines starting with "<IfModule" and "</IfModule>" are
//     read through without testing the module, except that a block whose
//     <IfModule line contains "mod_headers" is skipped as a whole. Every other
//     line is logged as "Invalid rewrite directive" and dropped. When a rule
//     fails to parse, the loader returns and the rest of the file is never
//     applied.
//   - Same tag, src/http/rewriterule.cpp RewriteRule::parse: after a
//     RewriteCond only comments, further RewriteCond lines, RewriteRule or
//     CacheKeyModify may follow; anything else fails the rule, which (above)
//     ends loading of the file.
//   - Same tag, src/http/httpvhost.cpp and src/http/httpcontext.cpp
//     (configRewriteRule): with autoLoadHtaccess on, the .htaccess of each
//     directory context is fed to the loader above as a RewriteFile. A search
//     of the tag's src/ tree for "htaccess" finds no other loader; the other
//     hits are the autoLoadHtaccess setting, comments in the PageSpeed module
//     and a PHP ini stage constant in mod_lsphp. php_value, php_flag,
//     php_admin_value and php_admin_flag are read only from the
//     phpIniOverride node of the virtual host or context configuration.
//   - The same file at tags v1.7.19 and v1.8.3 has no "mod_headers" check; it
//     first appears at v1.8.4. Older OLS versions apply rewrite rules inside
//     <IfModule mod_headers.c> blocks.
//   - dist/docs/Rewrite_Help.html at v1.9.4, "Auto Load from .htaccess": "Once
//     initially loaded, a graceful restart must be performed for any further
//     changes to that .htaccess file to take effect." It also lists the rewrite
//     differences: %{LA-U:...} and %{LA-F:...} are ignored and [L] behaves
//     like Apache's [END].
//   - dist/docs/Static_Context.html at v1.9.4, "php.ini Override": PHP
//     settings are a context or virtual host setting in OLS.
//   - https://docs.openlitespeed.org/config/rewriterules/ (page dated
//     2024-07-29): "OLS currently supports mod_rewrite rules from Apache",
//     "Unsupported directives will be ignored by OpenLiteSpeed", and OLS must
//     be restarted after a .htaccess change.
//   - https://docs.openlitespeed.org/security/access/ : "OpenLiteSpeed only
//     supports .htaccess for rewrite rules, and not for directives." Access
//     control is configured in WebAdmin (Accessible, Access Allowed/Denied).
//   - https://www.litespeedtech.com/products/litespeed-web-server/editions :
//     "OpenLiteSpeed requires a restart to load any new .htaccess file", while
//     LiteSpeed Enterprise re-reads .htaccess without restart and claims full
//     Apache compatibility. This package models OpenLiteSpeed only.
//
// So a .htaccess written after OpenLiteSpeed last started is not acted on
// until it restarts. This package does not restart anything. The root
// broker does: its web changes end with a graceful restart, and with the
// web operation on it also watches the homes filesystem and restarts
// gracefully, at most once per 30-second window, after any .htaccess is
// created, written, moved or deleted (internal/hostaccounts
// htaccess_watch.go and its README, ".htaccess changes").
//
// The supported set is the honoured column of directiveTable in table.go.
// Correct it there; nothing else encodes it.
//
// # Unverified (classified conservatively)
//
//   - RewriteBase is honoured by the OLS loader, but whether its result
//     matches Apache when the value differs from the directory's own URL path
//     (for example an addon-domain docroot below public_html) was not tested.
//     Only a RewriteBase equal to the directory's URL path counts as honoured.
//   - OLS's regex engine was not compared with Apache's PCRE pattern by
//     pattern. A rule OLS rejects ends loading of the rest of the file; this
//     package detects the RewriteCond-not-followed-by-RewriteRule case only.
//   - The Apache side of directiveTable (which names exist and which module
//     they belong to) comes from the Apache httpd 2.4 directive index and was
//     not re-checked name by name in this run. A name missing from the table
//     is classified unknown and fails closed (compat), so a gap over-reports
//     compat rather than hiding an access rule.
//   - https://openlitespeed.org/kb/ answered HTTP 403 and could not be read.
//   - Third-party add-ons that extend OLS .htaccess handling (for example
//     CyberPanel's paid .htaccess module) are not part of OLS and are not
//     assumed.
//
// # Converting access rules
//
// convert.go turns the access rules of one .htaccess into a FolderRule that
// internal/olsweb renders as OpenLiteSpeed vhost config, or refuses. It
// recognises the patterns in its table and nothing else. Where Apache and
// OpenLiteSpeed differ it keeps the stricter result or refuses. Sources were
// read on 2026-11-24.
//
// Apache httpd 2.4, what the converter relies on:
//
//   - Order, Allow, Deny (https://httpd.apache.org/docs/2.4/mod/mod_access_compat.html):
//     Deny,Allow is the default and admits a client unless a Deny matches
//     and no Allow does; Allow,Deny admits only a client an Allow matches and
//     no Deny does; Mutual-failure is refused. "When any directive provided
//     by this module is used in a new configuration section, no directives
//     provided by this module are inherited from previous configuration
//     sections": the module has no merger (modules/aaa/mod_access_compat.c,
//     "dir merger --- default is to override"), and server/config.c
//     (ap_set_config_vectors) creates a section's config only when the
//     section uses one of the module's directives. So a <Files> section with
//     "Allow from all" has its own Deny,Allow config with no Deny and admits
//     everyone, whatever the folder said. Allow from takes all, full,
//     partial ("10.1") and CIDR IPv4, and IPv6; host names, netmasks and
//     env= are refused here.
//   - Require (https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html,
//     https://httpd.apache.org/docs/2.4/mod/mod_authz_host.html,
//     https://httpd.apache.org/docs/2.4/mod/mod_authz_user.html): several
//     Require lines in one section "are implicitly contained within a
//     <RequireAny>"; with the default AuthMerging Off a section with its own
//     Require lines overrides earlier ones. Only all granted, all denied, ip,
//     valid-user and user convert, one kind per section; containers, not,
//     host, env, expr and group refuse.
//   - Both modules together: "Mixing old directives like Order, Allow or Deny
//     with new ones like Require is technically possible but discouraged";
//     with the default Satisfy All a client must pass both (request.c runs
//     the access checker, then authorization). Any Satisfy line refuses.
//   - AuthType, AuthName (https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html),
//     AuthBasicProvider (https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html),
//     AuthUserFile (https://httpd.apache.org/docs/2.4/mod/mod_authn_file.html):
//     Basic with the file provider and an absolute user file only. The user
//     file formats are in https://httpd.apache.org/docs/2.4/misc/password_encryptions.html;
//     userfile.go keeps the shapes both servers check alike.
//   - <Files>, <FilesMatch>, <IfModule>, Options
//     (https://httpd.apache.org/docs/2.4/mod/core.html): sections merge as
//     <Directory> and .htaccess, then <Files> and <FilesMatch>
//     (https://httpd.apache.org/docs/2.4/sections.html#merging), and a
//     <Files> section in a folder applies to "any other instance" of the
//     name "found under" it. <IfModule [!]mod_authz_core.c> (or
//     authz_core_module) is evaluated for Apache 2.4 and 2.2 alike, and both
//     must give the same rule. Options -Indexes converts to nothing: every
//     Sifruno vhost has autoIndex 0.
//
// OpenLiteSpeed 1.9.4, what the rule is rendered to (source tag v1.9.4, and
// https://docs.openlitespeed.org/security/access/ and
// https://docs.openlitespeed.org/security/realms/, both dated 2026-04-28):
//
//   - A context's accessControl allow and deny lists (src/main/configctx.cpp
//     configSecurity) are matched most specific first
//     (src/util/accesscontrol.cpp hasAccess); ALL or * set the default.
//     A single address is written without a prefix length, because
//     parseNetmask refuses /32 and /128.
//   - A realm's userDB file (src/http/httpvhost.cpp configRealm) is read when
//     a request needs it, by the server process after it dropped root
//     (src/util/hashdatacache.cpp FileStore::open), so it must be readable by
//     the web server user; the docs say the same.
//   - processContextAuth (src/http/httpsession.cpp) answers 403 when the
//     address check fails, then 401 until a user in the realm signs in.
//     The order of the request stages is vhost rewrite, context match,
//     context rewrite, file map, then this check; a rewrite that changes the
//     URI sends the request back to context matching, and a changed context
//     is checked again (src/http/httpreq.cpp postRewriteProcess).
//   - A plain context whose location does not exist when the config loads
//     is dropped with an error (src/http/httpvhost.cpp configContext,
//     "path is not accessible"), which would open the folder once it came
//     back. An "exp:" regex context is not checked that way, and
//     HttpReq::processContext tries the regex contexts before any other.
//     Every converted folder is therefore one regex context.
//   - A context found by bestMatch is extended per subfolder with contexts
//     that inherit its access control and load that subfolder's .htaccess
//     rewrite rules (src/http/httpvhost.cpp bestMatch); a regex context takes
//     the whole subtree instead, with rewriting off. Hence ConvertSite's
//     refusal of any .htaccess below a converted folder.
//   - <Files> names map to a negative lookahead in the folder's regex, so
//     only the exact names, below folders whose names have no dot, fall
//     through to the normal handling. A name is opened only with a static
//     file suffix: OpenLiteSpeed refuses a static file with a path after it
//     (src/http/httpreq.cpp setMimeBySuffix, "Path info is not allowed for
//     static file"), and a folder name without a dot cannot be a script, so
//     "/folder/script.php/allowed.css" stays closed.
//
// Unverified until the dev VM proof runs it: that OpenLiteSpeed loads the
// rendered regex contexts and realms without warnings, serves index files
// and PHP through them, and answers the statuses above for paths spelled
// with %-escapes or double slashes.
package htaccess
