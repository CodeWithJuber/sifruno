// Package htaccess finds the Apache .htaccess directives that OpenLiteSpeed
// (OLS) would not act on, so a migration can tell which sites keep their
// behaviour on OLS (native), which need a converter to move directives into
// virtual host configuration (convertible), and which must stay on Apache with
// PHP-FPM (compat). Access-control directives and anything unrecognised send a
// site to compat: OLS silently ignoring a password or deny rule would open a
// closed directory.
//
// The package is read-only. It parses and classifies files; it does not
// convert, rewrite or serve anything, and a verdict here is a pre-flight
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
package htaccess
