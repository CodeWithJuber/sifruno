package htaccess

import "strings"

// entry describes one Apache directive. honoured is the OpenLiteSpeed column:
// true only when OLS 1.9.4 acts on the directive when it loads .htaccess (see
// doc.go for the evidence). The classifier refines some rows per use, for
// example a rewrite rule inside a container OLS ignores.
type entry struct {
	category Category
	honoured bool
	access   AccessKind
}

// directiveTable is the single source for directive categories and for the
// set OLS honours. Keys are lower case; Apache matches names
// case-insensitively. Section containers (<IfModule>, <Files>, ...) are
// handled in classify.go because their meaning depends on their contents.
var directiveTable = map[string]entry{
	// Read by OLS's .htaccess loader (RewriteEngine::parseRules).
	"rewriteengine":  {CategoryRewrite, true, ""},
	"rewritecond":    {CategoryRewrite, true, ""},
	"rewriterule":    {CategoryRewrite, true, ""},
	"rewritebase":    {CategoryRewrite, true, ""},
	"cachekeymodify": {CategoryVendor, true, ""},
	// RewriteFile is also read by OLS, but it pulls in another file that this
	// scan does not open, so its effect is not known here.
	"rewritefile": {CategoryVendor, false, ""},

	"rewriteoptions": {CategoryRewrite, false, ""},
	"rewritemap":     {CategoryRewrite, false, ""},
	"cachelookup":    {CategoryVendor, false, ""},

	"authtype":                    {CategoryAccessControl, false, AccessPassword},
	"authname":                    {CategoryAccessControl, false, AccessPassword},
	"authuserfile":                {CategoryAccessControl, false, AccessPassword},
	"authgroupfile":               {CategoryAccessControl, false, AccessPassword},
	"authbasicprovider":           {CategoryAccessControl, false, AccessPassword},
	"authdigestprovider":          {CategoryAccessControl, false, AccessPassword},
	"authdbmuserfile":             {CategoryAccessControl, false, AccessPassword},
	"authdbmgroupfile":            {CategoryAccessControl, false, AccessPassword},
	"require":                     {CategoryAccessControl, false, AccessDenyAllow},
	"satisfy":                     {CategoryAccessControl, false, AccessDenyAllow},
	"order":                       {CategoryAccessControl, false, AccessDenyAllow},
	"allow":                       {CategoryAccessControl, false, AccessDenyAllow},
	"deny":                        {CategoryAccessControl, false, AccessDenyAllow},
	"sslrequiressl":               {CategoryAccessControl, false, AccessTLS},
	"sslrequire":                  {CategoryAccessControl, false, AccessTLS},
	"sslverifyclient":             {CategoryAccessControl, false, AccessTLS},
	"indexignore":                 {CategoryAccessControl, false, AccessListing},
	"removehandler":               {CategoryAccessControl, false, AccessExec},
	"removetype":                  {CategoryAccessControl, false, AccessExec},
	"authzsendforbiddenonfailure": {CategoryAccessControl, false, AccessDenyAllow},

	"php_value":        {CategoryPHPSettings, false, ""},
	"php_flag":         {CategoryPHPSettings, false, ""},
	"php_admin_value":  {CategoryPHPSettings, false, ""},
	"php_admin_flag":   {CategoryPHPSettings, false, ""},
	"suphp_configpath": {CategoryPHPSettings, false, ""},
	"suphp_engine":     {CategoryPHPSettings, false, ""},

	"header":        {CategoryHeaders, false, ""},
	"requestheader": {CategoryHeaders, false, ""},

	"expiresactive":      {CategoryCaching, false, ""},
	"expiresbytype":      {CategoryCaching, false, ""},
	"expiresdefault":     {CategoryCaching, false, ""},
	"fileetag":           {CategoryCaching, false, ""},
	"cacheenable":        {CategoryCaching, false, ""},
	"cachedisable":       {CategoryCaching, false, ""},
	"cachedefaultexpire": {CategoryCaching, false, ""},
	"cachemaxexpire":     {CategoryCaching, false, ""},

	"addtype":                {CategoryMIMEHandlers, false, ""},
	"addhandler":             {CategoryMIMEHandlers, false, ""},
	"sethandler":             {CategoryMIMEHandlers, false, ""},
	"addencoding":            {CategoryMIMEHandlers, false, ""},
	"forcetype":              {CategoryMIMEHandlers, false, ""},
	"directoryindex":         {CategoryMIMEHandlers, false, ""},
	"directoryindexredirect": {CategoryMIMEHandlers, false, ""},
	"addcharset":             {CategoryMIMEHandlers, false, ""},
	"adddefaultcharset":      {CategoryMIMEHandlers, false, ""},
	"addlanguage":            {CategoryMIMEHandlers, false, ""},
	"defaultlanguage":        {CategoryMIMEHandlers, false, ""},
	"defaulttype":            {CategoryMIMEHandlers, false, ""},
	"removeencoding":         {CategoryMIMEHandlers, false, ""},
	"removecharset":          {CategoryMIMEHandlers, false, ""},
	"removelanguage":         {CategoryMIMEHandlers, false, ""},
	"addinputfilter":         {CategoryMIMEHandlers, false, ""},
	"setinputfilter":         {CategoryMIMEHandlers, false, ""},
	"removeinputfilter":      {CategoryMIMEHandlers, false, ""},
	"addoutputfilter":        {CategoryMIMEHandlers, false, ""},
	"addoutputfilterbytype":  {CategoryMIMEHandlers, false, ""},
	"setoutputfilter":        {CategoryMIMEHandlers, false, ""},
	"removeoutputfilter":     {CategoryMIMEHandlers, false, ""},
	"action":                 {CategoryMIMEHandlers, false, ""},
	"multiviewsmatch":        {CategoryMIMEHandlers, false, ""},
	"fcgiwrapper":            {CategoryMIMEHandlers, false, ""},

	"redirect":          {CategoryRedirectAlias, false, ""},
	"redirectmatch":     {CategoryRedirectAlias, false, ""},
	"redirectpermanent": {CategoryRedirectAlias, false, ""},
	"redirecttemp":      {CategoryRedirectAlias, false, ""},

	"errordocument": {CategoryErrorDocuments, false, ""},

	"deflatecompressionlevel":        {CategoryCompression, false, ""},
	"deflatebuffersize":              {CategoryCompression, false, ""},
	"deflatefilternote":              {CategoryCompression, false, ""},
	"deflatememlevel":                {CategoryCompression, false, ""},
	"deflatewindowsize":              {CategoryCompression, false, ""},
	"deflatealteretag":               {CategoryCompression, false, ""},
	"deflateinflatelimitrequestbody": {CategoryCompression, false, ""},
	"brotlicompressionquality":       {CategoryCompression, false, ""},
	"brotlicompressionwindow":        {CategoryCompression, false, ""},
	"brotlifilternote":               {CategoryCompression, false, ""},
	"brotlialteretag":                {CategoryCompression, false, ""},

	"setenv":             {CategoryEnvironment, false, ""},
	"unsetenv":           {CategoryEnvironment, false, ""},
	"passenv":            {CategoryEnvironment, false, ""},
	"setenvif":           {CategoryEnvironment, false, ""},
	"setenvifnocase":     {CategoryEnvironment, false, ""},
	"setenvifexpr":       {CategoryEnvironment, false, ""},
	"browsermatch":       {CategoryEnvironment, false, ""},
	"browsermatchnocase": {CategoryEnvironment, false, ""},

	"options":               {CategoryOther, false, ""},
	"acceptpathinfo":        {CategoryOther, false, ""},
	"cgipassauth":           {CategoryOther, false, ""},
	"cgivar":                {CategoryOther, false, ""},
	"contentdigest":         {CategoryOther, false, ""},
	"serversignature":       {CategoryOther, false, ""},
	"limitrequestbody":      {CategoryOther, false, ""},
	"limitxmlrequestbody":   {CategoryOther, false, ""},
	"enablemmap":            {CategoryOther, false, ""},
	"enablesendfile":        {CategoryOther, false, ""},
	"languagepriority":      {CategoryOther, false, ""},
	"forcelanguagepriority": {CategoryOther, false, ""},
	"checkspelling":         {CategoryOther, false, ""},
	"checkcaseonly":         {CategoryOther, false, ""},
	"xbithack":              {CategoryOther, false, ""},
	"ssierrormsg":           {CategoryOther, false, ""},
	"ssitimeformat":         {CategoryOther, false, ""},
	"substitute":            {CategoryOther, false, ""},
	"directoryslash":        {CategoryOther, false, ""},
	"directorycheckhandler": {CategoryOther, false, ""},
	"fallbackresource":      {CategoryOther, false, ""},
	"indexoptions":          {CategoryOther, false, ""},
	"indexorderdefault":     {CategoryOther, false, ""},
	"indexstylesheet":       {CategoryOther, false, ""},
	"indexheadinsert":       {CategoryOther, false, ""},
	"headername":            {CategoryOther, false, ""},
	"readmename":            {CategoryOther, false, ""},
	"adddescription":        {CategoryOther, false, ""},
	"addicon":               {CategoryOther, false, ""},
	"addiconbyencoding":     {CategoryOther, false, ""},
	"addiconbytype":         {CategoryOther, false, ""},
	"defaulticon":           {CategoryOther, false, ""},
	"ssloptions":            {CategoryOther, false, ""},
	"sslverifydepth":        {CategoryOther, false, ""},
	"sslciphersuite":        {CategoryOther, false, ""},
	"sslrenegbuffersize":    {CategoryOther, false, ""},
	"secfilterengine":       {CategoryOther, false, ""},
	"secfilterscanpost":     {CategoryOther, false, ""},
	"secruleengine":         {CategoryOther, false, ""},
	"secrequestbodyaccess":  {CategoryOther, false, ""},
	"secruleremovebyid":     {CategoryOther, false, ""},
	"secruleremovebymsg":    {CategoryOther, false, ""},
	"xsendfile":             {CategoryOther, false, ""},
	"xsendfilepath":         {CategoryOther, false, ""},
}

// directivePrefixes covers module families with many directive names. The
// auth prefix spans mod_auth_*, mod_authn_* and mod_authz_* directives, all of
// which configure authentication or authorization.
var directivePrefixes = []struct {
	prefix string
	entry  entry
}{
	{"auth", entry{CategoryAccessControl, false, AccessPassword}},
	{"mod_gzip_", entry{CategoryCompression, false, ""}},
	{"modpagespeed", entry{CategoryOther, false, ""}},
	{"passenger", entry{CategoryOther, false, ""}},
}

func lookup(lower string) (entry, bool) {
	if e, ok := directiveTable[lower]; ok {
		return e, true
	}
	for _, p := range directivePrefixes {
		if strings.HasPrefix(lower, p.prefix) && len(lower) > len(p.prefix) {
			return p.entry, true
		}
	}
	return entry{}, false
}
