package olsweb

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// A site's protected folders, converted from the Apache .htaccess rules of a
// migrated site (internal/htaccess, convert.go), are written by the root
// broker into the site's vhconf.conf, never read from the tenant's files.
// Each folder is one regex context ("exp:") because OpenLiteSpeed 1.9.4
// drops a plain context whose location is missing when the config loads,
// which would open the folder once it came back, while a regex context is
// never checked that way and is matched before every other context
// (src/http/httpvhost.cpp configContext, src/http/httpreq.cpp
// processContext). The context has no location line: a regex context's
// default, "$DOC_ROOT$0", maps the whole matched URI under the document
// root. Its rewrite block has enable 0, so no rewrite rule runs for a path
// below the folder before the access check.
//
//	folder closed to all:      allowBrowse 0 (403)
//	  with names open to all:  the regex leaves those names out (negative
//	                           lookahead), so they get the site's normal
//	                           handling; a name is matched only below
//	                           folders whose names have no dot
//	hosts only / except:       accessControl allow/deny lists
//	realm:                     realm, authName, required, and a realm block
//	                           whose userDB is RealmFile(site, n)
//
// Every value is checked against an alphabet with no character the config
// grammar or the regex treats specially, apart from '.', which is written
// as [.].

// RealmRoot holds one root-owned directory per site with the user files of
// its realms, outside every home: OpenLiteSpeed reads them as the web server
// user when a request needs them, so the broker gives that user read access
// and no tenant can put a link there.
const RealmRoot = "/var/lib/sifruno-realms"

// Bounds for protected folders.
const (
	MaxFoldersPerSite  = 32
	MaxFolderNetworks  = 64
	MaxFolderNames     = 64
	MaxFolderUsers     = 64
	maxFolderPathBytes = 200
)

// Folder kinds of client address rule.
const (
	HostsAll    = "all"
	HostsNone   = "none"
	HostsOnly   = "only"
	HostsExcept = "except"
)

// Folder is one protected folder of an active site: Path (a URL path below
// the site root with a leading and trailing slash) and everything below it.
// Hosts is all, none, only or except; Networks are canonical prefixes for
// only and except. Allow names files open to every client in a folder
// whose Hosts is none. Realm asks for a password after the address check.
type Folder struct {
	Path     string       `json:"path"`
	Hosts    string       `json:"hosts"`
	Networks []string     `json:"networks,omitempty"`
	Allow    []string     `json:"allow,omitempty"`
	Realm    *FolderRealm `json:"realm,omitempty"`
}

// FolderRealm is a folder's Basic password check. UserFile must be
// RealmFile(site name, n), n being the folder's place in the site's sorted
// list counted from 1. Users empty means any user in the file.
type FolderRealm struct {
	Name     string   `json:"name"`
	UserFile string   `json:"user_file"`
	Users    []string `json:"users,omitempty"`
}

// RealmFile is the user file of a site's nth folder (counted from 1).
func RealmFile(site string, n int) string {
	return RealmRoot + "/" + site + "/realm" + strconv.Itoa(n) + ".htpasswd"
}

var (
	folderPart       = regexp.MustCompile(`^[A-Za-z0-9_@~-][A-Za-z0-9._@~-]{0,126}$`)
	folderName       = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]{0,126}$`)
	folderRealmName  = regexp.MustCompile(`^[A-Za-z0-9._,:()!?@-]([A-Za-z0-9 ._,:()!?@-]{0,62}[A-Za-z0-9._,:()!?@-])?$`)
	folderUserName   = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	staticFileSuffix = map[string]bool{
		"css": true, "js": true, "mjs": true, "map": true, "json": true, "txt": true, "xml": true,
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "avif": true, "svg": true,
		"ico": true, "bmp": true, "woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true,
		"pdf": true, "mp3": true, "mp4": true, "webm": true, "ogg": true, "wav": true,
	}
)

// ValidFolderPath reports whether p can be a protected folder's path: '/',
// then folder names of letters, digits and . _ @ ~ -, none starting with a
// dot, each followed by '/', at most 200 bytes; never the site root.
func ValidFolderPath(p string) bool {
	if len(p) < 3 || len(p) > maxFolderPathBytes || p[0] != '/' || !strings.HasSuffix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p[1:len(p)-1], "/") {
		if !folderPart.MatchString(part) {
			return false
		}
	}
	return true
}

// openName reports a file name a folder closed to all may open: a static
// file type, which OpenLiteSpeed never hands to a script handler.
func openName(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	return folderName.MatchString(name) && dot > 0 && staticFileSuffix[strings.ToLower(name[dot+1:])]
}

// canonicalNetwork reports a prefix in netip's canonical form with no host
// bits set, not the whole address space.
func canonicalNetwork(s string) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && p.String() == s && p == p.Masked() && p.Bits() > 0 && !p.Addr().Is4In6() && p.Addr().Zone() == ""
}

func sortedOnce(list []string) bool {
	for i := 1; i < len(list); i++ {
		if list[i-1] >= list[i] {
			return false
		}
	}
	return true
}

// CheckFolders validates the protected folders of the site named name
// exactly as Validate does, so a caller can refuse them before it stores
// them. A FieldError names the field as site.folders[i]...
func CheckFolders(name string, folders []Folder) error {
	if !siteNamePattern.MatchString(name) {
		return fieldErr("site.name", "must match %s", siteNamePattern)
	}
	return checkFolders("site", name, folders)
}

// checkFolders validates a site's protected folders: sorted by path, each
// once, none inside another (their regex contexts would overlap), each with
// one consistent rule.
func checkFolders(field string, name string, folders []Folder) error {
	if len(folders) > MaxFoldersPerSite {
		return fieldErr(field+".folders", "at most %d protected folders", MaxFoldersPerSite)
	}
	for i, f := range folders {
		ff := fmt.Sprintf("%s.folders[%d]", field, i)
		if !ValidFolderPath(f.Path) {
			return fieldErr(ff+".path", "must be / then folder names of letters, digits and . _ @ ~ -, none starting with a dot, each ending in /")
		}
		if i > 0 && folders[i-1].Path >= f.Path {
			return fieldErr(ff+".path", "folders must be sorted by path, each once")
		}
		for j := range i {
			if strings.HasPrefix(f.Path, folders[j].Path) {
				return fieldErr(ff+".path", "is inside folders[%d]", j)
			}
		}
		switch f.Hosts {
		case HostsAll, HostsNone:
			if len(f.Networks) != 0 {
				return fieldErr(ff+".networks", "only for hosts only or except")
			}
		case HostsOnly, HostsExcept:
			if len(f.Networks) == 0 || len(f.Networks) > MaxFolderNetworks || !sortedOnce(f.Networks) {
				return fieldErr(ff+".networks", "must list 1 to %d networks, sorted, each once", MaxFolderNetworks)
			}
			for k, n := range f.Networks {
				if !canonicalNetwork(n) {
					return fieldErr(fmt.Sprintf("%s.networks[%d]", ff, k), "must be a canonical IPv4 or IPv6 network")
				}
			}
		default:
			return fieldErr(ff+".hosts", "must be all, none, only or except")
		}
		if len(f.Allow) > 0 {
			if f.Hosts != HostsNone || f.Realm != nil {
				return fieldErr(ff+".allow", "only for a folder closed to all, without a realm")
			}
			if len(f.Allow) > MaxFolderNames || !sortedOnce(f.Allow) {
				return fieldErr(ff+".allow", "must list at most %d names, sorted, each once", MaxFolderNames)
			}
			for k, n := range f.Allow {
				if !openName(n) {
					return fieldErr(fmt.Sprintf("%s.allow[%d]", ff, k), "must be a static file name")
				}
			}
		}
		if f.Realm == nil {
			if f.Hosts == HostsAll {
				return fieldErr(ff, "opens the folder to everyone: nothing to protect")
			}
			continue
		}
		if f.Hosts == HostsNone {
			return fieldErr(ff+".realm", "a folder closed to all never asks for a password")
		}
		if !folderRealmName.MatchString(f.Realm.Name) || strings.Contains(f.Realm.Name, "  ") {
			return fieldErr(ff+".realm.name", "must be 1 to 64 letters, digits, single spaces and . _ , : ( ) ! ? @ -")
		}
		if f.Realm.UserFile != RealmFile(name, i+1) {
			return fieldErr(ff+".realm.user_file", "must be %s", RealmFile(name, i+1))
		}
		if len(f.Realm.Users) > MaxFolderUsers || !sortedOnce(f.Realm.Users) {
			return fieldErr(ff+".realm.users", "must list at most %d users, sorted, each once", MaxFolderUsers)
		}
		for k, u := range f.Realm.Users {
			if !folderUserName.MatchString(u) {
				return fieldErr(fmt.Sprintf("%s.realm.users[%d]", ff, k), "must be 1 to 64 letters, digits and . _ @ -")
			}
		}
	}
	return nil
}

// regexQuote writes a checked folder or file name for PCRE: '.' is the only
// character of those alphabets with a meaning there.
func regexQuote(s string) string { return strings.ReplaceAll(s, ".", "[.]") }

// folderPattern is the folder's context regex. (?s) lets '.' match a newline
// too, so a file name with one cannot slip past the folder; (?!.) is the end
// of the URI. A closed folder with open names leaves out exactly those
// names, below folders whose names have no dot.
func folderPattern(f Folder) string {
	p := "(?s)^" + regexQuote(f.Path)
	if len(f.Allow) > 0 {
		names := make([]string, len(f.Allow))
		for i, n := range f.Allow {
			names[i] = regexQuote(n)
		}
		p += "(?!(?:[^/.]+/)*(?:" + strings.Join(names, "|") + ")(?!.))"
	}
	return p + ".*"
}

// singleAddress writes a one-address network as the address alone:
// OpenLiteSpeed's parseNetmask refuses /32 and /128.
func singleAddress(n string) string {
	p := netip.MustParsePrefix(n)
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return n
}

func addressList(networks []string) string {
	out := make([]string, len(networks))
	for i, n := range networks {
		out[i] = singleAddress(n)
	}
	return strings.Join(out, ", ")
}

// renderFolders writes an active site's realms and protected folders.
func renderFolders(b *bytes.Buffer, v site) {
	for i, f := range v.Folders {
		if f.Realm == nil {
			continue
		}
		fmt.Fprintf(b, "\nrealm %srealm%d {\n", NamePrefix, i+1)
		b.WriteString("  userDB  {\n")
		fmt.Fprintf(b, "    %-21s %s\n", "location", f.Realm.UserFile)
		b.WriteString("  }\n")
		b.WriteString("}\n")
	}
	for i, f := range v.Folders {
		b.WriteString("\ncontext exp:" + folderPattern(f) + " {\n")
		if f.Hosts == HostsNone {
			// A closed folder serves nothing, so its location is the empty
			// root-owned SuspendedDocRoot: OpenLiteSpeed then looks for the
			// context's .htaccess there, not at a name in the tenant's
			// document root, which it would read as root when the config
			// loads (HttpContext::config, configRewriteRule).
			kv(b, "location", SuspendedDocRoot+"/")
			kv(b, "allowBrowse", "0")
		} else {
			kv(b, "allowBrowse", "1")
			if f.Realm != nil {
				kv(b, "realm", fmt.Sprintf("%srealm%d", NamePrefix, i+1))
				kv(b, "authName", f.Realm.Name)
				required := "valid-user"
				if len(f.Realm.Users) > 0 {
					required = "user " + strings.Join(f.Realm.Users, " ")
				}
				kv(b, "required", required)
			}
			b.WriteString("  accessControl  {\n")
			switch f.Hosts {
			case HostsAll:
				fmt.Fprintf(b, "    %-21s %s\n", "allow", "ALL")
			case HostsOnly:
				fmt.Fprintf(b, "    %-21s %s\n", "allow", addressList(f.Networks))
				fmt.Fprintf(b, "    %-21s %s\n", "deny", "ALL")
			case HostsExcept:
				fmt.Fprintf(b, "    %-21s %s\n", "allow", "ALL")
				fmt.Fprintf(b, "    %-21s %s\n", "deny", addressList(f.Networks))
			}
			b.WriteString("  }\n")
		}
		b.WriteString("  rewrite  {\n")
		fmt.Fprintf(b, "    %-21s %s\n", "enable", "0")
		b.WriteString("  }\n")
		b.WriteString("}\n")
	}
}

// checkFolderListeners refuses a folder closed to some networks only
// (except) while a listener has an IPv6 address. A "*" listener binds IPv4
// only (src/socket/gsockaddr.cpp: an address without '[' is AF_INET, "*"
// INADDR_ANY), so every client is an IPv4 address there. An IPv6 listener
// is dual-stack on Linux and sees IPv4 clients as ::ffff:a.b.c.d, which
// AccessControl::hasAccess(const in6_addr&) (src/util/accesscontrol.cpp)
// looks up in the IPv6 lists only: addIPControl and addSubNetControl store
// mapped and IPv4 entries in the IPv4 lists, so an IPv4 deny entry would
// miss and the client would be let in. A folder open to some networks only
// fails closed there (deny ALL covers both families) and is kept.
func checkFolderListeners(listeners []Listener, sites []Site) error {
	ipv6 := false
	for _, l := range listeners {
		if a, err := netip.ParseAddr(l.Address); err == nil && a.Is6() {
			ipv6 = true
		}
	}
	if !ipv6 {
		return nil
	}
	for i, s := range sites {
		for j, f := range s.Folders {
			if f.Hosts == HostsExcept {
				return fieldErr(fmt.Sprintf("sites[%d].folders[%d].hosts", i, j), "a folder closed to some networks needs IPv4 listeners only: an IPv6 listener sees IPv4 clients as ::ffff: addresses its deny list misses")
			}
		}
	}
	return nil
}

// FolderRealmFiles lists the user files a site's folders name, in order.
func FolderRealmFiles(folders []Folder) []string {
	var out []string
	for _, f := range folders {
		if f.Realm != nil {
			out = append(out, f.Realm.UserFile)
		}
	}
	return slices.Clip(out)
}
