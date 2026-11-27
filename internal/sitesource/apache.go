package sitesource

import (
	"fmt"
	"regexp"
	"strings"

	"sifruno/internal/htaccess"
	"sifruno/internal/sitemodel"
)

// ApacheSite is one <VirtualHost> of an Apache configuration file: its
// names (ServerName first), its document root, the user its PHP runs as
// when the file says, the PHP handler's version, the TLS files, and the
// lines of the virtual host that do not move. .htaccess files in the
// document root are read by the copy's own scan (internal/htaccess).
type ApacheSite struct {
	File      string
	Line      int
	Names     []string
	Root      string
	User      string
	PHPSource string
	TLS       *TLSFiles
	Refused   []sitemodel.Item
	Notes     []sitemodel.Item
}

var (
	// A PHP-FPM handler names its socket or pool: php8.2-fpm, php82,
	// php-fpm/www.sock with the version elsewhere, ea-php82 on cPanel.
	apachePHP = regexp.MustCompile(`(?:ea-)?php-?([5-8])\.?([0-9])`)
	// Directives inside a virtual host that set what Sifruno sets itself
	// or only change logging; the rest of a virtual host is not carried.
	apacheHarmless = map[string]bool{
		"servername": true, "serveralias": true, "documentroot": true, "serveradmin": true, "errorlog": true, "customlog": true,
		"transferlog": true, "loglevel": true, "sslengine": true, "sslcertificatefile": true, "sslcertificatekeyfile": true,
		"sslcertificatechainfile": true, "sslprotocol": true, "sslciphersuite": true, "sslhonorcipherorder": true,
		"suexecusergroup": true, "assignuserid": true, "directoryindex": true, "options": true, "allowoverride": true,
		"protocols": true, "keepalive": true, "usecanonicalname": true, "header": true, "addhandler": true, "sethandler": true,
		"includeoptional": true,
	}
)

// ParseApache reads the virtual hosts of one Apache configuration file.
// Its syntax is .htaccess syntax (internal/htaccess's parser); a file with
// a structural problem is refused, as Apache refuses it.
func ParseApache(name string, data []byte) ([]ApacheSite, error) {
	f, err := htaccess.Parse(data)
	if err != nil {
		return nil, &ParseError{File: name, Line: 0, Reason: "the file is larger than 1 MiB"}
	}
	if len(f.Problems) > 0 {
		return nil, &ParseError{File: name, Line: f.Problems[0].Line, Reason: f.Problems[0].Reason}
	}
	var out []ApacheSite
	var walk func([]*htaccess.Node)
	walk = func(nodes []*htaccess.Node) {
		for _, n := range nodes {
			if n.Kind != htaccess.KindSection {
				continue
			}
			if strings.EqualFold(n.Name, "VirtualHost") {
				out = append(out, apacheSite(name, n))
				continue
			}
			if strings.EqualFold(n.Name, "IfModule") || strings.EqualFold(n.Name, "IfDefine") {
				walk(n.Children)
			}
		}
	}
	walk(f.Nodes)
	return out, nil
}

func apacheSite(file string, vh *htaccess.Node) ApacheSite {
	s := ApacheSite{File: file, Line: vh.Line}
	at := func(n *htaccess.Node) string { return fmt.Sprintf("%s line %d", file, n.Line) }
	var aliases []string
	var visit func([]*htaccess.Node)
	visit = func(nodes []*htaccess.Node) {
		for _, n := range nodes {
			name := strings.ToLower(n.Name)
			switch n.Kind {
			case htaccess.KindSection:
				switch name {
				case "directory", "files", "filesmatch", "location", "locationmatch", "directorymatch", "ifmodule", "ifdefine", "ifversion":
					visit(n.Children)
				default:
					s.Refused = append(s.Refused, sitemodel.Item{Part: "rule", Text: "<" + n.Name + ">: Sifruno does not convert this section of a virtual host.", Where: at(n)})
				}
				continue
			case htaccess.KindDirective:
			default:
				continue
			}
			arg := func(i int) string {
				if i < len(n.Args) {
					return n.Args[i]
				}
				return ""
			}
			switch name {
			case "servername":
				s.Names = append([]string{strings.ToLower(hostOnly(arg(0)))}, s.Names...)
			case "serveralias":
				for _, a := range n.Args {
					aliases = append(aliases, strings.ToLower(a))
				}
			case "documentroot":
				s.Root = arg(0)
			case "suexecusergroup", "assignuserid":
				s.User = arg(0)
			case "sslcertificatefile", "sslcertificatekeyfile":
				if s.TLS == nil {
					s.TLS = &TLSFiles{}
				}
				if name == "sslcertificatefile" {
					s.TLS.Certificate = arg(0)
				} else {
					s.TLS.Key = arg(0)
				}
			case "sethandler", "addhandler":
				if m := apachePHP.FindStringSubmatch(strings.Join(n.Args, " ")); m != nil && s.PHPSource == "" {
					s.PHPSource = "php" + m[1] + "." + m[2] + "-fpm"
				}
			case "require":
				// "Require all granted" is every virtual host's default;
				// anything else decides who may read what.
				if !(len(n.Args) == 2 && strings.EqualFold(arg(0), "all") && strings.EqualFold(arg(1), "granted")) {
					s.Refused = append(s.Refused, sitemodel.Item{Part: "rule", Text: "Require: access rules in the virtual host are not converted; the folder would open to everyone.", Where: at(n)})
				}
			case "php_value", "php_flag", "php_admin_value", "php_admin_flag":
				s.Notes = append(s.Notes, sitemodel.Item{Part: "php", Text: n.Name + " " + clip(arg(0)) + ": PHP settings in the virtual host are not carried.", Where: at(n)})
			default:
				if !apacheHarmless[name] {
					s.Refused = append(s.Refused, sitemodel.Item{Part: "rule", Text: n.Name + ": Sifruno does not convert this line of a virtual host.", Where: at(n)})
				}
			}
		}
	}
	visit(vh.Children)
	s.Names = append(s.Names, aliases...)
	return s
}

// hostOnly drops a port or scheme a ServerName may carry.
func hostOnly(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}
