// Package whmsource reads an old cPanel server through its WHM API 1 over
// HTTPS, for Move a website here with the old server's WHM login (D-0005).
// It runs as the panel, never as root: it lists the accounts, adds and
// removes the broker's migration public key for root, and fetches what the
// copy asks of cPanel, which the broker reads with the same parsers as
// whmapi1's and uapi's output over SSH. The private key never leaves the
// broker.
//
// The login (an API token, or the root password) is held in memory only,
// for one connection to the old server; it is never stored, logged or
// returned, and is sent only to the address the admin gave, over TLS that
// the system trust store verifies or that the admin pinned by the
// certificate's SHA-256 fingerprint.
//
// cPanel's behaviour is taken from its public documentation, read on
// 2026-11-26 (the WHM OpenAPI specification 11.138):
//
//   - Authentication: https://api.docs.cpanel.net/whm/tokens ("Authorization:
//     whm username:token") and
//     https://api.docs.cpanel.net/guides/guide-to-api-authentication/guide-to-api-authentication-username-and-password-authentication
//     (basic authentication, only over SSL on port 2087).
//   - Calls: https://api.docs.cpanel.net/whm/introduction
//     (https://host:2087/json-api/<function>?api.version=1&...), every
//     answer with metadata.result 1 for success, 0 with metadata.reason.
//   - Each function's page is cited where it is called.
package whmsource

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"sifruno/internal/cpsource"
	"sifruno/internal/hostaccounts"
)

// DefaultPort is WHM's HTTPS port.
const DefaultPort = 2087

// Bounds on every call, so a slow or hostile server cannot hold the panel.
const (
	dialTimeout   = 15 * time.Second
	callTimeout   = 90 * time.Second
	maxAnswer     = cpsource.MaxOutput
	maxReasonText = 300
)

// Address is the old server's WHM: a lowercase DNS name or an IPv4
// address, and the HTTPS port.
type Address struct {
	Host string
	Port int
}

func (a Address) hostPort() string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

func (a Address) String() string { return "https://" + a.hostPort() }

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ErrAddress is an address this package does not call.
var ErrAddress = errors.New("the WHM address is not https://host:port")

// ParseAddress reads what the admin typed: a host, host:port, or an https
// URL such as https://server1.example.com:2087 (a path, as a browser shows
// one, is ignored: only the scheme, host and port are used). Plain http, a
// user name in the URL, IPv6 and this server's own loopback are refused;
// the port is 2087 unless given.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 2048 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return Address{}, ErrAddress
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return Address{}, ErrAddress
	}
	host := u.Hostname()
	port := DefaultPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return Address{}, ErrAddress
		}
		port = n
	}
	if !validHost(host) {
		return Address{}, ErrAddress
	}
	return Address{Host: host, Port: port}, nil
}

// validHost is the broker's rule for a migration's host (an IPv4 address
// or a DNS name with a dot), because SSH and rsync reach the same name.
func validHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil && ip.String() == host && allowedIP(ip)
	}
	return len(host) <= 253 && dnsName.MatchString(host)
}

// allowedIP refuses addresses that are never an old server: this server's
// loopback, unspecified, link-local (a cloud's metadata service) and
// multicast. A private address is allowed: the old server may share a
// network with this one.
func allowedIP(ip net.IP) bool {
	if ip.IsLoopback() && loopbackAllowed.Load() {
		return true
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsInterfaceLocalMulticast()
}

var loopbackAllowed atomic.Bool

// AllowLoopbackForTesting lets tests reach a fake WHM on 127.0.0.1
// (whmtest). Nothing but a test calls it.
func AllowLoopbackForTesting() { loopbackAllowed.Store(true) }

// Login is root's WHM login: an API token, or the root password.
type Login struct {
	Token    string
	Password string
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)

// Valid reports whether exactly one of the two is given in a form WHM
// takes: a token of 16 to 128 letters and digits, or a password of 1 to
// 1024 bytes without control characters.
func (l Login) Valid() bool {
	switch {
	case l.Token != "" && l.Password == "":
		return tokenPattern.MatchString(l.Token)
	case l.Password != "" && l.Token == "":
		return len(l.Password) <= 1024 && !strings.ContainsFunc(l.Password, func(r rune) bool { return r < 0x20 || r == 0x7f })
	}
	return false
}

// authorization is the header WHM reads: "whm root:TOKEN" for a token,
// basic authentication for the password.
func (l Login) authorization() string {
	if l.Token != "" {
		return "whm root:" + l.Token
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("root:"+l.Password))
}

// Certificate is the certificate WHM presented: its SHA-256 fingerprint
// (colon-separated upper-case hex, as browsers and openssl show it) and
// whether the system trust store verifies it for the address.
type Certificate struct {
	Fingerprint string    `json:"fingerprint"`
	Trusted     bool      `json:"trusted"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
}

// Fingerprint is a certificate's SHA-256 fingerprint as Certificate shows it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

var fingerprintPattern = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)

// ValidFingerprint reports whether s is a fingerprint as Certificate shows it.
func ValidFingerprint(s string) bool { return fingerprintPattern.MatchString(s) }

// dialer connects only to an address allowedIP accepts, whatever the name
// resolved to, so a DNS name cannot lead the login to this server's own
// loopback or a metadata service.
func dialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !allowedIP(ip) {
			return fmt.Errorf("refused address %s", host)
		}
		return nil
	}}
}

// Probe reads WHM's certificate with a TLS handshake alone: no login is
// sent. The page shows an untrusted certificate's fingerprint for the admin
// to confirm before the login goes anywhere.
func Probe(ctx context.Context, a Address) (Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout+5*time.Second)
	defer cancel()
	d := &tls.Dialer{NetDialer: dialer(), Config: &tls.Config{InsecureSkipVerify: true, ServerName: serverName(a.Host), MinVersion: tls.VersionTLS12}} // #nosec G402 -- the certificate is checked below, and only read here
	conn, err := d.DialContext(ctx, "tcp4", a.hostPort())
	if err != nil {
		return Certificate{}, unreachable(a, err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Certificate{}, &hostaccounts.MigrationError{Step: "whm_tls", Detail: "WHM at " + a.String() + " sent no certificate."}
	}
	leaf := state.PeerCertificates[0]
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: a.Host, Intermediates: pool})
	return Certificate{Fingerprint: Fingerprint(leaf.Raw), Trusted: verr == nil, Subject: clean(leaf.Subject.String(), 200), Issuer: clean(leaf.Issuer.String(), 200), NotAfter: leaf.NotAfter}, nil
}

// serverName is the TLS server name: a DNS name; an IP address sends none.
func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// Client calls one old server's WHM with root's login.
type Client struct {
	address Address
	login   Login
	pinned  string
	http    *http.Client
}

// New makes a client. pinned, when set, is the certificate fingerprint the
// admin confirmed: only that certificate is accepted. Without it the system
// trust store must verify WHM's certificate for the address.
func New(a Address, login Login, pinned string) (*Client, error) {
	if !validHost(a.Host) || a.Port < 1 || a.Port > 65535 || !login.Valid() || (pinned != "" && !ValidFingerprint(pinned)) {
		return nil, ErrAddress
	}
	config := &tls.Config{ServerName: serverName(a.Host), MinVersion: tls.VersionTLS12}
	if pinned != "" {
		config.InsecureSkipVerify = true // #nosec G402 -- VerifyConnection accepts only the pinned certificate
		config.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || Fingerprint(cs.PeerCertificates[0].Raw) != pinned {
				return errPinMismatch
			}
			return nil
		}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer().DialContext,
		TLSClientConfig:        config,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  callTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
	}
	client := &http.Client{Transport: transport, Timeout: callTimeout,
		// WHM's API answers in place; a redirect, to another host or not,
		// is not followed, so the login never goes anywhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{address: a, login: login, pinned: pinned, http: client}, nil
}

// Address is where the client calls.
func (c *Client) Address() Address { return c.address }

var errPinMismatch = errors.New("the certificate is not the one confirmed")

func unreachable(a Address, err error) error {
	return &hostaccounts.MigrationError{Step: "whm_unreachable", Detail: "Nothing answered at " + a.String() + ".", Output: clean(err.Error(), 300)}
}

// call runs one WHM API 1 function and returns its whole answer once
// metadata.result is 1.
func (c *Client) call(ctx context.Context, function string, params url.Values) ([]byte, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("api.version", "1")
	u := c.address.String() + "/json-api/" + function + "?" + params.Encode()
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, ErrAddress
	}
	req.Header.Set("Authorization", c.login.authorization())
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var unknown x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		var hostname x509.HostnameError
		var verify *tls.CertificateVerificationError
		switch {
		case errors.Is(err, errPinMismatch):
			return nil, &hostaccounts.MigrationError{Step: "whm_tls", Detail: "WHM at " + c.address.String() + " now presents another certificate than the one you confirmed."}
		case errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &hostname), errors.As(err, &verify):
			return nil, &hostaccounts.MigrationError{Step: "whm_tls", Detail: "WHM's certificate at " + c.address.String() + " is not trusted by this server.", Output: clean(err.Error(), 300)}
		}
		return nil, unreachable(c.address, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, unreachable(c.address, err)
	}
	if len(body) > maxAnswer {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "WHM's answer to " + function + " was larger than the panel reads."}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &hostaccounts.MigrationError{Step: "whm_login", Detail: "WHM at " + c.address.String() + " answered HTTP " + strconv.Itoa(resp.StatusCode) + " to " + function + ".", Output: clean(string(body), 300)}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "WHM answered " + function + " with a redirect, which the panel does not follow.", Output: clean(resp.Header.Get("Location"), 300)}
	case resp.StatusCode != http.StatusOK:
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "WHM answered HTTP " + strconv.Itoa(resp.StatusCode) + " to " + function + ".", Output: clean(string(body), 300)}
	}
	var envelope struct {
		Metadata *struct {
			Result json.RawMessage `json:"result"`
			Reason string          `json:"reason"`
		} `json:"metadata"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Metadata == nil {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "WHM's answer to " + function + " is not the JSON cPanel documents.", Output: clean(string(body), 300)}
	}
	if string(envelope.Metadata.Result) != "1" {
		reason := clean(envelope.Metadata.Reason, maxReasonText)
		// WHM answers a token or password it does not accept, or a user
		// without root's rights, with a reason rather than a status on some
		// versions.
		lower := strings.ToLower(reason)
		if strings.Contains(lower, "access denied") || strings.Contains(lower, "token denied") || strings.Contains(lower, "permission") {
			return nil, &hostaccounts.MigrationError{Step: "whm_login", Detail: "WHM refused " + function + ".", Output: reason}
		}
		return nil, &hostaccounts.MigrationError{Step: "whm_failed", Detail: "WHM could not run " + function + ".", Output: reason}
	}
	return body, nil
}

// clean keeps a printable, one-line, bounded copy of what the old server
// sent, for Technical details.
func clean(s string, max int) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\n' || c == '\t' || c == '\r':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	text := strings.Join(strings.Fields(string(b)), " ")
	if len(text) > max {
		text = text[:max]
	}
	return text
}

// Accounts lists the old server's accounts.
// WHM API 1 listaccts: https://api.docs.cpanel.net/openapi/whm/operation/listaccts/
func (c *Client) Accounts(ctx context.Context) ([]cpsource.Account, error) {
	out, err := c.call(ctx, "listaccts", url.Values{"want": {"user,domain,diskused,disklimit,suspended"}})
	if err != nil {
		return nil, err
	}
	items, err := cpsource.ParseAccounts(out)
	if err != nil {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "The old server's list of accounts could not be read (WHM API 1 listaccts)."}
	}
	return items, nil
}

// Answers fetches what the copy of one account asks of cPanel, for the
// broker, which reads each answer with the parsers it uses for whmapi1's
// and uapi's output over SSH. The account list holds that account only, and
// the PHP list only its site's virtual host, so the broker's request stays
// small.
func (c *Client) Answers(ctx context.Context, user string) (*hostaccounts.CPanelAnswers, error) {
	if !cpsource.UserPattern.MatchString(user) {
		return nil, hostaccounts.ErrInvalid
	}
	// listaccts with search=<user>, searchtype=user, searchmethod=exact.
	accounts, err := c.call(ctx, "listaccts", url.Values{"search": {user}, "searchtype": {"user"}, "searchmethod": {"exact"}, "want": {"user,domain,diskused,disklimit,suspended"}})
	if err != nil {
		return nil, err
	}
	items, err := cpsource.ParseAccounts(accounts)
	if err != nil {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "The old server's list of accounts could not be read (WHM API 1 listaccts)."}
	}
	domain := ""
	for _, a := range items {
		if a.User == user {
			domain = a.Domain
		}
	}
	answers := &hostaccounts.CPanelAnswers{Accounts: accounts}
	if !cpsource.ValidDomain(domain) {
		// The broker reports the account as missing or unusable, from the
		// list itself.
		return answers, nil
	}
	// WHM API 1 domainuserdata: https://api.docs.cpanel.net/openapi/whm/operation/domainuserdata/
	if answers.Site, err = c.call(ctx, "domainuserdata", url.Values{"domain": {domain}}); err != nil {
		return nil, err
	}
	// WHM API 1 php_get_vhost_versions: https://api.docs.cpanel.net/openapi/whm/operation/php_get_vhost_versions/
	php, err := c.call(ctx, "php_get_vhost_versions", nil)
	if err != nil {
		return nil, err
	}
	if answers.PHP, err = onlyVhost(php, domain); err != nil {
		return nil, err
	}
	if answers.Databases, err = c.uapi(ctx, user, "Mysql", "list_databases"); err != nil {
		return nil, err
	}
	if answers.DatabaseUsers, err = c.uapi(ctx, user, "Mysql", "list_users"); err != nil {
		return nil, err
	}
	return answers, nil
}

// onlyVhost keeps the domain's entry of php_get_vhost_versions' list, in
// the same shape.
func onlyVhost(out []byte, domain string) ([]byte, error) {
	var raw struct {
		Data struct {
			Versions []json.RawMessage `json:"versions"`
		} `json:"data"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "The old server's PHP versions could not be read (WHM API 1 php_get_vhost_versions)."}
	}
	kept := []json.RawMessage{}
	for _, v := range raw.Data.Versions {
		var entry struct {
			Vhost string `json:"vhost"`
		}
		if json.Unmarshal(v, &entry) == nil && entry.Vhost == domain {
			kept = append(kept, v)
		}
	}
	var shaped struct {
		Data struct {
			Versions []json.RawMessage `json:"versions"`
		} `json:"data"`
	}
	shaped.Data.Versions = kept
	return json.Marshal(shaped)
}

// uapi calls a UAPI function as the account and returns its result in the
// shape uapi --output=json prints, {"result": {...}}, for the broker's
// parser.
// WHM API 1 uapi_cpanel: https://api.docs.cpanel.net/openapi/whm/operation/uapi_cpanel/
// (the UAPI result is data.uapi, with its own status).
func (c *Client) uapi(ctx context.Context, user, module, function string) ([]byte, error) {
	out, err := c.call(ctx, "uapi_cpanel", url.Values{"cpanel.user": {user}, "cpanel.module": {module}, "cpanel.function": {function}})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Data struct {
			UAPI json.RawMessage `json:"uapi"`
		} `json:"data"`
	}
	if json.Unmarshal(out, &raw) != nil || len(raw.Data.UAPI) == 0 || raw.Data.UAPI[0] != '{' {
		return nil, &hostaccounts.MigrationError{Step: "whm_output", Detail: "The old server's answer to UAPI " + module + "::" + function + " is not the JSON cPanel documents."}
	}
	return json.Marshal(struct {
		Result json.RawMessage `json:"result"`
	}{raw.Data.UAPI})
}

// keyName names the migration's key on the old server: its file
// /root/.ssh/<name>.pub and the comment ending its authorized_keys line.
func keyName(id string) string { return cpsource.KeyComment(id) }

// keyText is the public key as WHM stores it: "ssh-ed25519 <blob>
// sifruno-migration-<id>", without the line's options.
func keyText(line, id string) (string, bool) {
	text, ok := strings.CutPrefix(line, "restrict ")
	fields := strings.Fields(text)
	if !ok || len(fields) != 3 || fields[0] != "ssh-ed25519" || fields[2] != keyName(id) || strings.ContainsAny(text, "\r\n") {
		return "", false
	}
	return text, true
}

// AuthorizeKey adds the broker's migration public key to root's
// authorized_keys on the old server with the "restrict" option (no
// forwarding, no terminal), as the key line of the SSH path does: first it
// is imported as /root/.ssh/<name>.pub, then authorized.
// WHM API 1 importsshkey: https://api.docs.cpanel.net/openapi/whm/operation/importsshkey/
// WHM API 1 authorizesshkey: https://api.docs.cpanel.net/openapi/whm/operation/authorizesshkey/
// (options: "A comma-separated list of options to include with the public
// SSH key"; when text is given, file is ignored).
func (c *Client) AuthorizeKey(ctx context.Context, line, id string) error {
	text, ok := keyText(line, id)
	if !ok {
		return hostaccounts.ErrInvalid
	}
	if _, err := c.call(ctx, "importsshkey", url.Values{"key": {text}, "name": {keyName(id)}}); err != nil {
		return err
	}
	out, err := c.call(ctx, "authorizesshkey", url.Values{"file": {keyName(id) + ".pub"}, "text": {text}, "authorize": {"1"}, "options": {"restrict"}})
	if err != nil {
		return err
	}
	var raw struct {
		Data struct {
			Authorized json.RawMessage `json:"authorized"`
		} `json:"data"`
	}
	if json.Unmarshal(out, &raw) != nil || strings.Trim(string(raw.Data.Authorized), `"`) != "1" {
		return &hostaccounts.MigrationError{Step: "whm_failed", Detail: "WHM did not confirm that the migration key is authorized for root (WHM API 1 authorizesshkey)."}
	}
	return nil
}

// RemoveKey takes the migration key out of root's authorized_keys and
// deletes its file, then reads WHM's list of root's keys to say whether it
// is gone: true only when WHM lists no authorized key with its text.
// WHM API 1 deletesshkey: https://api.docs.cpanel.net/openapi/whm/operation/deletesshkey/
// WHM API 1 listsshkeys: https://api.docs.cpanel.net/openapi/whm/operation/listsshkeys/
func (c *Client) RemoveKey(ctx context.Context, line, id string) (bool, error) {
	text, ok := keyText(line, id)
	if !ok {
		return false, hostaccounts.ErrInvalid
	}
	// Each step is tried; the list at the end decides.
	_, deauthorize := c.call(ctx, "authorizesshkey", url.Values{"file": {keyName(id) + ".pub"}, "text": {text}, "authorize": {"0"}})
	_, remove := c.call(ctx, "deletesshkey", url.Values{"file": {keyName(id) + ".pub"}, "leave_authorized": {"0"}})
	out, err := c.call(ctx, "listsshkeys", url.Values{"public": {"1"}, "private": {"0"}, "private_texts": {"0"}, "public_texts": {"1"}})
	if err != nil {
		return false, errors.Join(err, deauthorize, remove)
	}
	var raw struct {
		Data struct {
			Keys []struct {
				Authorized json.RawMessage `json:"authorized"`
				File       string          `json:"file"`
				Text       string          `json:"text"`
			} `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return false, &hostaccounts.MigrationError{Step: "whm_output", Detail: "WHM's list of root's SSH keys is not the JSON cPanel documents."}
	}
	blob := strings.Fields(text)[1]
	for _, k := range raw.Data.Keys {
		if strings.Contains(k.Text, blob) && strings.Trim(string(k.Authorized), `"`) == "1" {
			return false, errors.Join(&hostaccounts.MigrationError{Step: "whm_failed", Detail: "WHM still lists the migration key as authorized for root."}, deauthorize, remove)
		}
	}
	return true, nil
}

// String never shows the login.
func (l Login) String() string { return "[login]" }

// GoString never shows the login.
func (l Login) GoString() string { return "whmsource.Login{[hidden]}" }

// Format never shows the login, whatever the verb.
func (l Login) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[login]")) }

// MarshalJSON never writes the login.
func (l Login) MarshalJSON() ([]byte, error) { return []byte(`"[login]"`), nil }
