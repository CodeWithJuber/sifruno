package phpmyadmin

import (
	"errors"
	"html"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The panel serves phpMyAdmin under BasePath by passing each request to
// OpenLiteSpeed's loopback listener. The request loses what proves who the
// person is to the panel (its session cookie, API tokens, the CSRF header)
// and any forwarding header a client sent; the panel adds X-Forwarded-Proto
// itself, which phpMyAdmin reads to mark its cookies Secure. The answer may
// set cookies only for BasePath and never the panel's own, and loses headers
// that would act beyond phpMyAdmin's pages: security policies (the panel sets
// phpMyAdmin's), CORS, HSTS and Clear-Site-Data.

// PanelCookie is the panel's session cookie (internal/operator), which never
// reaches phpMyAdmin and which phpMyAdmin may never set.
const PanelCookie = "sifruno_operator"

// MaxRequestBytes bounds a request body, an import's upload included.
const MaxRequestBytes = 64 << 20

// strippedRequest are the request headers phpMyAdmin never sees.
var strippedRequest = []string{
	"Authorization", "Proxy-Authorization", "X-Csrf-Token",
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Real-Ip",
	// PHP would expose it as HTTP_PROXY (httpoxy).
	"Proxy",
}

// strippedResponse are the answer headers the panel never passes on.
var strippedResponse = []string{
	"Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Security-Policy", "X-Webkit-Csp",
	"Referrer-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "Clear-Site-Data",
	"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Expose-Headers",
	"Set-Cookie2", "Server", "X-Powered-By",
}

// Proxy passes the requests the panel admitted to phpMyAdmin's listener.
type Proxy struct {
	rp *httputil.ReverseProxy
}

// CheckUpstream reports whether address is a loopback IP and a port, the
// only place the proxy may send requests.
func CheckUpstream(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("phpmyadmin: the listener address must be IP:PORT")
	}
	ip := net.ParseIP(host)
	n, perr := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || perr != nil || n < 1 || n > 65535 {
		return errors.New("phpmyadmin: the listener address must be a loopback IP and a port, such as 127.0.0.1:8090")
	}
	return nil
}

// NewProxy is the proxy to OpenLiteSpeed's phpMyAdmin listener at upstream,
// a loopback IP and port.
func NewProxy(upstream string) (*Proxy, error) {
	if err := CheckUpstream(upstream); err != nil {
		return nil, err
	}
	target := &url.URL{Scheme: "http", Host: upstream}
	p := &Proxy{}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			stripRequest(pr.Out.Header, pr.In.TLS != nil)
		},
		// No proxy from the environment: the request goes to the listener.
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConns:          8,
			IdleConnTimeout:       60 * time.Second,
			ResponseHeaderTimeout: 10 * time.Minute,
		},
		ModifyResponse: func(res *http.Response) error {
			filterResponse(res.Header, res.Request != nil && res.Request.Header.Get("X-Forwarded-Proto") == "https", upstream)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				WritePage(w, http.StatusRequestEntityTooLarge, "The upload is too large.", "phpMyAdmin takes at most 64 MB in one request.", "Import a smaller file, or split the SQL file into parts and import them one at a time.")
				return
			}
			WritePage(w, http.StatusBadGateway, "phpMyAdmin did not answer.", "The panel could not reach phpMyAdmin on this server's OpenLiteSpeed listener ("+upstream+").", "Check that OpenLiteSpeed is running (systemctl status lsws), then reload this page.")
		},
	}
	return p, nil
}

// stripRequest removes the panel's credentials and every forwarding header,
// then marks a request that reached the panel over HTTPS.
func stripRequest(h http.Header, https bool) {
	for _, name := range strippedRequest {
		h.Del(name)
	}
	cookies := []string{}
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part == "" || strings.TrimSpace(name) == PanelCookie {
				continue
			}
			cookies = append(cookies, part)
		}
	}
	h.Del("Cookie")
	if len(cookies) > 0 {
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
	if https {
		h.Set("X-Forwarded-Proto", "https")
	}
}

// filterResponse keeps only cookies for BasePath that are not the panel's,
// drops the headers in strippedResponse, and turns a redirect to the
// listener's own address into a path on the panel.
func filterResponse(h http.Header, https bool, upstream string) {
	lines := h.Values("Set-Cookie")
	h.Del("Set-Cookie")
	for _, line := range lines {
		if c := allowedCookie(line, https); c != "" {
			h.Add("Set-Cookie", c)
		}
	}
	for _, name := range strippedResponse {
		h.Del(name)
	}
	if loc := h.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Host != "" && strings.EqualFold(u.Host, upstream) {
			u.Scheme, u.Host, u.User = "", "", nil
			h.Set("Location", u.String())
		}
	}
}

// allowedCookie is a Set-Cookie line as the browser may get it, or "" when
// it must not be set: unreadable, the panel's cookie, or a prefixed name
// whose rules a path below BasePath would break. The cookie's path is held
// to BasePath and its domain to this host.
func allowedCookie(line string, https bool) string {
	c, err := http.ParseSetCookie(line)
	if err != nil || c.Name == PanelCookie || strings.HasPrefix(c.Name, "__Host-") || strings.HasPrefix(c.Name, "__Secure-") {
		return ""
	}
	if !strings.HasPrefix(c.Path, BasePath) {
		c.Path = BasePath
	}
	c.Domain = ""
	if https {
		c.Secure = true
	}
	return c.String()
}

// ServeHTTP passes a request the panel has admitted to phpMyAdmin. The
// caller checks the session, the method and the path.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxRequestBytes {
		WritePage(w, http.StatusRequestEntityTooLarge, "The upload is too large.", "phpMyAdmin takes at most 64 MB in one request.", "Import a smaller file, or split the SQL file into parts and import them one at a time.")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	}
	p.rp.ServeHTTP(w, r)
}

// WritePage answers with a small page that says what happened, why, and what
// to do next. The texts are the panel's own; they are escaped all the same.
func WritePage(w http.ResponseWriter, status int, what, why, next string) {
	h := w.Header()
	h.Del("Set-Cookie")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" +
		html.EscapeString(what) + "</title></head>\n<body><main><h1>" + html.EscapeString(what) + "</h1><p>" + html.EscapeString(why) + "</p><p><strong>Next step:</strong> " +
		html.EscapeString(next) + "</p></main></body></html>\n"))
}
