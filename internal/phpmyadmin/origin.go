package phpmyadmin

import (
	"net"
	"net/http"
	pathpkg "path"
	"strings"
	"time"
)

// phpMyAdmin's own origin: the panel's host names and certificate on a
// second HTTPS port, serving phpMyAdmin at the root and nothing of the
// panel's. A script on a phpMyAdmin page (phpMyAdmin needs inline scripts
// and eval, and tenants control the names and data it shows) is on another
// origin than the panel: it cannot read the panel's answers, its policy lets
// it connect and post only to its own origin, and the panel's API refuses
// its Origin. The panel's session cookie (Path=/api/v1) is never used here:
// every /api path answers 404.
//
// A browser is let in by the admission cookie, made when the sign-in
// request with a valid code succeeds and bound to that code's temporary
// user: it ends when the user expires (at most an hour), at sign-out, or
// when the panel restarts. Every other request without a valid one gets a
// page that says to open phpMyAdmin again from the panel.

// CSP is the policy for phpMyAdmin's pages: the one phpMyAdmin 5.2 sends
// itself (its scripts need inline code and eval), with connections, form
// targets, framing, plugins and the base address held to this origin.
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// requestWait bounds one phpMyAdmin request: a large export or import.
const requestWait = 10 * time.Minute

const againNext = "Go back to the website's Databases page in the panel and choose Open phpMyAdmin."

// Origin is the handler of phpMyAdmin's HTTPS listener.
type Origin struct {
	svc   *Service
	proxy http.Handler
	hosts map[string]bool
}

// NewOrigin serves phpMyAdmin through proxy for hosts, the panel's own host
// names, admitting browsers with svc's codes and admission cookies.
func NewOrigin(svc *Service, proxy http.Handler, hosts []string) *Origin {
	o := &Origin{svc: svc, proxy: proxy, hosts: map[string]bool{}}
	for _, h := range hosts {
		o.hosts[strings.ToLower(h)] = true
	}
	return o
}

func (o *Origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	host := r.Host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if r.TLS == nil || !o.hosts[host] {
		h.Set("Cache-Control", "no-store")
		http.Error(w, "This phpMyAdmin listener does not answer for that host name.", http.StatusMisdirectedRequest)
		return
	}
	p := r.URL.Path
	// The panel's API path: its cookie would be sent here, so nothing is.
	if lower := strings.ToLower(p); lower == "/api" || strings.HasPrefix(lower, "/api/") {
		WritePage(w, http.StatusNotFound, "There is no such page here.", "This address serves phpMyAdmin only; the panel is on its own address.", "Open the panel at its usual address.")
		return
	}
	clean := pathpkg.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	if !strings.HasPrefix(p, "/") || clean != p || strings.Contains(p, "\\") || strings.Contains(strings.ToLower(r.URL.RawPath), "%2f") {
		WritePage(w, http.StatusBadRequest, "That phpMyAdmin address is not valid.", "The address has parts such as .. or // that are not passed on.", againNext)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		h.Set("Allow", "GET, HEAD, POST")
		WritePage(w, http.StatusMethodNotAllowed, "phpMyAdmin does not take that kind of request.", "phpMyAdmin pages use GET and POST only.", "Use phpMyAdmin's own links and buttons.")
		return
	}
	if len(r.Header.Values("Authorization")) > 0 {
		WritePage(w, http.StatusForbidden, "API tokens cannot open phpMyAdmin.", "phpMyAdmin signs in to a website's databases, which only a person signed in to the panel may start.", againNext)
		return
	}
	// phpMyAdmin's own pages are the only senders of its changes; it also
	// checks its own token on every change.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" || (r.Method == http.MethodPost && r.Header.Get("Origin") != "https://"+r.Host) {
		WritePage(w, http.StatusForbidden, "phpMyAdmin refused this request.", "It did not come from a phpMyAdmin page on this address.", "Reload phpMyAdmin and try again.")
		return
	}
	cookie := ""
	if c, err := r.Cookie(AdmissionCookie); err == nil {
		cookie = c.Value
	}
	// Only phpMyAdmin's own cookies go further.
	keepPhpMyAdminCookies(r.Header)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(requestWait))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(requestWait))

	if p == SignonPath {
		q := r.URL.Query()
		if q.Has("signed_out") {
			// phpMyAdmin's sign-out: the script ends its session, and the
			// admission ends here.
			if cookie != "" {
				o.svc.Revoke(cookie)
			}
			clearAdmission(w)
			o.proxy.ServeHTTP(w, r)
			return
		}
		if code := q.Get("code"); code != "" && r.Method == http.MethodGet {
			user, ok := o.svc.Peek(code)
			if !ok {
				WritePage(w, http.StatusForbidden, "This phpMyAdmin link no longer works.", "Each link signs in once and only within a minute of the click, and this one was already used or has expired.", againNext)
				return
			}
			// The script redeems the code; when it answers with its
			// redirect to phpMyAdmin, the browser gets the admission cookie.
			o.proxy.ServeHTTP(&admitOnSuccess{ResponseWriter: w, svc: o.svc, user: user}, r)
			return
		}
	}
	if cookie == "" || !o.svc.Admitted(cookie) {
		clearAdmission(w)
		WritePage(w, http.StatusUnauthorized, "phpMyAdmin needs a new sign-in.", "A sign-in from the panel lasts at most one hour, and this browser has none that still works here.", againNext)
		return
	}
	o.proxy.ServeHTTP(w, r)
}

// clearAdmission removes the admission cookie from the browser.
func clearAdmission(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: AdmissionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// admitOnSuccess sets the admission cookie when the sign-in script answers
// with its redirect to phpMyAdmin, which it does only after redeeming the
// code: the cookie never comes from a code that did not work.
type admitOnSuccess struct {
	http.ResponseWriter
	svc  *Service
	user string
	done bool
}

func (a *admitOnSuccess) WriteHeader(status int) {
	if !a.done {
		a.done = true
		if status == http.StatusSeeOther && a.Header().Get("Location") == "/index.php" {
			if token, expires, err := a.svc.Admit(a.user); err == nil {
				http.SetCookie(a.ResponseWriter, &http.Cookie{Name: AdmissionCookie, Value: token, Path: "/", Expires: expires, MaxAge: max(1, int(time.Until(expires).Seconds())),
					Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			} else {
				// No cookie: the redirect then shows the page that says to
				// open phpMyAdmin again.
				a.Header().Del("Set-Cookie")
			}
		}
	}
	a.ResponseWriter.WriteHeader(status)
}

func (a *admitOnSuccess) Write(b []byte) (int, error) {
	if !a.done {
		a.WriteHeader(http.StatusOK)
	}
	return a.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection.
func (a *admitOnSuccess) Unwrap() http.ResponseWriter { return a.ResponseWriter }
