//go:build linux

package phpmyadmin

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped sign-in script against the real socket server, when a PHP CLI
// is installed: PHP's built-in web server runs a copy whose socket and
// session folder point into the test's own folder.
func TestTheSignonScriptRedeemsACodeOnce(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("no php on PATH; the dev VM proof runs the script under lsphp")
	}
	dir := t.TempDir()
	web, sessions := filepath.Join(dir, "web"), filepath.Join(dir, "sessions")
	for _, d := range []string{web, sessions} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(dir, "phpmyadmin.sock")
	raw, err := os.ReadFile("../../scripts/install/phpmyadmin/sifruno-signon.php")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("'/run/sifruno-panel/phpmyadmin.sock'", "'"+socket+"'", "'/var/lib/sifruno-phpmyadmin/sessions'", "'"+sessions+"'").Replace(string(raw))
	if script == string(raw) {
		t.Fatal("the script's socket and session paths were not found")
	}
	if err := os.WriteFile(filepath.Join(web, strings.TrimPrefix(SignonPath, "/")), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	db := newFakeDatabase()
	s, _ := newTestService(t, db, &clock{now: time.Now()})
	l, err := ListenRedeem(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ServeRedeem(ctx, l, os.Getuid()) }()

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	free.Close()
	server := exec.Command(php, "-n", "-d", "session.save_handler=files", "-S", addr, "-t", web)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}
	get := func(query string) (*http.Response, string) {
		t.Helper()
		var res *http.Response
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("GET", "http://"+addr+SignonPath+query, nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			if res, err = client.Do(req); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(body)
	}

	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	code := codeOf(t, h)
	var user, password string
	for name, u := range db.users {
		user, password = name, u.password
	}
	res, body := get("?code=" + code)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/index.php" {
		t.Fatalf("redeem: %d %q %s", res.StatusCode, res.Header.Get("Location"), body)
	}
	cookie := res.Header.Get("Set-Cookie")
	for _, want := range []string{"SifrunoPhpMyAdminSignon=", "path=/;", "secure", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("cookie %q lacks %q", cookie, want)
		}
	}
	if strings.Contains(fmt.Sprint(res.Header), password) || strings.Contains(body, password) {
		t.Fatal("the password reached the browser")
	}
	files, _ := filepath.Glob(filepath.Join(sessions, "sess_*"))
	if len(files) != 1 {
		t.Fatalf("session files %q", files)
	}
	session, _ := os.ReadFile(files[0])
	if !strings.Contains(string(session), `PMA_single_signon_user|s:31:"`+user+`"`) || !strings.Contains(string(session), `PMA_single_signon_password|s:43:"`+password+`"`) {
		t.Fatalf("the signon session does not hold the login: %s", strings.ReplaceAll(string(session), password, "[secret]"))
	}

	// The same code again: refused, and nothing new in the session folder.
	res, body = get("?code=" + code)
	if res.StatusCode != http.StatusForbidden || !strings.Contains(body, "This phpMyAdmin link no longer works.") || res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("reused code: %d %s", res.StatusCode, body)
	}
	for query, status := range map[string]int{"": 401, "?code=short": 400, "?code=" + strings.Repeat("A", 43): 403, "?signed_out=1": 200} {
		if res, body := get(query); res.StatusCode != status || !strings.Contains(body, "Next step:") {
			t.Fatalf("%q: %d %s", query, res.StatusCode, body)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(sessions, "sess_*")); len(files) != 1 {
		t.Fatalf("session files after the refusals %q", files)
	}

	// The whole way, as a browser goes: phpMyAdmin's origin and the proxy in
	// front of the script, which sets the admission cookie only after the
	// script redeemed the code.
	if err := os.WriteFile(filepath.Join(web, "index.php"), []byte("<?php echo 'phpMyAdmin index';"), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy, err := NewProxy(addr)
	if err != nil {
		t.Fatal(err)
	}
	origin := NewOrigin(s, proxy, []string{"panel.example.test"})
	h, err = s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	w := originRequest(origin, "GET", h.Path, nil)
	admitted := admission(t, w)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/index.php" || admitted == nil {
		t.Fatalf("through the origin: %d %q %v", w.Code, w.Header().Get("Location"), w.Result().Cookies())
	}
	if w := originRequest(origin, "GET", "/index.php", []*http.Cookie{admitted}); w.Code != 200 || w.Body.String() != "phpMyAdmin index" {
		t.Fatalf("admitted: %d %s", w.Code, w.Body.String())
	}
	if w := originRequest(origin, "GET", h.Path, nil); w.Code != 403 || admission(t, w) != nil {
		t.Fatalf("reused through the origin: %d", w.Code)
	}
}
