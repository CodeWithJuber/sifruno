//go:build linux

package phpmyadmin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// redeemOver sends one line on the socket and returns the answer line, or ""
// when the panel closed the connection without one.
func redeemOver(t *testing.T, path, line string) string {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(line)); err != nil {
		return ""
	}
	answer, _ := bufio.NewReader(conn).ReadString('\n')
	return answer
}

func TestTheSocketAnswersOnlyPhpMyAdminsUser(t *testing.T) {
	db := newFakeDatabase()
	c := &clock{now: time.Now()}
	s, _ := newTestService(t, db, c)
	path := filepath.Join(t.TempDir(), "phpmyadmin.sock")
	// A socket left by an earlier run is replaced; another file is not.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	l, err := ListenRedeem(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v %v", info.Mode(), err)
	}
	plain := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenRedeem(plain); err == nil {
		t.Fatal("a plain file was replaced by the socket")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// Served for this test's own user ID, as the panel serves phpMyAdmin's.
	go func() { done <- s.ServeRedeem(ctx, l, os.Getuid()) }()

	h, err := s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	if err != nil {
		t.Fatal(err)
	}
	code := codeOf(t, h)
	var got redeemAnswer
	if err := json.Unmarshal([]byte(redeemOver(t, path, `{"code":"`+code+`"}`+"\n")), &got); err != nil {
		t.Fatal(err)
	}
	user := db.users[got.User]
	if got.Error != "" || user.password != got.Password || got.ExpiresAt != h.LoginExpires.Unix() {
		t.Fatalf("answer %+v", got.User)
	}
	// The same code again, a made-up one, other fields, not JSON: refused.
	for _, line := range []string{`{"code":"` + code + `"}`, `{"code":"` + strings.Repeat("A", 43) + `"}`, `{"code":"` + code + `","user":"x"}`, `code=` + code} {
		if answer := redeemOver(t, path, line+"\n"); strings.TrimSpace(answer) != `{"error":"refused"}` {
			t.Fatalf("%s answered %q", line, answer)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// Another user ID is answered with nothing at all, and its code stays
	// unredeemed.
	l, err = ListenRedeem(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ServeRedeem(ctx, l, os.Getuid()+1) }()
	h, _ = s.Open(context.Background(), "alpha", []string{"alpha_wp"})
	code = codeOf(t, h)
	if answer := redeemOver(t, path, `{"code":"`+code+`"}`+"\n"); answer != "" {
		t.Fatalf("another user was answered %q", answer)
	}
	if _, err := s.Redeem(code); err != nil {
		t.Fatalf("a refused peer used up the code: %v", err)
	}

	// Other users holding connections open take no slot: phpMyAdmin's user
	// is still answered. Here every connection is "another user", so the
	// server must close each at once rather than keep it waiting in a slot.
	held := make([]net.Conn, 0, 2*maxRedeemConns)
	for i := 0; i < 2*maxRedeemConns; i++ {
		conn, err := net.DialTimeout("unix", path, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	for _, conn := range held {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil || isTimeout(err) {
			t.Fatalf("another user's connection was kept open: %d %v", n, err)
		}
		conn.Close()
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
