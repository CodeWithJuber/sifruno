package phpmyadmin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"
)

// The sign-in script redeems a code on a Unix socket: one line of JSON,
// {"code":"..."}, and one line back, {"user":"...","password":"...",
// "expires_at":UNIX} or {"error":"refused"}. The socket's folder may be open
// to every local user; the panel answers only a peer whose user ID, read from
// the kernel (SO_PEERCRED), is phpMyAdmin's own. A tenant that somehow saw a
// code still could not redeem it, and the password only ever travels to that
// one user.

const (
	redeemWait     = 5 * time.Second
	maxRedeemLine  = 512
	maxRedeemConns = 8
)

type redeemRequest struct {
	Code string `json:"code"`
}

type redeemAnswer struct {
	User      string `json:"user,omitempty"`
	Password  string `json:"password,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ListenRedeem makes the Unix socket at path for ServeRedeem. A socket left
// by an earlier run is removed first; any other file there is an error. The
// socket is 0666: the peer check, not the mode, decides who is answered.
func ListenRedeem(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("phpmyadmin: " + path + " exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// ServeRedeem answers code redemptions on l from the user uid only, until ctx
// ends or l fails.
func (s *Service) ServeRedeem(ctx context.Context, l net.Listener, uid int) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	slots := make(chan struct{}, maxRedeemConns)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of file descriptors and the like: wait, as net/http does,
			// rather than stop answering for good.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// The peer is checked before it may take a slot, so other local
		// users cannot hold every slot and starve phpMyAdmin's redemptions.
		// Nothing is read from, or written to, anyone else.
		if peer, err := peerUID(conn); err != nil || uid < 0 || peer != uid {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				s.answer(conn)
			}()
		default:
			conn.Close()
		}
	}
}

// answer redeems one code for a peer ServeRedeem has already checked.
func (s *Service) answer(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(redeemWait))
	line, err := bufio.NewReaderSize(conn, maxRedeemLine).ReadSlice('\n')
	if err != nil {
		return
	}
	var req redeemRequest
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	answer := redeemAnswer{Error: "refused"}
	if d.Decode(&req) == nil {
		if login, err := s.Redeem(req.Code); err == nil {
			answer = redeemAnswer{User: login.User, Password: login.Password, ExpiresAt: login.Expires.Unix()}
		}
	}
	out, err := json.Marshal(answer)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(out, '\n'))
}
