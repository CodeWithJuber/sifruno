//go:build linux

package hostaccountsreview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sifruno/internal/hostaccounts"
)

const reviewGuestFlag = "SIFRUNO_HOSTACCOUNTS_REVIEW_GUEST"
const reviewControllerUID = 2000

type peerResult struct {
	Allowed bool `json:"allowed"`
	Status  int  `json:"status"`
}

// This suite runs only when root explicitly stages it in a disposable Linux
// guest. It creates new /run test directories and reads broker capability/list;
// it never sends an admissible account creation or a state change for an
// existing identity. No OS account utility is requested by these challenges.
func TestBrokerKernelPeersAndProtocol(t *testing.T) {
	if os.Getenv(reviewGuestFlag) != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicit disposable-guest root admission")
	}
	base, err := os.MkdirTemp("/run", "sfr-review-")
	if err != nil {
		t.Fatal("fresh guest test directory unavailable")
	}
	defer os.RemoveAll(base)
	if os.Chmod(base, 0755) != nil {
		t.Fatal("guest test directory permission failure")
	}
	// Guest staging may keep the original ELF under a root-private directory.
	// Copy only this known test executable into the new traversable test parent
	// so peer helpers can run after setuid without opening the staged payload.
	self, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	input, err := os.Open(self)
	if err != nil {
		t.Fatal("test executable input unavailable")
	}
	peerExecutable := filepath.Join(base, "peer-test")
	output, err := os.OpenFile(peerExecutable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		input.Close()
		t.Fatal("exclusive peer executable unavailable")
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, 64<<20+1))
	inputErr, outputErr := input.Close(), output.Close()
	if copyErr != nil || inputErr != nil || outputErr != nil || written > 64<<20 {
		t.Fatal("bounded test executable copy failed")
	}
	socketParent := filepath.Join(base, "socket")
	homes := filepath.Join(base, "homes")
	for _, path := range []string{socketParent, homes} {
		if os.Mkdir(path, 0755) != nil {
			t.Fatal("fresh broker parent unavailable")
		}
	}
	socket := filepath.Join(socketParent, "broker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- hostaccounts.RunBroker(ctx, hostaccounts.BrokerOptions{StateDir: filepath.Join(base, "state"), SocketPath: socket, HomesDir: homes, ControllerUID: reviewControllerUID})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("owned test broker returned failure on shutdown")
			}
		case <-time.After(5 * time.Second):
			t.Error("owned test broker did not stop within bound")
		}
	}()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		info, err := os.Lstat(socket)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0600 {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid == reviewControllerUID {
				ready = true
				break
			}
		}
		select {
		case <-done:
			done <- hostaccounts.ErrUnavailable
			t.Fatal("test broker failed before socket readiness")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("test broker socket readiness exceeded bound")
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("broker socket is not controller-private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != reviewControllerUID {
		t.Fatal("broker socket owner is not the exact controller UID")
	}

	t.Run("exact-controller-peer", func(t *testing.T) {
		result := runPeer(t, peerExecutable, reviewControllerUID, socket, "client", "")
		if !result.Allowed || result.Status != 200 {
			t.Fatal("configured nonroot kernel peer was not admitted")
		}
	})
	t.Run("root-peer-denied", func(t *testing.T) {
		result := rawPeer(socket, "GET", "/v1/capability", "", "", "unix", "")
		if result.Allowed || (result.Status != 0 && result.Status != 403) {
			t.Fatal("root kernel peer received an unprotected HTTP broker response")
		}
	})
	t.Run("other-peer-denied-after-permission-bypass", func(t *testing.T) {
		// Only this newly created test socket is made connectable. A raw client
		// bypasses the production client's permission check, proving server
		// peer enforcement beyond Linux filesystem DAC.
		if os.Chmod(socket, 0666) != nil {
			t.Fatal("isolated socket mode challenge failed")
		}
		defer func() {
			if os.Chmod(socket, 0600) != nil {
				t.Error("isolated socket mode restoration failed")
			}
		}()
		result := runPeer(t, peerExecutable, reviewControllerUID+1, socket, "raw", "")
		if result.Allowed || (result.Status != 0 && result.Status != 403) {
			t.Fatal("other kernel peer received an unprotected HTTP broker response")
		}
	})
	t.Run("strict-bounded-protocol", func(t *testing.T) {
		for _, test := range []struct{ name, payload string }{
			{"duplicate-actor", `{"input":{"state":"active","expected_revision":1,"reason":"review"},"actor":"reviewer","actor":"other"}`},
			{"duplicate-nested", `{"input":{"state":"active","state":"suspended","expected_revision":1,"reason":"review"},"actor":"reviewer"}`},
			{"unknown-authority", `{"input":{"state":"active","expected_revision":1,"reason":"review","utility":"/bin/false"},"actor":"reviewer"}`},
			{"invalid-utf8", "{\"input\":{\"state\":\"active\",\"expected_revision\":1,\"reason\":\"" + string([]byte{0xff}) + "\"},\"actor\":\"reviewer\"}"},
			{"byte-cap", strings.Repeat(" ", hostaccounts.MaxRequestBytes+1)},
			{"null-value", `{"input":{"state":"active","expected_revision":1,"reason":null},"actor":"reviewer"}`},
		} {
			t.Run(test.name, func(t *testing.T) {
				result := runPeer(t, peerExecutable, reviewControllerUID, socket, "invalid", test.payload)
				if result.Status != 400 {
					t.Fatal("malformed protocol did not fail before nonexistent account lookup")
				}
			})
		}
	})
	t.Run("inspection-does-not-create-accounts", func(t *testing.T) {
		result := runPeer(t, peerExecutable, reviewControllerUID, socket, "empty-list", "")
		if !result.Allowed || result.Status != 200 {
			t.Fatal("read-only challenges changed the empty account inventory")
		}
		entries, err := os.ReadDir(homes)
		if err != nil || len(entries) != 0 {
			t.Fatal("read-only challenges created a managed home")
		}
	})
}

func runPeer(t *testing.T, executable string, uid uint32, socket, mode, payload string) peerResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestBrokerPeerHelper$", "-test.timeout=4s")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", reviewGuestFlag + "=1", "SIFRUNO_REVIEW_HELPER=1", "SIFRUNO_REVIEW_SOCKET=" + socket, "SIFRUNO_REVIEW_MODE=" + mode}
	command.Stdin = strings.NewReader(payload)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &boundedOutput{buffer: &output, limit: 8192}, io.Discard
	if command.Run() != nil || ctx.Err() != nil {
		t.Fatal("bounded nonroot peer helper failed")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "BROKER_REVIEW_RESULT:") {
			var result peerResult
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "BROKER_REVIEW_RESULT:")), &result) == nil {
				return result
			}
		}
	}
	t.Fatal("peer helper omitted its sanitized result")
	return peerResult{}
}

type boundedOutput struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	count := len(p)
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buffer.Write(p)
	}
	return count, nil
}

func TestBrokerPeerHelper(t *testing.T) {
	if os.Getenv(reviewGuestFlag) != "1" || os.Getenv("SIFRUNO_REVIEW_HELPER") != "1" {
		t.Skip("peer subprocess only")
	}
	socket, mode := os.Getenv("SIFRUNO_REVIEW_SOCKET"), os.Getenv("SIFRUNO_REVIEW_MODE")
	result := peerResult{}
	switch mode {
	case "client":
		capability, err := hostaccounts.NewClient(socket).Capability(context.Background())
		if err == nil && capability.Available {
			result = peerResult{Allowed: true, Status: 200}
		}
	case "empty-list":
		items, err := hostaccounts.NewClient(socket).List(context.Background())
		if err == nil && len(items) == 0 {
			result = peerResult{Allowed: true, Status: 200}
		}
	case "raw":
		result = rawPeer(socket, "GET", "/v1/capability", "", "", "unix", "")
	case "invalid":
		payload, err := io.ReadAll(io.LimitReader(os.Stdin, hostaccounts.MaxRequestBytes+2))
		if err != nil {
			t.Fatal("fixed protocol fixture unavailable")
		}
		result = rawPeer(socket, "POST", "/v1/accounts/"+strings.Repeat("a", 32)+"/state", string(payload), "application/json", "unix", "")
	default:
		t.Fatal("unknown peer helper mode")
	}
	fmt.Printf("BROKER_REVIEW_RESULT:%s\n", mustResult(result))
}

func mustResult(result peerResult) []byte { encoded, _ := json.Marshal(result); return encoded }

func rawPeer(socket, method, path, body, contentType, host, origin string) peerResult {
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return peerResult{}
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		return peerResult{}
	}
	request.Host = host
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if request.Write(connection) != nil {
		return peerResult{}
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return peerResult{}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
	return peerResult{Allowed: response.StatusCode == 200, Status: response.StatusCode}
}
