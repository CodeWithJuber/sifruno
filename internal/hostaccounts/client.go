package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type client struct {
	socket     string
	http       *http.Client
	configured bool
}

func NewClient(socket string) Service {
	c := &client{socket: socket, configured: runtime.GOOS == "linux" && validSocketName(socket)}
	c.http = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return connectBroker(ctx, c.socket) }}}
	return c
}
func validSocketName(s string) bool {
	return s != "" && len(s) <= 100 && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func (c *client) Capability(ctx context.Context) (Capability, error) {
	if ctx == nil {
		return Capability{}, ErrInvalid
	}
	if !c.configured {
		return unavailable("linux_broker_not_configured"), nil
	}
	var out Capability
	err := c.request(ctx, "GET", "/v1/capability", nil, &out)
	if err != nil {
		return unavailable("linux_broker_unavailable"), nil
	}
	return out, nil
}
func (c *client) List(ctx context.Context) ([]Account, error) {
	var out struct {
		Items []Account `json:"items"`
	}
	err := c.requestBounded(ctx, "GET", "/v1/accounts", nil, &out, maxListResponseBytes)
	if err != nil {
		return nil, err
	}
	if out.Items == nil {
		out.Items = []Account{}
	}
	if len(out.Items) > MaxAccounts {
		return nil, ErrUnavailable
	}
	return out.Items, nil
}
func (c *client) Create(ctx context.Context, in CreateInput, actor string) (Account, error) {
	if !validCreate(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	err := c.request(ctx, "POST", "/v1/accounts", struct {
		Input CreateInput `json:"input"`
		Actor string      `json:"actor"`
	}{in, actor}, &out)
	return out, err
}
func (c *client) SetState(ctx context.Context, id string, in StateInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validState(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/state", struct {
		Input StateInput `json:"input"`
		Actor string     `json:"actor"`
	}{in, actor}, &out)
	return out, err
}
func (c *client) SetPlan(ctx context.Context, id string, in PlanInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validPlan(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/plan", struct {
		Input PlanInput `json:"input"`
		Actor string    `json:"actor"`
	}{in, actor}, &out)
	return out, err
}
func (c *client) Delete(ctx context.Context, id string, in DeleteInput, actor string) (Account, error) {
	if !idPattern.MatchString(id) || !validDelete(in, actor) {
		return Account{}, ErrInvalid
	}
	var out Account
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/delete", struct {
		Input DeleteInput `json:"input"`
		Actor string      `json:"actor"`
	}{in, actor}, &out)
	return out, err
}

// maxResponseBytes bounds every broker answer except the account list, whose
// size grows with the inventory: one account is well under 8 KiB of JSON.
const maxResponseBytes = 256 << 10
const maxListResponseBytes = MaxAccounts * (8 << 10)

func (c *client) SSHKeys(ctx context.Context, id string) (SSHKeysResult, error) {
	if !idPattern.MatchString(id) {
		return SSHKeysResult{}, ErrInvalid
	}
	var out SSHKeysResult
	err := c.request(ctx, "GET", "/v1/accounts/"+id+"/ssh-keys", nil, &out)
	return out, err
}

func (c *client) SetSSHKeys(ctx context.Context, id string, in SSHKeysInput, actor string) (SSHKeysResult, error) {
	if _, _, ok := normalizeSSHKeys(in.Keys); !ok || !idPattern.MatchString(id) || in.ExpectedRevision == 0 || !validText(in.Reason, 500) || !validText(actor, 120) {
		return SSHKeysResult{}, ErrInvalid
	}
	if in.Keys == nil {
		in.Keys = []string{}
	}
	var out SSHKeysResult
	err := c.request(ctx, "POST", "/v1/accounts/"+id+"/ssh-keys", struct {
		Input SSHKeysInput `json:"input"`
		Actor string       `json:"actor"`
	}{in, actor}, &out)
	return out, err
}

func (c *client) request(ctx context.Context, method, path string, input, output any) error {
	return c.requestBounded(ctx, method, path, input, output, maxResponseBytes)
}

func (c *client) requestBounded(ctx context.Context, method, path string, input, output any, limit int64) error {
	if ctx == nil {
		return ErrInvalid
	}
	if !c.configured {
		return ErrUnavailable
	}
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil || len(b) > MaxRequestBytes {
			return ErrInvalid
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, body)
	if err != nil {
		return ErrInvalid
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return ErrUnavailable
	}
	if response.StatusCode != 200 {
		var failure struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &failure) != nil {
			return ErrUnavailable
		}
		switch failure.Error {
		case "invalid":
			return ErrInvalid
		case "conflict":
			return ErrConflict
		case "not_found":
			return ErrNotFound
		case "recovery":
			return ErrRecovery
		default:
			return ErrUnavailable
		}
	}
	if json.Unmarshal(b, output) != nil {
		return ErrUnavailable
	}
	return nil
}
