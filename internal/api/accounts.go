package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"sifruno/internal/hostaccounts"
	"sifruno/internal/operator"
)

type AccountCreateBody hostaccounts.CreateInput
type AccountStateBody hostaccounts.StateInput
type accountCreateInput struct{ Body AccountCreateBody }
type accountStateInput struct {
	ID   string `path:"id"`
	Body AccountStateBody
}
type AccountPlanBody hostaccounts.PlanInput
type AccountDeleteBody hostaccounts.DeleteInput
type accountPlanInput struct {
	ID   string `path:"id"`
	Body AccountPlanBody
}
type accountDeleteInput struct {
	ID   string `path:"id"`
	Body AccountDeleteBody
}
type accountOutput struct{ Body hostaccounts.Account }
type accountListBody struct {
	Items []hostaccounts.Account `json:"items"`
}
type accountListOutput struct{ Body accountListBody }
type accountCapabilityOutput struct{ Body hostaccounts.Capability }

func accountError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, hostaccounts.ErrInvalid):
		return huma.Error422UnprocessableEntity("Invalid native account request")
	case errors.Is(err, hostaccounts.ErrConflict):
		return huma.Error409Conflict("Account identity, domain or revision changed; refresh and review before retrying")
	case errors.Is(err, hostaccounts.ErrNotFound):
		return huma.Error404NotFound("Managed account not found")
	case errors.Is(err, hostaccounts.ErrRecovery):
		return huma.Error503ServiceUnavailable("Account recovery requires operator review; do not retry creation")
	default:
		return huma.Error503ServiceUnavailable("Linux account broker unavailable; refresh accounts to reconcile any interrupted request")
	}
}

func registerAccounts(a huma.API, o Options) {
	service := o.Accounts
	if service == nil {
		service = hostaccounts.NewClient("")
	}
	op := func(id, method, path string) huma.Operation {
		return huma.Operation{OperationID: id, Method: method, Path: path, MaxBodyBytes: 4096, BodyReadTimeout: 5 * time.Second, SkipValidateBody: true, SkipValidateParams: true}
	}
	huma.Register(a, op("account-capability", "GET", "/api/v1/accounts/capability"), func(ctx context.Context, _ *struct{}) (*accountCapabilityOutput, error) {
		v, err := service.Capability(ctx)
		if err != nil {
			return nil, accountError(err)
		}
		if v.Restrictions == nil {
			v.Restrictions = []string{}
		}
		return &accountCapabilityOutput{Body: v}, nil
	})
	huma.Register(a, op("list-accounts", "GET", "/api/v1/accounts"), func(ctx context.Context, _ *struct{}) (*accountListOutput, error) {
		v, err := service.List(ctx)
		if err != nil {
			return nil, accountError(err)
		}
		if v == nil {
			v = []hostaccounts.Account{}
		}
		return &accountListOutput{Body: accountListBody{Items: v}}, nil
	})
	huma.Register(a, op("create-account", "POST", "/api/v1/accounts"), func(ctx context.Context, in *accountCreateInput) (*accountOutput, error) {
		v, err := service.Create(ctx, hostaccounts.CreateInput(in.Body), siteActor(ctx))
		if err != nil {
			return nil, accountError(err)
		}
		return &accountOutput{Body: v}, nil
	})
	huma.Register(a, op("set-account-state", "POST", "/api/v1/accounts/{id}/state"), func(ctx context.Context, in *accountStateInput) (*accountOutput, error) {
		if len(in.ID) > 64 || strings.ContainsAny(in.ID, "/\\?#%") {
			return nil, accountError(hostaccounts.ErrInvalid)
		}
		v, err := service.SetState(ctx, in.ID, hostaccounts.StateInput(in.Body), siteActor(ctx))
		if err != nil {
			return nil, accountError(err)
		}
		return &accountOutput{Body: v}, nil
	})
	huma.Register(a, op("set-account-plan", "POST", "/api/v1/accounts/{id}/plan"), func(ctx context.Context, in *accountPlanInput) (*accountOutput, error) {
		if len(in.ID) > 64 || strings.ContainsAny(in.ID, "/\\?#%") {
			return nil, accountError(hostaccounts.ErrInvalid)
		}
		v, err := service.SetPlan(ctx, in.ID, hostaccounts.PlanInput(in.Body), siteActor(ctx))
		if err != nil {
			return nil, accountError(err)
		}
		return &accountOutput{Body: v}, nil
	})
	huma.Register(a, op("delete-account", "POST", "/api/v1/accounts/{id}/delete"), func(ctx context.Context, in *accountDeleteInput) (*accountOutput, error) {
		if len(in.ID) > 64 || strings.ContainsAny(in.ID, "/\\?#%") {
			return nil, accountError(hostaccounts.ErrInvalid)
		}
		v, err := service.Delete(ctx, in.ID, hostaccounts.DeleteInput(in.Body), siteActor(ctx))
		if err != nil {
			return nil, accountError(err)
		}
		return &accountOutput{Body: v}, nil
	})
}

func isAccountPath(p string) bool {
	return p == "/api/v1/accounts" || strings.HasPrefix(p, "/api/v1/accounts/")
}
func allowedAccountMutation(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if r.URL.Path == "/api/v1/accounts" {
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/accounts/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/accounts/"), "/")
	return len(parts) == 2 && parts[0] != "" && (parts[1] == "state" || parts[1] == "plan" || parts[1] == "delete")
}

func prepareAccountJSON(w http.ResponseWriter, r *http.Request) bool {
	ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		operator.WriteError(w, 415, "invalid_request", "JSON content type required")
		return false
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer http.NewResponseController(w).SetReadDeadline(time.Time{})
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	if len(raw) > 4096 {
		operator.WriteError(w, 413, "invalid_request", "Request body too large")
		return false
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		operator.WriteError(w, 400, "invalid_request", "JSON object required")
		return false
	}
	var target any
	if r.URL.Path == "/api/v1/accounts" {
		target = &hostaccounts.CreateInput{}
	} else {
		target = &hostaccounts.StateInput{}
	}
	if operator.DecodeObject(raw, target) != nil {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	// Go's JSON decoder accepts case aliases. Account requests use only the
	// canonical schema keys so aliases cannot overwrite a prior field.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
		return false
	}
	for key := range fields {
		valid := key == "reason"
		if r.URL.Path == "/api/v1/accounts" {
			valid = valid || key == "username" || key == "domain"
		} else {
			valid = valid || key == "state" || key == "expected_revision"
		}
		if !valid {
			operator.WriteError(w, 400, "invalid_request", "Invalid JSON request")
			return false
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return true
}
