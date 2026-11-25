package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
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
type AccountAbandonCreateBody hostaccounts.AbandonCreateInput
type accountAbandonCreateInput struct {
	ID   string `path:"id"`
	Body AccountAbandonCreateBody
}
type AccountFinishDeleteBody hostaccounts.FinishDeleteInput
type accountFinishDeleteInput struct {
	ID   string `path:"id"`
	Body AccountFinishDeleteBody
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
	case errors.Is(err, hostaccounts.ErrWebRejected):
		return huma.Error422UnprocessableEntity("The web server's configuration test failed with this change, so the server kept its old configuration and the account is unchanged")
	case errors.Is(err, hostaccounts.ErrRecovery):
		return huma.Error503ServiceUnavailable("Account recovery requires operator review; do not retry creation")
	default:
		return huma.Error503ServiceUnavailable("Linux account broker unavailable; refresh accounts to reconcile any interrupted request")
	}
}

// abandonRefusals say why the broker removed nothing, by the reason it
// answers, and what the admin can do.
var abandonRefusals = map[string]string{
	hostaccounts.AbandonNoCreate:     "Nothing was removed: this hosting account has no unfinished create to abandon.",
	hostaccounts.AbandonMarker:       "Nothing was removed: the broker's ownership marker for this account is missing or different, so it cannot prove the leftovers are this create's. Check the server by hand.",
	hostaccounts.AbandonUser:         "Nothing was removed: a Linux user with this account's name or ID is not the one this create made. Check the server by hand.",
	hostaccounts.AbandonGroup:        "Nothing was removed: a Linux group with this account's name or ID is not the one this create made. Check the server by hand.",
	hostaccounts.AbandonHome:         "Nothing was removed: the home folder is not the one this create made. Check the server by hand.",
	hostaccounts.AbandonHomeNotEmpty: "Nothing was removed: the home folder holds files this create did not make. Move them away, then try again.",
	hostaccounts.AbandonMailSpool:    "Nothing was removed: the mail file with this account's name is not this account's. Check the server by hand.",
	hostaccounts.AbandonProcesses:    "Nothing was removed: the account's processes kept running. Try again in a moment.",
}

// finishRefusals say why the broker removed nothing when asked to finish a
// delete, by the reason it answers, and what the admin can do.
var finishRefusals = map[string]string{
	hostaccounts.DeleteNoUnfinished: "Nothing was removed: this hosting account has no unfinished delete to finish.",
	hostaccounts.DeleteMarker:       "Nothing was removed: the broker's ownership marker for this account is missing or different, so it cannot prove what is left is this account's. Check the server by hand.",
	hostaccounts.DeleteUser:         "Nothing was removed: a Linux user with this account's name or ID is not this account's. Check the server by hand.",
	hostaccounts.DeleteGroup:        "Nothing was removed: a Linux group with this account's name or ID is not this account's. Check the server by hand.",
	hostaccounts.DeleteHome:         "Nothing was removed: the home folder is not the one this account was given. Check the server by hand.",
	hostaccounts.DeleteTrash:        "Nothing was removed: the folder deleted homes go to (.sifruno-trash in the homes folder) is not the broker's own. Make it a folder of root's with mode 0700 on the same disk, then try again.",
	hostaccounts.DeleteProcesses:    "Nothing was removed: the account's processes kept running. Try again in a moment.",
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
		forgetWebsite(o, in.ID)
		return &accountOutput{Body: v}, nil
	})
	// An admin's way out of a create that no start can finish: the broker
	// removes only what the create made and ends it, so the other accounts
	// can change again. Admins only, never an API token (tokenArea).
	huma.Register(a, op("abandon-account-create", "POST", "/api/v1/accounts/{id}/abandon-create"), func(ctx context.Context, in *accountAbandonCreateInput) (*accountOutput, error) {
		if len(in.ID) > 64 || strings.ContainsAny(in.ID, "/\\?#%") {
			return nil, accountError(hostaccounts.ErrInvalid)
		}
		recovery, ok := service.(hostaccounts.CreateRecoveryService)
		if !ok {
			return nil, accountError(hostaccounts.ErrUnavailable)
		}
		v, err := recovery.AbandonCreate(ctx, in.ID, hostaccounts.AbandonCreateInput(in.Body), siteActor(ctx))
		var refused *hostaccounts.AbandonRefusedError
		if errors.As(err, &refused) {
			message, ok := abandonRefusals[refused.Reason]
			if !ok {
				message = "Nothing was removed: the broker could not prove the leftovers are this create's."
			}
			return nil, huma.Error409Conflict(message)
		}
		if err != nil {
			return nil, accountError(err)
		}
		forgetWebsite(o, in.ID)
		return &accountOutput{Body: v}, nil
	})
	// An admin's way out of a delete that no start can finish: the broker
	// removes only what is provably the account's and ends the delete, so
	// the other accounts can change again. Admins only, never an API token
	// (tokenArea).
	huma.Register(a, op("finish-account-delete", "POST", "/api/v1/accounts/{id}/finish-delete"), func(ctx context.Context, in *accountFinishDeleteInput) (*accountOutput, error) {
		if len(in.ID) > 64 || strings.ContainsAny(in.ID, "/\\?#%") {
			return nil, accountError(hostaccounts.ErrInvalid)
		}
		recovery, ok := service.(hostaccounts.DeleteRecoveryService)
		if !ok {
			return nil, accountError(hostaccounts.ErrUnavailable)
		}
		v, err := recovery.FinishDelete(ctx, in.ID, hostaccounts.FinishDeleteInput(in.Body), siteActor(ctx))
		var refused *hostaccounts.DeleteRefusedError
		if errors.As(err, &refused) {
			message, ok := finishRefusals[refused.Reason]
			if !ok {
				message = "Nothing was removed: the broker could not prove what is left is this account's."
			}
			return nil, huma.Error409Conflict(message)
		}
		if err != nil {
			return nil, accountError(err)
		}
		forgetWebsite(o, in.ID)
		return &accountOutput{Body: v}, nil
	})
}

// forgetWebsite takes a deleted hosting account off every customer's
// websites. The delete already happened, so a failure to save is logged and
// the answer stays a success: the ID then gives nothing, because hosting
// account IDs are random and never reused.
func forgetWebsite(o Options, accountID string) {
	if o.Operator == nil {
		return
	}
	if err := o.Operator.ForgetWebsite(accountID); err != nil {
		log.Printf("customer logins: website %s was deleted but could not be taken off the customers' lists: %v", accountID, err)
	}
}

// missingWebsites is the operator's check that the websites given to a
// customer are hosting accounts the broker has.
func missingWebsites(service hostaccounts.Service) operator.WebsiteCheck {
	return func(ctx context.Context, ids []string) ([]string, error) {
		accounts, err := service.List(ctx)
		if err != nil {
			return nil, err
		}
		known := make(map[string]bool, len(accounts))
		for _, a := range accounts {
			known[a.ID] = true
		}
		var missing []string
		for _, id := range ids {
			if !known[id] {
				missing = append(missing, id)
			}
		}
		return missing, nil
	}
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
	return len(parts) == 2 && parts[0] != "" && (parts[1] == "state" || parts[1] == "plan" || parts[1] == "delete" || parts[1] == "abandon-create" || parts[1] == "finish-delete")
}

// isAbandonCreatePath is an admin's abandon of an unfinished create.
func isAbandonCreatePath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/accounts/")
	parts := strings.Split(rest, "/")
	return ok && len(parts) == 2 && parts[0] != "" && parts[1] == "abandon-create"
}

// isFinishDeletePath is an admin's finish of an unfinished delete.
func isFinishDeletePath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/accounts/")
	parts := strings.Split(rest, "/")
	return ok && len(parts) == 2 && parts[0] != "" && parts[1] == "finish-delete"
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
	switch {
	case r.URL.Path == "/api/v1/accounts":
		target = &hostaccounts.CreateInput{}
	case isAbandonCreatePath(r.URL.Path):
		target = &hostaccounts.AbandonCreateInput{}
	case isFinishDeletePath(r.URL.Path):
		target = &hostaccounts.FinishDeleteInput{}
	default:
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
		switch {
		case r.URL.Path == "/api/v1/accounts":
			valid = valid || key == "username" || key == "domain"
		case isAbandonCreatePath(r.URL.Path), isFinishDeletePath(r.URL.Path):
		default:
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
