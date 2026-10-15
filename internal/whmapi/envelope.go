package whmapi

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Envelope shapes below mirror the licensed cPanel & WHM 11.138.0.11
// reference captures in docs/reference. Field order, types and reason
// strings are compatibility-relevant: unchanged clients pattern-match them.

// outputBlock carries metadata.output; Raw is the provisioning step log on
// success and null on failure (observed).
type outputBlock struct {
	Raw any `json:"raw"`
}

// metadata is the WHM API 1 metadata block. Version is `any` because the
// reference emits number 1 on success/failure but string "1" in the
// unknown-app error (observed quirk, lifecycle-capture doc §1).
type metadata struct {
	Version any          `json:"version"`
	Result  int          `json:"result"`
	Command string       `json:"command"`
	Reason  string       `json:"reason"`
	Output  *outputBlock `json:"output,omitempty"`
}

// envelope is the WHM API 1 response wrapper. Data is omitted for zero-match
// reads (observed: filtered listaccts success carries no data key).
type envelope struct {
	Data     any      `json:"data,omitempty"`
	Metadata metadata `json:"metadata"`
}

// legacyDeny is the unauthenticated response shape: HTTP 403 with the legacy
// cpanelresult envelope (observed on the reference, differs from the
// authenticated envelope family).
type legacyDenyResult struct {
	APIVersion string `json:"apiversion"`
	Error      string `json:"error"`
	Data       struct {
		Reason string `json:"reason"`
		Result string `json:"result"`
	} `json:"data"`
	Type string `json:"type"`
}

func writeWireHeaders(w http.ResponseWriter) {
	// Observed reference response headers (:2087, 2026-10-15).
	w.Header().Set("Content-Type", `application/json; charset="utf-8"`)
	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Add("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "close")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	writeWireHeaders(w)
	raw, err := json.Marshal(v)
	if err != nil {
		// Marshal failures are programmer error for these static shapes.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// writeSuccess emits `result:1`, `reason:"OK"`; data may be nil (zero-match
// reads) and rawLog carries the ordered step log for mutation calls.
func writeSuccess(w http.ResponseWriter, command string, data any, rawLog string) {
	env := envelope{Data: data, Metadata: metadata{Version: 1, Result: 1, Command: command, Reason: "OK"}}
	if rawLog != "" {
		env.Metadata.Output = &outputBlock{Raw: rawLog}
	}
	writeJSON(w, http.StatusOK, env)
}

// writeError emits `result:0` with output.raw explicitly null (observed).
func writeError(w http.ResponseWriter, command, reason string) {
	writeJSON(w, http.StatusOK, envelope{
		Metadata: metadata{Version: 1, Result: 0, Command: command, Reason: reason, Output: &outputBlock{Raw: nil}},
	})
}

// writeUnknownApp emits the exact observed unknown-function error. The
// reference wraps the function name in U+201C/U+201D quotes and serializes
// metadata.version as the string "1" only here.
func writeUnknownApp(w http.ResponseWriter, fn string) {
	writeJSON(w, http.StatusOK, envelope{
		Metadata: metadata{
			Version: "1",
			Result:  0,
			Command: fn,
			Reason:  "Unknown app (“" + fn + "”) requested for this version (1) of the API.",
		},
	})
}

// writeAccessDenied emits HTTP 403 with the legacy cpanelresult envelope
// (observed for unauthenticated requests).
func writeAccessDenied(w http.ResponseWriter) {
	r := legacyDenyResult{APIVersion: "2", Error: "Access denied", Type: "text"}
	r.Data.Reason = "Access denied"
	r.Data.Result = "0"
	writeJSON(w, http.StatusForbidden, struct {
		CpanelResult legacyDenyResult `json:"cpanelresult"`
	}{CpanelResult: r})
}
