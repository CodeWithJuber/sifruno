// hostweb-render is an offline fixture/helper for rendering a hostweb Bundle.
// It accepts one bounded JSON document on stdin and writes one JSON document
// on stdout. It never reads or writes host configuration, starts a daemon, or
// installs a certificate.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"sifruno/internal/hostaccounts"
	"sifruno/internal/hostweb"
)

const (
	maxInputBytes = 1 << 20
	schemaVersion = 1
)

type profileJSON struct {
	Name              string `json:"name"`
	ManagedRoot       string `json:"managedRoot"`
	ManagedHomeRoot   string `json:"managedHomeRoot"`
	FrontChroot       string `json:"frontChroot"`
	ApacheModuleRoot  string `json:"apacheModuleRoot"`
	BackendChrootRoot string `json:"backendChrootRoot"`
	RuntimeRoot       string `json:"runtimeRoot"`
	ApacheBinary      string `json:"apacheBinary"`
	FPMBinary         string `json:"fpmBinary"`
	TLSRoot           string `json:"tlsRoot"`
	CAFile            string `json:"caFile"`
	FrontendIP        string `json:"frontendIP"`
	FrontendPort      uint16 `json:"frontendPort"`
	BackendPort       uint16 `json:"backendPort"`
	FrontUID          uint32 `json:"frontUID"`
	FrontGID          uint32 `json:"frontGID"`
	ControllerUID     uint32 `json:"controllerUID"`
}

type accountJSON struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	Home       string    `json:"home"`
	PublicHTML string    `json:"public_html"`
	State      string    `json:"state"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	Revision   uint64    `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type inputJSON struct {
	SchemaVersion int           `json:"schemaVersion"`
	Compatibility bool          `json:"compatibility"`
	Activation    bool          `json:"activation"`
	Profile       profileJSON   `json:"profile"`
	Accounts      []accountJSON `json:"accounts"`
}

type fileJSON struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
	Config string `json:"config"`
}

type bundleJSON struct {
	Profile string     `json:"profile"`
	SHA256  string     `json:"sha256"`
	Files   []fileJSON `json:"files"`
}

type outputJSON struct {
	SchemaVersion int        `json:"schemaVersion"`
	Compatibility bool       `json:"compatibility"`
	Activation    bool       `json:"activation"`
	Bundle        bundleJSON `json:"bundle"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hostweb-render:", err)
		os.Exit(2)
	}
}

func run() error {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputBytes+1))
	if err != nil {
		return err
	}
	if len(input) > maxInputBytes {
		return errors.New("input exceeds 1048576 bytes")
	}
	output, err := render(input)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(output)
	return err
}

func render(input []byte) ([]byte, error) {
	if len(input) > maxInputBytes {
		return nil, errors.New("input exceeds 1048576 bytes")
	}
	if err := rejectDuplicateKeys(input); err != nil {
		return nil, err
	}
	if err := rejectUnknownKeys(input); err != nil {
		return nil, err
	}
	var in inputJSON
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, fmt.Errorf("invalid trailing JSON: %w", err)
	}
	if in.SchemaVersion != schemaVersion || in.Compatibility || in.Activation {
		return nil, errors.New("schemaVersion must be 1 with compatibility=false and activation=false")
	}
	p := hostweb.Profile{
		Name: in.Profile.Name, ManagedRoot: in.Profile.ManagedRoot, ManagedHomeRoot: in.Profile.ManagedHomeRoot,
		FrontChroot: in.Profile.FrontChroot, ApacheModuleRoot: in.Profile.ApacheModuleRoot, BackendChrootRoot: in.Profile.BackendChrootRoot, RuntimeRoot: in.Profile.RuntimeRoot,
		ApacheBinary: in.Profile.ApacheBinary, FPMBinary: in.Profile.FPMBinary, TLSRoot: in.Profile.TLSRoot, CAFile: in.Profile.CAFile,
		FrontendIP: in.Profile.FrontendIP, FrontendPort: in.Profile.FrontendPort, BackendPort: in.Profile.BackendPort, FrontUID: in.Profile.FrontUID, FrontGID: in.Profile.FrontGID, ControllerUID: in.Profile.ControllerUID,
	}
	accounts := make([]hostaccounts.Account, len(in.Accounts))
	for i, a := range in.Accounts {
		accounts[i] = hostaccounts.Account{ID: a.ID, Username: a.Username, Domain: a.Domain, Home: a.Home, PublicHTML: a.PublicHTML, State: a.State, UID: a.UID, GID: a.GID, Revision: a.Revision, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
	}
	bundle, err := hostweb.Compile(p, accounts)
	if err != nil {
		return nil, err
	}
	files := make([]fileJSON, len(bundle.Files))
	for i, f := range bundle.Files {
		files[i] = fileJSON{Path: f.Path, Mode: "0600", SHA256: f.SHA256, Config: string(f.Data)}
	}
	out := outputJSON{SchemaVersion: schemaVersion, Compatibility: false, Activation: false, Bundle: bundleJSON{Profile: bundle.Profile, SHA256: bundle.SHA256, Files: files}}
	var output bytes.Buffer
	enc := json.NewEncoder(&output)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func rejectUnknownKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return fmt.Errorf("invalid object: %w", err)
	}
	if err := checkKeys(top, map[string]bool{"schemaVersion": true, "compatibility": true, "activation": true, "profile": true, "accounts": true}); err != nil {
		return err
	}
	var profile map[string]json.RawMessage
	if raw := top["profile"]; raw != nil {
		if err := json.Unmarshal(raw, &profile); err != nil {
			return fmt.Errorf("invalid profile object: %w", err)
		}
		if err := checkKeys(profile, map[string]bool{"name": true, "managedRoot": true, "managedHomeRoot": true, "frontChroot": true, "apacheModuleRoot": true, "backendChrootRoot": true, "runtimeRoot": true, "apacheBinary": true, "fpmBinary": true, "tlsRoot": true, "caFile": true, "frontendIP": true, "frontendPort": true, "backendPort": true, "frontUID": true, "frontGID": true, "controllerUID": true}); err != nil {
			return err
		}
	}
	var accounts []json.RawMessage
	if raw := top["accounts"]; raw != nil {
		if err := json.Unmarshal(raw, &accounts); err != nil {
			return fmt.Errorf("invalid accounts array: %w", err)
		}
	}
	for i, raw := range accounts {
		var account map[string]json.RawMessage
		if err := json.Unmarshal(raw, &account); err != nil {
			return fmt.Errorf("invalid account %d: %w", i, err)
		}
		if err := checkKeys(account, map[string]bool{"id": true, "username": true, "domain": true, "home": true, "public_html": true, "state": true, "uid": true, "gid": true, "revision": true, "created_at": true, "updated_at": true}); err != nil {
			return err
		}
	}
	return nil
}

func checkKeys(got map[string]json.RawMessage, allowed map[string]bool) error {
	for key := range got {
		if !allowed[key] {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

// rejectDuplicateKeys walks all JSON objects before decoding into typed
// structs. encoding/json rejects unknown fields, but otherwise accepts a
// duplicate key and silently keeps the last value.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSON(dec); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func walkJSON(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch delim := token.(type) {
	case json.Delim:
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid object key %q", key)
				}
				seen[key] = true
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated object")
			}
		case '[':
			for dec.More() {
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return nil
}
