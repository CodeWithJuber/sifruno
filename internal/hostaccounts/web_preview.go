package hostaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
)

// WebPreview is compiler metadata, not installed/serving state or an apply token.
type WebPreview struct {
	Profile           string           `json:"profile"`
	ProfileSHA256     string           `json:"profile_sha256"`
	SnapshotSHA256    string           `json:"snapshot_sha256"`
	BundleSHA256      string           `json:"bundle_sha256"`
	Accounts          int              `json:"accounts"`
	ActiveAccounts    int              `json:"active_accounts"`
	SuspendedAccounts int              `json:"suspended_accounts"`
	Files             []WebPreviewFile `json:"files"`
}
type WebPreviewFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type WebPreviewService interface {
	Preview(context.Context) (WebPreview, error)
}

// WebPreviewFactory receives only the broker-owned snapshot authority and
// installs one fixed read-only operation, never arbitrary routes or commands.
type WebPreviewFactory func(SnapshotProvider) WebPreviewService

var previewHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var previewFilePath = regexp.MustCompile(`^(apache/backends|fpm)/([a-f0-9]{32})\.conf$`)

func validWebPreview(p WebPreview) bool {
	if p.Profile != "restricted-chroot-v1" || !previewHash.MatchString(p.ProfileSHA256) || !previewHash.MatchString(p.SnapshotSHA256) || !previewHash.MatchString(p.BundleSHA256) || p.Accounts < 0 || p.Accounts > MaxAccounts || p.ActiveAccounts < 0 || p.ActiveAccounts > MaxAccounts || p.SuspendedAccounts < 0 || p.SuspendedAccounts > MaxAccounts || p.ActiveAccounts+p.SuspendedAccounts != p.Accounts || len(p.Files) != 1+2*p.ActiveAccounts {
		return false
	}
	seen := map[string]bool{}
	pairs := map[string]uint8{}
	total := 0
	for _, f := range p.Files {
		if seen[f.Path] || f.Mode != 0600 || f.Bytes <= 0 || f.Bytes > 256<<10 || !previewHash.MatchString(f.SHA256) {
			return false
		}
		if f.Path != "apache/front.conf" {
			match := previewFilePath.FindStringSubmatch(f.Path)
			if match == nil {
				return false
			}
			if match[1] == "fpm" {
				pairs[match[2]] |= 2
			} else {
				pairs[match[2]] |= 1
			}
		}
		seen[f.Path] = true
		total += f.Bytes
	}
	if !seen["apache/front.conf"] || len(pairs) != p.ActiveAccounts {
		return false
	}
	for _, pair := range pairs {
		if pair != 3 {
			return false
		}
	}
	return total <= 8<<20
}
func NewWebPreviewClient(socket string) WebPreviewService { return NewClient(socket).(*client) }
func (c *client) Preview(ctx context.Context) (WebPreview, error) {
	var raw json.RawMessage
	if err := c.request(ctx, "GET", "/v1/web-preview", nil, &raw); err != nil {
		return WebPreview{}, err
	}
	var out WebPreview
	if decodeWebPreview(raw, &out) != nil || !validWebPreview(out) || ctx.Err() != nil {
		return WebPreview{}, ErrUnavailable
	}
	return out, nil
}
func decodeWebPreview(raw []byte, out *WebPreview) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if previewJSONValue(d, 0) != nil {
		return ErrUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrUnavailable
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// Exact root/file keys reject aliases and duplicate fields before Go's typed
// decoder can perform case-insensitive matching. Depth is bounded by the DTO.
func previewJSONValue(d *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrUnavailable
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return ErrUnavailable
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		var allowed map[string]bool
		switch depth {
		case 0:
			allowed = map[string]bool{"profile": true, "profile_sha256": true, "snapshot_sha256": true, "bundle_sha256": true, "accounts": true, "active_accounts": true, "suspended_accounts": true, "files": true}
		case 2:
			allowed = map[string]bool{"path": true, "mode": true, "bytes": true, "sha256": true}
		default:
			return ErrUnavailable
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || !allowed[name] {
				return ErrUnavailable
			}
			seen[name] = true
			if err = previewJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		if len(seen) != len(allowed) {
			return ErrUnavailable
		}
	case '[':
		if depth != 1 {
			return ErrUnavailable
		}
		for d.More() {
			if err = previewJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrUnavailable
	}
	_, err = d.Token()
	return err
}
