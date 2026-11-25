// Package sites manages app-owned static website files for a local operator.
// It does not provision OS accounts, PHP, DNS, TLS, mail or databases.
package sites

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound    = errors.New("website resource not found")
	ErrConflict    = errors.New("website revision or file content changed")
	ErrInvalid     = errors.New("invalid website input")
	ErrUnavailable = errors.New("website storage or recovery unavailable")
)

// ErrDomainTaken is the conflict of a domain another website already uses.
// It matches ErrConflict too, so every caller still answers 409.
var ErrDomainTaken = fmt.Errorf("%w: domain used by another website", ErrConflict)

const (
	MaxSites         = 100
	MaxFiles         = 64
	MaxFileBytes     = 2 << 20
	MaxSiteBytes     = 32 << 20
	MaxBackupBytes   = 34 << 20
	MaxBackups       = 8
	MaxBackupStorage = 128 << 20
)

type Site struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`
	PreviewHost string    `json:"preview_host"`
	State       string    `json:"state"`
	Revision    uint64    `json:"revision"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type CreateInput struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// ImportInput requires an explicit target identity. Archive accepts only the
// bounded native Sifruno ZIP v1 format; source IDs are never reused as targets.
type ImportInput struct {
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Archive []byte `json:"archive"`
}
type FileInfo struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type FileContent struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	SHA256   string `json:"sha256"`
	Revision uint64 `json:"revision"`
}
type WriteInput struct {
	Path             string `json:"path"`
	Content          string `json:"content"`
	ExpectedSHA256   string `json:"expected_sha256"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// UploadInput creates one static file; JSON content is base64 encoded.
// No overwrite flag or expected hash is accepted.
type UploadInput struct {
	Path             string `json:"path"`
	Content          []byte `json:"content"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// ReplaceInput binds byte replacement to an existing file and site revision.
type ReplaceInput struct {
	Path             string `json:"path"`
	Content          []byte `json:"content"`
	ExpectedSHA256   string `json:"expected_sha256"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type StateInput struct {
	State            string `json:"state"`
	ExpectedRevision uint64 `json:"expected_revision"`
}
type BackupInfo struct {
	ID        string    `json:"id"`
	SiteID    string    `json:"site_id"`
	CreatedAt time.Time `json:"created_at"`
	Bytes     int64     `json:"bytes"`
	Files     int       `json:"files"`
	SHA256    string    `json:"sha256"`
	Revision  uint64    `json:"revision"`
}
type RestoreInput struct {
	BackupID         string `json:"backup_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// RemoveBackupInput confirms one exact saved native ZIP at the current site revision.
type RemoveBackupInput struct {
	BackupID             string `json:"backup_id"`
	ExpectedBackupSHA256 string `json:"expected_backup_sha256"`
	ExpectedRevision     uint64 `json:"expected_revision"`
	Confirmed            bool   `json:"confirmed"`
}
