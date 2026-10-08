package sites

import (
	"errors"
	"io"
	"math"
	"strings"
	"time"
)

// RenameInput binds one relative static-file move to its saved bytes and site.
type RenameInput struct {
	Path             string `json:"path"`
	Destination      string `json:"destination"`
	ExpectedSHA256   string `json:"expected_sha256"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// RenameFile preserves bytes through the checked snapshot and signed mutation
// path. No filesystem paths or site identity can be supplied by the caller.
func (s *Store) RenameFile(id string, input RenameInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || safeFile(input.Path) != nil || safeFile(input.Destination) != nil || !hashPattern.MatchString(input.ExpectedSHA256) || input.ExpectedRevision == 0 || strings.EqualFold(input.Path, input.Destination) {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != input.ExpectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	data, err := s.snapshot(r)
	if err != nil {
		return Site{}, err
	}
	existing, found := data[input.Path]
	if !found {
		return Site{}, ErrNotFound
	}
	if sum(existing) != input.ExpectedSHA256 {
		return Site{}, ErrConflict
	}
	destination := strings.ToLower(input.Destination)
	for path := range data {
		key := strings.ToLower(path)
		if key == destination || strings.HasPrefix(key, destination+"/") || strings.HasPrefix(destination, key+"/") {
			return Site{}, ErrConflict
		}
	}
	// The catalog omits empty folders left by earlier moves. Check actual
	// directory names before creating checkpoints, including case aliases so
	// catalog paths remain identical on Windows and case-sensitive hosts.
	rt, err := s.siteRoot(id)
	if err != nil {
		return Site{}, err
	}
	defer rt.Close()
	parent := "content"
	parts := strings.Split(input.Destination, "/")
	for i, part := range parts {
		dir, err := rt.Open(parent)
		if err != nil {
			return Site{}, ErrUnavailable
		}
		entries, err := dir.ReadDir(MaxFiles*9 + 1)
		dir.Close()
		if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > MaxFiles*9 {
			return Site{}, ErrUnavailable
		}
		found := false
		for _, entry := range entries {
			if strings.EqualFold(entry.Name(), part) {
				if entry.Name() != part || i == len(parts)-1 || !entry.IsDir() {
					return Site{}, ErrConflict
				}
				found = true
			}
		}
		if !found {
			break
		}
		parent += "/" + part
	}
	delete(data, input.Path)
	data[input.Destination] = existing
	files, err := fileCatalog(data)
	if err != nil {
		return Site{}, err
	}
	next := r
	next.Files = files
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, data, "rename", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}
