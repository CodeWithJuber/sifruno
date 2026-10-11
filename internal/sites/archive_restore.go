package sites

import (
	"errors"
	"io"
	"strings"
	"time"
)

// Uploaded archives are stateless: preview creates no backup or staging record.
type ArchiveRestoreInput struct {
	Archive               []byte
	ExpectedRevision      uint64
	ExpectedArchiveSHA256 string
}

type ArchiveRestorePreview struct {
	SiteID          string               `json:"site_id"`
	CurrentRevision uint64               `json:"current_revision"`
	ArchiveSHA256   string               `json:"archive_sha256"`
	BackupID        string               `json:"backup_id"`
	BackupRevision  uint64               `json:"backup_revision"`
	Files           []RestorePreviewFile `json:"files"`
	Counts          RestorePreviewCounts `json:"counts"`
}

// Both preview and confirmation verify the current files under the store lock.
// Archive identity belongs to its source; only its files replace the target.
func (s *Store) archiveRestoreLocked(id string, input ArchiveRestoreInput) (record, map[string][]byte, ArchiveRestorePreview, error) {
	var empty ArchiveRestorePreview
	if !identifier.MatchString(id) || input.ExpectedRevision == 0 || input.ExpectedRevision > maxScheduleRevision {
		return record{}, nil, empty, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return r, nil, empty, err
	}
	if r.Site.Revision != input.ExpectedRevision {
		return r, nil, empty, ErrConflict
	}
	if _, err = s.snapshot(r); err != nil {
		return r, nil, empty, err
	}
	data, manifest, err := parseNativeArchive(input.Archive)
	if err != nil || manifest.Revision > maxScheduleRevision {
		return r, nil, empty, ErrInvalid
	}
	after, err := fileCatalog(data)
	if err != nil {
		return r, nil, empty, err
	}
	files, counts, err := restoreDiff(r.Files, after)
	if err != nil {
		return r, nil, empty, err
	}
	if err := s.validateRestoreDestinations(id, after); err != nil {
		return r, nil, empty, err
	}
	return r, data, ArchiveRestorePreview{SiteID: id, CurrentRevision: r.Site.Revision, ArchiveSHA256: sum(input.Archive), BackupID: manifest.BackupID, BackupRevision: manifest.Revision, Files: files, Counts: counts}, nil
}

func (s *Store) PreviewArchiveRestore(id string, input ArchiveRestoreInput) (ArchiveRestorePreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, preview, err := s.archiveRestoreLocked(id, input)
	return preview, err
}

func (s *Store) RestoreArchive(id string, input ArchiveRestoreInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !hashPattern.MatchString(input.ExpectedArchiveSHA256) {
		return Site{}, ErrInvalid
	}
	if sum(input.Archive) != input.ExpectedArchiveSHA256 {
		return Site{}, ErrConflict
	}
	r, data, _, err := s.archiveRestoreLocked(id, input)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision >= maxScheduleRevision {
		return Site{}, ErrConflict
	}
	next := r
	next.Files, err = fileCatalog(data)
	if err != nil {
		return Site{}, err
	}
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, data, "restore", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}

// validateRestoreDestinations admits the complete resulting catalog before any
// pending marker, directory creation or checkpoint. Caller holds the store lock
// and has verified the current physical snapshot.
func (s *Store) validateRestoreDestinations(id string, after []FileInfo) error {
	// Refuse file/directory transitions and physical case aliases before the
	// signed change path can create directories or pending checkpoints.
	rt, err := s.siteRoot(id)
	if err != nil {
		return err
	}
	defer rt.Close()
	directories := map[string]bool{}
	var walk func(string) error
	walk = func(parent string) error {
		dir, err := rt.Open("content/" + parent)
		if err != nil {
			return ErrUnavailable
		}
		entries, err := dir.ReadDir(MaxFiles*9 + 1)
		dir.Close()
		if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > MaxFiles*9 {
			return ErrUnavailable
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if parent != "." {
				name = parent + "/" + name
			}
			directories[name] = true
			if len(directories) > MaxFiles*9 {
				return ErrUnavailable
			}
			if err := walk(name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return err
	}
	for _, file := range after {
		parent := "content"
		parts := strings.Split(file.Path, "/")
		for i, part := range parts {
			dir, err := rt.Open(parent)
			if err != nil {
				return ErrUnavailable
			}
			entries, err := dir.ReadDir(MaxFiles*9 + 1)
			dir.Close()
			if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > MaxFiles*9 {
				return ErrUnavailable
			}
			found := false
			for _, entry := range entries {
				if strings.EqualFold(entry.Name(), part) {
					if entry.Name() != part || (i == len(parts)-1 && !entry.Type().IsRegular()) || (i < len(parts)-1 && !entry.IsDir()) {
						return ErrConflict
					}
					found = true
				}
			}
			if !found {
				break
			}
			parent += "/" + part
		}
		for i := 1; i < len(parts); i++ {
			name := strings.Join(parts[:i], "/")
			for existing := range directories {
				if strings.EqualFold(existing, name) && existing != name {
					return ErrInvalid
				}
			}
			directories[name] = true
		}
	}
	if len(directories)+len(after) > MaxFiles*9 {
		return ErrInvalid
	}
	return nil
}
