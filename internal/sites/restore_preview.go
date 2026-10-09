package sites

import (
	"sort"
	"strings"
)

// RestorePreview contains only verified native static-site file metadata.
// Added/removed describe the result of restoring the selected archive.
type RestorePreview struct {
	SiteID          string               `json:"site_id"`
	CurrentRevision uint64               `json:"current_revision"`
	BackupID        string               `json:"backup_id"`
	BackupSHA256    string               `json:"backup_sha256"`
	BackupRevision  uint64               `json:"backup_revision"`
	Files           []RestorePreviewFile `json:"files"`
	Counts          RestorePreviewCounts `json:"counts"`
}

type RestorePreviewFile struct {
	Path   string    `json:"path"`
	Kind   string    `json:"kind"`
	Before *FileInfo `json:"before"`
	After  *FileInfo `json:"after"`
}

type RestorePreviewCounts struct {
	Added     int `json:"added"`
	Modified  int `json:"modified"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

// PreviewRestore holds the same store lock as Restore, verifies both current
// content and the archive, and never writes state, files, schedules or trail.
func (s *Store) PreviewRestore(id string, input RestoreInput) (RestorePreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !identifier.MatchString(id) || !identifier.MatchString(input.BackupID) || input.ExpectedRevision == 0 || input.ExpectedRevision > maxScheduleRevision {
		return RestorePreview{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return RestorePreview{}, err
	}
	if r.Site.Revision != input.ExpectedRevision {
		return RestorePreview{}, ErrConflict
	}
	var found *BackupInfo
	for i := range r.Backups {
		if r.Backups[i].ID == input.BackupID {
			found = &r.Backups[i]
			break
		}
	}
	if found == nil {
		return RestorePreview{}, ErrNotFound
	}
	if found.Revision > maxScheduleRevision {
		return RestorePreview{}, ErrUnavailable
	}
	if _, err = s.snapshot(r); err != nil {
		return RestorePreview{}, err
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return RestorePreview{}, err
	}
	raw, err := readRoot(rt, "backups/"+found.ID+".zip", MaxBackupBytes)
	rt.Close()
	if err != nil {
		return RestorePreview{}, ErrUnavailable
	}
	data, err := parseArchive(raw, *found)
	if err != nil {
		// Invalid bytes in an already stored backup are storage corruption,
		// rather than invalid operator input.
		return RestorePreview{}, ErrUnavailable
	}
	after, err := fileCatalog(data)
	if err != nil {
		return RestorePreview{}, ErrUnavailable
	}
	result := RestorePreview{SiteID: id, CurrentRevision: r.Site.Revision, BackupID: found.ID, BackupSHA256: found.SHA256, BackupRevision: found.Revision}
	result.Files, result.Counts, err = restoreDiff(r.Files, after)
	if err != nil {
		return RestorePreview{}, ErrUnavailable
	}
	return result, err
}

func restoreDiff(before, after []FileInfo) ([]RestorePreviewFile, RestorePreviewCounts, error) {
	result := RestorePreview{Files: []RestorePreviewFile{}}
	files := map[string]RestorePreviewFile{}
	aliases := map[string]string{}
	for _, f := range before {
		files[f.Path] = RestorePreviewFile{Path: f.Path, Before: &f}
		aliases[strings.ToLower(f.Path)] = f.Path
	}
	for _, f := range after {
		if existing, ok := aliases[strings.ToLower(f.Path)]; ok && existing != f.Path {
			return nil, RestorePreviewCounts{}, ErrInvalid
		}
		entry := files[f.Path]
		entry.Path, entry.After = f.Path, &f
		files[f.Path] = entry
	}
	if len(files) > 2*MaxFiles {
		return nil, RestorePreviewCounts{}, ErrInvalid
	}
	for _, f := range files {
		switch {
		case f.Before == nil:
			f.Kind = "added"
			result.Counts.Added++
		case f.After == nil:
			f.Kind = "removed"
			result.Counts.Removed++
		case f.Before.Bytes == f.After.Bytes && f.Before.SHA256 == f.After.SHA256:
			f.Kind = "unchanged"
			result.Counts.Unchanged++
		default:
			f.Kind = "modified"
			result.Counts.Modified++
		}
		result.Files = append(result.Files, f)
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	return result.Files, result.Counts, nil
}
