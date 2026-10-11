package sites

import "time"

// FileRestoreInput binds one exact archived path to its saved ZIP and current site.
type FileRestoreInput struct {
	BackupID             string `json:"backup_id"`
	ExpectedBackupSHA256 string `json:"expected_backup_sha256"`
	ExpectedRevision     uint64 `json:"expected_revision"`
	Path                 string `json:"path"`
}

type ConfirmFileRestoreInput struct {
	FileRestoreInput
	Confirmed bool `json:"confirmed"`
}

type FileRestorePreview struct {
	SiteID          string             `json:"site_id"`
	CurrentRevision uint64             `json:"current_revision"`
	BackupID        string             `json:"backup_id"`
	BackupSHA256    string             `json:"backup_sha256"`
	BackupRevision  uint64             `json:"backup_revision"`
	File            RestorePreviewFile `json:"file"`
	PreservedFiles  int                `json:"preserved_files"`
}

// Both operations validate the merged catalog while holding the store lock.
// Only the selected archive bytes enter that catalog; every other current file stays.
func (s *Store) fileRestoreLocked(id string, input FileRestoreInput) (record, map[string][]byte, []FileInfo, FileRestorePreview, error) {
	var empty FileRestorePreview
	if !identifier.MatchString(id) || !identifier.MatchString(input.BackupID) || !hashPattern.MatchString(input.ExpectedBackupSHA256) || input.ExpectedRevision == 0 || input.ExpectedRevision > maxScheduleRevision || safeFile(input.Path) != nil {
		return record{}, nil, nil, empty, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return r, nil, nil, empty, err
	}
	if r.Site.Revision != input.ExpectedRevision {
		return r, nil, nil, empty, ErrConflict
	}
	var found *BackupInfo
	for i := range r.Backups {
		if r.Backups[i].ID == input.BackupID {
			found = &r.Backups[i]
			break
		}
	}
	if found == nil {
		return r, nil, nil, empty, ErrNotFound
	}
	if found.SHA256 != input.ExpectedBackupSHA256 {
		return r, nil, nil, empty, ErrConflict
	}
	if found.Revision > maxScheduleRevision {
		return r, nil, nil, empty, ErrUnavailable
	}
	data, err := s.snapshot(r)
	if err != nil {
		return r, nil, nil, empty, err
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return r, nil, nil, empty, err
	}
	raw, err := readRoot(rt, "backups/"+found.ID+".zip", MaxBackupBytes)
	rt.Close()
	if err != nil {
		return r, nil, nil, empty, ErrUnavailable
	}
	archived, err := parseArchive(raw, *found)
	if err != nil {
		return r, nil, nil, empty, ErrUnavailable
	}
	selected, ok := archived[input.Path]
	if !ok {
		return r, nil, nil, empty, ErrNotFound
	}
	data[input.Path] = selected
	after, err := fileCatalog(data)
	if err != nil {
		return r, nil, nil, empty, err
	}
	if err = s.validateRestoreDestinations(id, after); err != nil {
		return r, nil, nil, empty, err
	}
	files, _, err := restoreDiff(r.Files, after)
	if err != nil {
		return r, nil, nil, empty, err
	}
	for _, file := range files {
		if file.Path == input.Path {
			return r, data, after, FileRestorePreview{SiteID: id, CurrentRevision: r.Site.Revision, BackupID: found.ID, BackupSHA256: found.SHA256, BackupRevision: found.Revision, File: file, PreservedFiles: len(after) - 1}, nil
		}
	}
	return r, nil, nil, empty, ErrUnavailable
}

func (s *Store) PreviewFileRestore(id string, input FileRestoreInput) (FileRestorePreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, _, preview, err := s.fileRestoreLocked(id, input)
	return preview, err
}

func (s *Store) RestoreFile(id string, input ConfirmFileRestoreInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !input.Confirmed || !validActor(actor) {
		return Site{}, ErrInvalid
	}
	r, data, files, _, err := s.fileRestoreLocked(id, input.FileRestoreInput)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision >= maxScheduleRevision {
		return Site{}, ErrConflict
	}
	next := r
	next.Files = files
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	if err = s.change(r, next, data, "restore", actor); err != nil {
		return Site{}, err
	}
	return next.Site, nil
}
