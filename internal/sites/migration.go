package sites

// ExportBackup returns the original archive bytes only after the signed
// catalog, private file identity and complete archive have been verified.
func (s *Store) ExportBackup(siteID, backupID string) ([]byte, BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !identifier.MatchString(backupID) {
		return nil, BackupInfo{}, ErrInvalid
	}
	r, err := s.checked(siteID)
	if err != nil {
		return nil, BackupInfo{}, err
	}
	var info *BackupInfo
	for i := range r.Backups {
		if r.Backups[i].ID == backupID {
			info = &r.Backups[i]
			break
		}
	}
	if info == nil {
		return nil, BackupInfo{}, ErrNotFound
	}
	rt, err := s.siteRoot(siteID)
	if err != nil {
		return nil, BackupInfo{}, err
	}
	defer rt.Close()
	raw, err := readRoot(rt, "backups/"+backupID+".zip", MaxBackupBytes)
	if err != nil {
		return nil, BackupInfo{}, ErrUnavailable
	}
	if _, err = parseArchive(raw, *info); err != nil {
		return nil, BackupInfo{}, ErrUnavailable
	}
	return raw, *info, nil
}

// ImportArchive validates the entire native archive before any record or file
// is created. An import receives a fresh target ID/revision and no fabricated
// source backup history. Its complete catalog shares Create's scoped journal.
func (s *Store) ImportArchive(input ImportInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !validName(input.Name) {
		return Site{}, ErrInvalid
	}
	if _, err := canonicalDomain(input.Domain); err != nil {
		return Site{}, err
	}
	data, _, err := parseNativeArchive(input.Archive)
	if err != nil {
		return Site{}, ErrInvalid
	}
	return s.create(CreateInput{Name: input.Name, Domain: input.Domain}, data, "import", actor)
}
