package sites

// DownloadInput binds a read to the saved file and inventory revision.
type DownloadInput struct {
	Path             string
	ExpectedSHA256   string
	ExpectedRevision uint64
}

// DownloadFile returns verified raw saved bytes, including non-UTF-8 assets.
// It uses the same root and handle guards as the editor without changing state.
func (s *Store) DownloadFile(id string, input DownloadInput) ([]byte, FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if safeFile(input.Path) != nil || !hashPattern.MatchString(input.ExpectedSHA256) || input.ExpectedRevision == 0 {
		return nil, FileInfo{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return nil, FileInfo{}, err
	}
	if r.Site.Revision != input.ExpectedRevision {
		return nil, FileInfo{}, ErrConflict
	}
	var expected *FileInfo
	for i := range r.Files {
		if r.Files[i].Path == input.Path {
			expected = &r.Files[i]
			break
		}
	}
	if expected == nil {
		return nil, FileInfo{}, ErrNotFound
	}
	if expected.SHA256 != input.ExpectedSHA256 {
		return nil, FileInfo{}, ErrConflict
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return nil, FileInfo{}, err
	}
	defer rt.Close()
	data, err := readRoot(rt, "content/"+input.Path, MaxFileBytes)
	if err != nil {
		return nil, FileInfo{}, ErrUnavailable
	}
	if sum(data) != expected.SHA256 || int64(len(data)) != expected.Bytes {
		return nil, FileInfo{}, ErrConflict
	}
	return data, *expected, nil
}
