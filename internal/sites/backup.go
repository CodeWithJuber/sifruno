package sites

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

type archiveManifest struct {
	Version  int        `json:"version"`
	BackupID string     `json:"backup_id"`
	SiteID   string     `json:"site_id"`
	Revision uint64     `json:"revision"`
	Files    []FileInfo `json:"files"`
}
type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, ErrInvalid
	}
	return b.Buffer.Write(p)
}
func buildArchive(r record, backupID string, data map[string][]byte) ([]byte, error) {
	files, err := fileCatalog(data)
	if err != nil {
		return nil, err
	}
	manifest := archiveManifest{Version: 1, BackupID: backupID, SiteID: r.Site.ID, Revision: r.Site.Revision, Files: files}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrUnavailable
	}
	out := &boundedBuffer{limit: MaxBackupBytes}
	writer := zip.NewWriter(out)
	add := func(name string, content []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		f, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = f.Write(content)
		return err
	}
	if add("manifest.json", raw) != nil {
		return nil, ErrUnavailable
	}
	for _, f := range files {
		if add("files/"+f.Path, data[f.Path]) != nil {
			return nil, ErrUnavailable
		}
	}
	if writer.Close() != nil {
		return nil, ErrUnavailable
	}
	return out.Bytes(), nil
}
func parseArchive(raw []byte, info BackupInfo) (map[string][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxBackupBytes || int64(len(raw)) != info.Bytes || sum(raw) != info.SHA256 {
		return nil, ErrUnavailable
	}
	data, manifest, err := parseNativeArchive(raw)
	if err != nil {
		return nil, err
	}
	if manifest.SiteID != info.SiteID || manifest.BackupID != info.ID || manifest.Revision != info.Revision || len(data) != info.Files {
		return nil, ErrInvalid
	}
	return data, nil
}

func parseNativeArchive(raw []byte) (map[string][]byte, archiveManifest, error) {
	invalid := func() (map[string][]byte, archiveManifest, error) { return nil, archiveManifest{}, ErrInvalid }
	if len(raw) == 0 || len(raw) > MaxBackupBytes || boundedZipDirectory(raw) != nil {
		return invalid()
	}
	r, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(r.File) < 2 || len(r.File) > MaxFiles+1 {
		return invalid()
	}
	data := map[string][]byte{}
	seen := map[string]bool{}
	var manifest *archiveManifest
	var total int64
	for _, f := range r.File {
		key := strings.ToLower(f.Name)
		if seen[key] || !f.Mode().IsRegular() || f.NonUTF8 || f.CompressedSize64 > MaxBackupBytes || (f.Method != zip.Store && f.Method != zip.Deflate) || f.Flags&1 != 0 {
			return invalid()
		}
		seen[key] = true
		limit := int64(MaxFileBytes)
		if f.Name == "manifest.json" {
			limit = 64 << 10
		} else {
			if !strings.HasPrefix(f.Name, "files/") || safeFile(strings.TrimPrefix(f.Name, "files/")) != nil {
				return invalid()
			}
		}
		if f.UncompressedSize64 > uint64(limit) {
			return invalid()
		}
		stream, err := f.Open()
		if err != nil {
			return invalid()
		}
		content, err := io.ReadAll(io.LimitReader(stream, limit+1))
		closeErr := stream.Close()
		if err != nil || closeErr != nil || int64(len(content)) > limit || uint64(len(content)) != f.UncompressedSize64 {
			return invalid()
		}
		if f.Name == "manifest.json" {
			m, err := decodeArchiveManifest(content)
			if err != nil {
				return invalid()
			}
			manifest = &m
		} else {
			total += int64(len(content))
			if total > MaxSiteBytes {
				return invalid()
			}
			data[strings.TrimPrefix(f.Name, "files/")] = content
		}
	}
	if manifest == nil || manifest.Version != 1 || !identifier.MatchString(manifest.SiteID) || !identifier.MatchString(manifest.BackupID) || manifest.Revision == 0 {
		return invalid()
	}
	files, err := fileCatalog(data)
	if err != nil || !reflect.DeepEqual(files, manifest.Files) {
		return invalid()
	}
	return data, *manifest, nil
}
func (s *Store) Backup(id string, expectedRevision uint64, actor string) (BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) {
		return BackupInfo{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return BackupInfo{}, err
	}
	if expectedRevision != r.Site.Revision || r.Site.Revision == math.MaxUint64 {
		return BackupInfo{}, ErrConflict
	}
	if len(r.Backups) >= MaxBackups {
		return BackupInfo{}, ErrInvalid
	}
	data, err := s.snapshot(r)
	if err != nil {
		return BackupInfo{}, err
	}
	backupID, err := newID()
	if err != nil {
		return BackupInfo{}, err
	}
	raw, err := buildArchive(r, backupID, data)
	if err != nil {
		return BackupInfo{}, err
	}
	var stored int64
	for _, b := range r.Backups {
		stored += b.Bytes
	}
	if stored+int64(len(raw)) > MaxBackupStorage {
		return BackupInfo{}, ErrInvalid
	}
	info := BackupInfo{ID: backupID, SiteID: id, CreatedAt: time.Now().UTC(), Bytes: int64(len(raw)), Files: len(data), SHA256: sum(raw), Revision: r.Site.Revision}
	rt, err := s.siteRoot(id)
	if err != nil {
		return BackupInfo{}, err
	}
	defer rt.Close()
	if checkParents(rt, "backups") != nil {
		return BackupInfo{}, ErrUnavailable
	}
	name := "backups/" + backupID + ".zip"
	if _, err = rt.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return BackupInfo{}, ErrUnavailable
	}
	pending := r
	pending.Pending = &pendingChange{Action: "backup", Checkpoints: []string{}}
	if s.save(pending) != nil {
		return BackupInfo{}, ErrUnavailable
	}
	if atomicRoot(rt, name, raw) != nil {
		return BackupInfo{}, ErrUnavailable
	}
	next := r
	next.Site.Revision++
	next.Site.UpdatedAt = time.Now().UTC()
	next.Backups = append(append([]BackupInfo{}, r.Backups...), info)
	if err = s.change(r, next, nil, "backup", actor); err != nil {
		current, _ := s.load(id)
		if current.Pending == nil && checkParents(rt, name) == nil {
			_ = rt.Remove(name)
		}
		return BackupInfo{}, err
	}
	return info, nil
}
func (s *Store) Backups(id string) ([]BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.checked(id)
	if err != nil {
		return nil, err
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	for _, b := range r.Backups {
		raw, err := readRoot(rt, "backups/"+b.ID+".zip", MaxBackupBytes)
		if err != nil {
			return nil, ErrUnavailable
		}
		if _, err = parseArchive(raw, b); err != nil {
			return nil, ErrUnavailable
		}
	}
	result := append([]BackupInfo{}, r.Backups...)
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}
func (s *Store) Restore(id string, input RestoreInput, actor string) (Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validActor(actor) || !identifier.MatchString(input.BackupID) {
		return Site{}, ErrInvalid
	}
	r, err := s.checked(id)
	if err != nil {
		return Site{}, err
	}
	if r.Site.Revision != input.ExpectedRevision || r.Site.Revision == math.MaxUint64 {
		return Site{}, ErrConflict
	}
	var found *BackupInfo
	for i := range r.Backups {
		if r.Backups[i].ID == input.BackupID {
			found = &r.Backups[i]
		}
	}
	if found == nil {
		return Site{}, ErrNotFound
	}
	if _, err = s.snapshot(r); err != nil {
		return Site{}, err
	}
	rt, err := s.siteRoot(id)
	if err != nil {
		return Site{}, err
	}
	raw, err := readRoot(rt, "backups/"+found.ID+".zip", MaxBackupBytes)
	rt.Close()
	if err != nil {
		return Site{}, ErrUnavailable
	}
	data, err := parseArchive(raw, *found)
	if err != nil {
		return Site{}, err
	}
	files, err := fileCatalog(data)
	if err != nil {
		return Site{}, err
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
