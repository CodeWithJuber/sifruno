package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"sifruno/internal/securestate"
	"sifruno/internal/sites"
)

func transferID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func transferRoot(path string) (*os.Root, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" || guardTransferPath(absolute) != nil || securestate.CheckPath(absolute) != nil {
		return nil, "", errors.New("archive path must be a real local file path")
	}
	name := filepath.Base(absolute)
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return nil, "", errors.New("invalid archive file path")
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, "", errors.New("archive parent directory unavailable")
	}
	return root, name, nil
}
func readTransferArchive(path string) ([]byte, error) {
	root, name, err := transferRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > sites.MaxBackupBytes {
		return nil, errors.New("archive must be a nonempty regular file no larger than 34 MiB")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("archive file unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || guardTransferHandle(file, opened) != nil {
		return nil, errors.New("archive must be an unchanged single-link regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, sites.MaxBackupBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(raw) > sites.MaxBackupBytes || int64(len(raw)) != info.Size() || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || guardTransferHandle(file, after) != nil {
		return nil, errors.New("archive changed or exceeded the bounded limit")
	}
	if !nativeTransferZIP(raw) {
		return nil, errors.New("archive is not a bounded native Sifruno v1 ZIP")
	}
	return raw, nil
}

// This admission check does not replace the server's full signed catalog and
// native archive verification. Bound central-directory allocation before using
// archive/zip, and validate CRCs and native manifest version without echoing data.
func nativeTransferZIP(raw []byte) bool {
	if len(raw) < 22 || len(raw) > sites.MaxBackupBytes || !bytes.HasPrefix(raw, []byte{'P', 'K', 3, 4}) {
		return false
	}
	end := raw[len(raw)-22:]
	u16, u32 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32
	count := int(u16(end[10:]))
	start, size := uint64(u32(end[16:])), uint64(u32(end[12:]))
	if u32(end) != 0x06054b50 || u16(end[4:]) != 0 || u16(end[6:]) != 0 || u16(end[20:]) != 0 || count < 2 || count > sites.MaxFiles+1 || int(u16(end[8:])) != count || size > uint64((sites.MaxFiles+1)*2048) || start+size != uint64(len(raw)-22) {
		return false
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(zr.File) != count {
		return false
	}
	manifest := false
	var total uint64
	for _, f := range zr.File {
		limit := uint64(sites.MaxFileBytes)
		if f.Name == "manifest.json" {
			if manifest {
				return false
			}
			manifest = true
			limit = 65536
		} else if len(f.Name) < 7 || f.Name[:6] != "files/" {
			return false
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 > limit {
			return false
		}
		reader, err := f.Open()
		if err != nil {
			return false
		}
		if f.Name == "manifest.json" {
			b, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
			reader.Close()
			var m struct {
				Version int `json:"version"`
			}
			if err != nil || uint64(len(b)) > limit || json.Unmarshal(b, &m) != nil || m.Version != 1 {
				return false
			}
		} else {
			n, err := io.Copy(io.Discard, io.LimitReader(reader, int64(limit)+1))
			reader.Close()
			if err != nil || uint64(n) > limit {
				return false
			}
			total += uint64(n)
			if total > sites.MaxSiteBytes {
				return false
			}
		}
	}
	return manifest
}

func (c *siteClient) exportSite(endpoint, path string, out io.Writer) error {
	root, name, err := transferRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("export output must be a new file; existing paths are refused")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return errors.New("export file identity unavailable")
	}
	success := false
	defer func() {
		file.Close()
		if !success {
			current, e := root.Lstat(name)
			if e == nil && current.Mode().IsRegular() && os.SameFile(info, current) {
				_ = root.Remove(name)
			}
		}
	}()
	if !info.Mode().IsRegular() || guardTransferHandle(file, info) != nil {
		return errors.New("export output must be a single-link regular file")
	}
	req, err := http.NewRequest(http.MethodGet, c.base+endpoint, nil)
	if err != nil {
		return errors.New("invalid archive request")
	}
	req.Header.Set("Accept", "application/zip")
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("local archive export request failed")
	}
	defer resp.Body.Close()
	ct, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || err != nil || ct != "application/zip" || len(params) != 0 || resp.ContentLength > sites.MaxBackupBytes || resp.ContentLength == 0 {
		return errors.New("panel rejected export or returned an invalid bounded ZIP response")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, sites.MaxBackupBytes+1))
	if err != nil || len(raw) > sites.MaxBackupBytes || (resp.ContentLength >= 0 && int64(len(raw)) != resp.ContentLength) || !nativeTransferZIP(raw) {
		return errors.New("panel archive response is malformed or exceeds 34 MiB")
	}
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || guardTransferHandle(file, info) != nil {
		return errors.New("export output identity changed")
	}
	if _, err = file.Write(raw); err != nil {
		return errors.New("export archive could not be written")
	}
	if file.Sync() != nil || file.Close() != nil {
		return errors.New("export archive could not be persisted")
	}
	current, err = root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return errors.New("export output identity changed")
	}
	success = true
	hash := sha256.Sum256(raw)
	return json.NewEncoder(out).Encode(struct {
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
		Format string `json:"format"`
	}{len(raw), hex.EncodeToString(hash[:]), "sifruno-site-v1"})
}

func (c *siteClient) importSite(endpoint, name, domain, path string, out io.Writer) error {
	archive, err := readTransferArchive(path)
	if err != nil {
		return err
	}
	// Known bounded file/fields make the multipart body bounded in memory.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if mw.WriteField("name", name) != nil || mw.WriteField("domain", domain) != nil {
		return errors.New("archive request unavailable")
	}
	part, err := mw.CreateFormFile("archive", "sifruno-site.zip")
	if err != nil {
		return errors.New("archive request unavailable")
	}
	if _, err = part.Write(archive); err != nil || mw.Close() != nil || body.Len() > sites.MaxBackupBytes+16384 {
		return errors.New("archive request exceeded the bounded limit")
	}
	req, err := http.NewRequest(http.MethodPost, c.base+endpoint, &body)
	if err != nil {
		return errors.New("invalid archive import request")
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", c.base)
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("local archive import request failed")
	}
	defer resp.Body.Close()
	ct, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || err != nil || ct != "application/json" {
		return errors.New("panel rejected archive import")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("panel import response exceeded the bounded limit")
	}
	var site sites.Site
	if json.Unmarshal(raw, &site) != nil || !transferID(site.ID) || site.Revision == 0 || site.Domain == "" || site.State != "active" {
		return errors.New("panel returned invalid imported website metadata")
	}
	return json.NewEncoder(out).Encode(site)
}
