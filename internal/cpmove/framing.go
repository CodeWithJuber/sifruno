package cpmove

import (
	"archive/tar"
	"bytes"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The SDK caps special headers at 1 MiB (archive/tar/format.go). This guard
// applies that bound before SDK allocation, detects sparse metadata before SDK
// normalization, and preserves a strict end-of-archive boundary.
const maxMetadata = 1 << 20
const maxRetainedMetadata = 64 << 10

type tarGuard struct {
	r                  io.Reader
	limits             Limits
	block              [512]byte
	pos                int
	ready              bool
	remaining, padding int64
	metadata           []byte
	metaType           byte
	logicalType        byte
	pending            map[string]string
	longName, longLink bool
	zeros              int
	ended              bool
}

func (g *tarGuard) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if g.ready {
		n := copy(p, g.block[g.pos:])
		g.pos += n
		if g.pos == 512 {
			g.ready = false
			g.pos = 0
		}
		return n, nil
	}
	if g.remaining > 0 {
		if int64(len(p)) > g.remaining {
			p = p[:g.remaining]
		}
		n, err := g.r.Read(p)
		g.remaining -= int64(n)
		if g.metaType != 0 {
			g.metadata = append(g.metadata, p[:n]...)
		}
		if g.remaining == 0 && g.metaType != 0 {
			if parseErr := g.parseMetadata(); parseErr != nil {
				return n, parseErr
			}
		}
		return n, err
	}
	if g.padding > 0 {
		if int64(len(p)) > g.padding {
			p = p[:g.padding]
		}
		n, err := g.r.Read(p)
		g.padding -= int64(n)
		return n, err
	}
	if g.ended {
		return 0, io.EOF
	}
	if _, err := io.ReadFull(g.r, g.block[:]); err != nil {
		return 0, err
	}
	if bytes.Equal(g.block[:], make([]byte, 512)) {
		g.zeros++
		if g.pending != nil || g.longName || g.longLink {
			return 0, ErrArchive
		}
		if g.zeros == 2 {
			g.ended = true
		}
	} else {
		if g.zeros != 0 {
			return 0, ErrArchive
		}
		if err := g.header(); err != nil {
			return 0, err
		}
	}
	g.ready = true
	return g.Read(p)
}

func (g *tarGuard) header() error {
	t := g.block[156]
	if t == tar.TypeGNUSparse || t == tar.TypeXGlobalHeader {
		return ErrUnsupported
	}
	size, ok := tarNumber(g.block[124:136])
	if !ok || size < 0 {
		return ErrArchive
	}
	g.metaType = 0
	g.metadata = nil
	switch t {
	case tar.TypeXHeader:
		if g.pending != nil {
			return ErrUnsupported
		}
		if size > maxMetadata {
			return ErrLimit
		}
		g.metaType = t
	case tar.TypeGNULongName, tar.TypeGNULongLink:
		if size > int64(g.limits.MaxPathBytes)+1 || size > maxMetadata {
			return ErrLimit
		}
		if (t == tar.TypeGNULongName && g.longName) || (t == tar.TypeGNULongLink && g.longLink) {
			return ErrUnsupported
		}
		if t == tar.TypeGNULongName {
			g.longName = true
		} else {
			g.longLink = true
		}
		g.metaType = t
	default:
		g.logicalType = t
		if g.pending != nil {
			if value, exists := g.pending["size"]; exists && value != "" {
				var err error
				size, err = strconv.ParseInt(value, 10, 64)
				if err != nil || size < 0 {
					return ErrArchive
				}
			}
		}
		g.pending = nil
		g.longName = false
		g.longLink = false
		if size > g.limits.MaxFileBytes {
			return ErrLimit
		}
		// These SDK types have no physical payload, even if their size field is
		// nonzero. Preserve Size in the catalog; do not invent payload bytes.
		switch t {
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
			size = 0
		}
	}
	g.remaining = size
	g.padding = (512 - size%512) % 512
	if g.metaType != 0 && size == 0 {
		return g.parseMetadata()
	}
	return nil
}

func (g *tarGuard) parseMetadata() error {
	if g.metaType != tar.TypeXHeader {
		if len(g.metadata) == 0 || g.metadata[0] == 0 {
			return ErrUnsupported
		}
		if nul := bytes.IndexByte(g.metadata, 0); nul >= 0 {
			for _, b := range g.metadata[nul:] {
				if b != 0 {
					return ErrUnsupported
				}
			}
		}
		g.metadata = nil
		g.metaType = 0
		return nil
	}
	g.pending = make(map[string]string)
	s := string(g.metadata)
	retained := 0
	for len(s) > 0 {
		space := strings.IndexByte(s, ' ')
		if space <= 0 {
			return ErrArchive
		}
		length, err := strconv.Atoi(s[:space])
		if err != nil || length <= space+2 || length > len(s) || s[length-1] != '\n' {
			return ErrArchive
		}
		record := s[space+1 : length-1]
		equals := strings.IndexByte(record, '=')
		if equals <= 0 {
			return ErrArchive
		}
		key, value := record[:equals], record[equals+1:]
		// JSON key-name strings cannot retain invalid UTF-8 bytes. Refuse that
		// variant rather than serialize replacement characters as observations.
		if !utf8.ValidString(key) {
			return ErrUnsupported
		}
		if strings.ContainsRune(key, 0) || strings.ContainsRune(key, '\n') {
			return ErrArchive
		}
		if strings.HasPrefix(key, "GNU.sparse.") || key == "SCHILY.realsize" || key == "SCHILY.filetype" && value == "sparse" {
			return ErrUnsupported
		}
		if len(key) > g.limits.MaxPathBytes {
			return ErrLimit
		}
		retained += len(key) + len(value)
		if retained > maxRetainedMetadata {
			return ErrLimit
		}
		if _, exists := g.pending[key]; exists {
			return ErrUnsupported
		}
		g.pending[key] = value
		s = s[length:]
	}
	g.metadata = nil
	g.metaType = 0
	return nil
}

func (g *tarGuard) finish() error {
	if !g.ended || g.zeros != 2 || g.ready || g.remaining != 0 || g.padding != 0 {
		return ErrArchive
	}
	buf := make([]byte, 32768)
	var padding int64
	for {
		n, err := g.r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return ErrArchive
			}
		}
		padding += int64(n)
		if err == io.EOF {
			if padding%512 != 0 {
				return ErrArchive
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func tarNumber(b []byte) (int64, bool) {
	if b[0]&0x80 != 0 {
		if b[0]&0x40 != 0 {
			return 0, false
		}
		var n int64
		for i, c := range b {
			if i == 0 {
				c &= 0x7f
			}
			if n > (1<<63-1-int64(c))/256 {
				return 0, false
			}
			n = n*256 + int64(c)
		}
		return n, true
	}
	s := strings.Trim(string(b), " \x00")
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 8, 64)
	return n, err == nil
}
