package sites

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// boundedZipDirectory admits the bounded ordinary ZIP layout written by
// buildArchive before archive/zip allocates its central-directory inventory.
// Native v1 never needs ZIP64, split disks, executable prefixes or comments.
// Decompression, CRC and data-descriptor checks remain archive/zip's work.
func boundedZipDirectory(raw []byte) error {
	if len(raw) < 22 || !bytes.HasPrefix(raw, []byte{'P', 'K', 3, 4}) {
		return ErrInvalid
	}
	end := len(raw) - 22
	eocd := raw[end:]
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	if u32(eocd) != 0x06054b50 || u16(eocd[4:]) != 0 || u16(eocd[6:]) != 0 || u16(eocd[20:]) != 0 {
		return ErrInvalid
	}
	count := int(u16(eocd[10:]))
	if count < 2 || count > MaxFiles+1 || int(u16(eocd[8:])) != count {
		return ErrInvalid
	}
	start, size := uint64(u32(eocd[16:])), uint64(u32(eocd[12:]))
	if start+size != uint64(end) || start >= uint64(end) {
		return ErrInvalid
	}
	at := int(start)
	for i := 0; i < count; i++ {
		if at > end-46 || u32(raw[at:]) != 0x02014b50 {
			return ErrInvalid
		}
		h := raw[at : at+46]
		nameSize, extraSize, commentSize := int(u16(h[28:])), int(u16(h[30:])), int(u16(h[32:]))
		next := at + 46 + nameSize + extraSize + commentSize
		if next > end || u16(h[34:]) != 0 || u32(h[20:]) > MaxBackupBytes || u32(h[24:]) > MaxFileBytes {
			return ErrInvalid
		}
		name := raw[at+46 : at+46+nameSize]
		local := uint64(u32(h[42:]))
		if local+30 > start {
			return ErrInvalid
		}
		lh := raw[int(local) : int(local)+30]
		localName := int(u16(lh[26:]))
		dataStart := local + 30 + uint64(localName) + uint64(u16(lh[28:]))
		if u32(lh) != 0x04034b50 || u16(lh[6:]) != u16(h[8:]) || u16(lh[8:]) != u16(h[10:]) || dataStart > start || dataStart+uint64(u32(h[20:])) > start || !bytes.Equal(name, raw[int(local)+30:int(local)+30+localName]) {
			return ErrInvalid
		}
		at = next
	}
	if at != end {
		return ErrInvalid
	}
	return nil
}

func decodeArchiveManifest(raw []byte) (archiveManifest, error) {
	var m archiveManifest
	if !utf8.Valid(raw) || uniqueJSONKeys(raw) != nil {
		return m, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, ErrInvalid
	}
	return m, nil
}

// JSON's normal duplicate-key last-write-wins behavior is inappropriate for
// an archive manifest. Reuse decoder tokens and reject aliases before decoding
// the typed schema; bound nesting as well as the existing 64 KiB byte limit.
func uniqueJSONKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		delim, composite := t.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				key, ok := keyToken.(string)
				key = strings.ToLower(key)
				if err != nil || !ok || seen[key] {
					return ErrInvalid
				}
				seen[key] = true
				if value(depth+1) != nil {
					return ErrInvalid
				}
			}
			if close, err := d.Token(); err != nil || close != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if value(depth+1) != nil {
					return ErrInvalid
				}
			}
			if close, err := d.Token(); err != nil || close != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if value(0) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
