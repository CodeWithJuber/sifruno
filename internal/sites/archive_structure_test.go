package sites

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These mutations were accepted by archive/zip with unchanged payload CRC/SHA.
// Native admission must reject the inconsistent metadata before target writes.
func TestNativeZIPRejectsInconsistentLocalHeadersAndDescriptors(t *testing.T) {
	raw := nativeMigrationArchive(t, map[string][]byte{"index.html": []byte("<h1>Original</h1>")})
	u16, u32 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32
	central := int(u32(raw[len(raw)-6:]))
	local := int(u32(raw[central+42:]))
	payload := local + 30 + int(u16(raw[local+26:])) + int(u16(raw[local+28:]))
	descriptor := payload + int(u32(raw[central+20:]))
	if u16(raw[local+6:])&8 == 0 || u32(raw[descriptor:]) != 0x08074b50 {
		t.Fatal("native writer did not provide the expected descriptor")
	}
	cases := []struct {
		name string
		edit func([]byte)
	}{
		{"descriptor CRC", func(b []byte) { b[descriptor+4] ^= 1 }},
		{"descriptor compressed size", func(b []byte) { b[descriptor+8] ^= 1 }},
		{"descriptor expanded size", func(b []byte) { b[descriptor+12] ^= 1 }},
		{"descriptor signature", func(b []byte) { b[descriptor] ^= 1 }},
		{"local placeholder CRC", func(b []byte) { binary.LittleEndian.PutUint32(b[local+14:], u32(b[central+16:])^1) }},
		{"local placeholder compressed size", func(b []byte) { binary.LittleEndian.PutUint32(b[local+18:], u32(b[central+20:])+1) }},
		{"local placeholder expanded size", func(b []byte) { binary.LittleEndian.PutUint32(b[local+22:], u32(b[central+24:])+1) }},
		{"local fixed CRC mismatch", func(b []byte) {
			binary.LittleEndian.PutUint16(b[local+6:], u16(b[local+6:])&^8)
			binary.LittleEndian.PutUint16(b[central+8:], u16(b[central+8:])&^8)
			binary.LittleEndian.PutUint32(b[local+14:], u32(b[central+16:])^1)
			binary.LittleEndian.PutUint32(b[local+18:], u32(b[central+20:]))
			binary.LittleEndian.PutUint32(b[local+22:], u32(b[central+24:]))
		}},
		{"overlapping local records", func(b []byte) {
			second := central + 46 + int(u16(b[central+28:])) + int(u16(b[central+30:])) + int(u16(b[central+32:]))
			binary.LittleEndian.PutUint32(b[second+42:], uint32(local))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := append([]byte(nil), raw...)
			tc.edit(candidate)
			s, _, base := fixture(t)
			if _, err := s.ImportArchive(ImportInput{Name: "Rejected", Domain: "rejected.test", Archive: candidate}, "local-operator"); !errors.Is(err, ErrInvalid) {
				t.Fatal("inconsistent ZIP metadata admitted")
			}
			items, err := s.List()
			if err != nil || len(items) != 0 {
				t.Fatal("rejected ZIP created a record")
			}
			dirs, err := os.ReadDir(filepath.Join(base, "sites", "data"))
			if err != nil || len(dirs) != 0 {
				t.Fatal("rejected ZIP created files")
			}
		})
	}
}
