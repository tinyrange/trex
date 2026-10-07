package cpio

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
	"testing"
)

func sidecar(extended bool) []byte {
	size := 82
	if extended {
		size = 180
	}
	b := make([]byte, size)
	be := binary.BigEndian
	be.PutUint32(b, 0x51607)
	be.PutUint32(b[4:], 0x20000)
	be.PutUint16(b[24:], 2)
	be.PutUint32(b[26:], 9)
	be.PutUint32(b[30:], 50)
	be.PutUint32(b[34:], 32)
	be.PutUint32(b[38:], 2)
	be.PutUint32(b[42:], uint32(size))
	b[58] = 0x80
	if extended {
		be.PutUint32(b[34:], uint32(size-50))
		copy(b[84:], "ATTR")
		be.PutUint32(b[92:], uint32(size))
		be.PutUint32(b[96:], 120) // empty ATTR with allocated slack
	}
	return b
}
func TestCPIOAppleDoubleNormalizationPreservesBorrowedMetadata(t *testing.T) {
	for _, extended := range []bool{false, true} {
		raw := record("070707", "._link", string(sidecar(extended)), 1, 0100644, 1)
		raw = append(raw, record("070707", "link", "target", 2, 0120777, 1)...)
		raw = append(raw, trailer("070707")...)
		entries, err := Read(&starfile.Bytes{Data: raw}, 10)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := WithAppleDouble(entries)
		if err != nil || len(normalized) != 1 {
			t.Fatal(err)
		}
		e := normalized[0]
		if e.Kind != "symlink" || e.Attributes["target"] != "target" {
			t.Fatal("followed or changed symlink")
		}
		finder := e.Attributes["finder_info"].(storage.Reader)
		raw[bytes.Index(raw, sidecar(extended))+58] = 0x40
		got, err := io.ReadAll(io.NewSectionReader(finder, 0, finder.Size()))
		if err != nil || len(got) != 32 || got[8] != 0x40 {
			t.Fatal("copied or corrupted FinderInfo", err)
		}
		if _, changed := entries[1].Attributes["finder_info"]; changed {
			t.Fatal("mutated raw inventory")
		}
	}
}
func TestCPIOAppleDoubleFailuresAreContextual(t *testing.T) {
	for _, target := range []bool{false, true} {
		raw := record("070701", "dir/._file", "bad", 1, 0100644, 1)
		if target {
			raw = append(raw, record("070701", "dir/file", "payload", 2, 0100644, 1)...)
		}
		entries, err := Read(&starfile.Bytes{Data: raw}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := WithAppleDouble(entries); out != nil || err == nil || !strings.Contains(err.Error(), "dir/._file") {
			t.Fatal(out, err)
		}
	}
}
