package applearchive

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func record(path string, data []byte) []byte {
	h := []byte("AA01\x00\x00TYP1FPATP")
	h = binary.LittleEndian.AppendUint16(h, uint16(len(path)))
	h = append(h, path...)
	h = append(h, []byte("MOD2\xa4\x01MTMT")...)
	h = binary.LittleEndian.AppendUint64(h, 1700000000)
	h = binary.LittleEndian.AppendUint32(h, 123456)
	h = append(h, []byte("DATB")...)
	h = binary.LittleEndian.AppendUint32(h, uint32(len(data)))
	binary.LittleEndian.PutUint16(h[4:], uint16(len(h)))
	return append(h, data...)
}

func TestBorrowedRecords(t *testing.T) {
	input := append(record("digest.db", []byte("AA01 is ordinary blob data")), record("mtree.txt", []byte("hello"))...)
	entries, err := Read(bytes.NewReader(input), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Path != "digest.db" || entries[1].Path != "mtree.txt" {
		t.Fatalf("entries %+v", entries)
	}
	if got := entries[0].Fields["MTM"].(Timestamp); got.Seconds != 1700000000 || got.Nanoseconds != 123456 {
		t.Fatal(got)
	}
	data, err := io.ReadAll(io.NewSectionReader(entries[0].Data, 0, entries[0].Data.Size()))
	if err != nil || string(data) != "AA01 is ordinary blob data" {
		t.Fatalf("data %q %v", data, err)
	}
	if entries[1].Fields["MOD"].(uint64) != 0644 {
		t.Fatal("mode")
	}
}

func TestShortBlobAndSymlink(t *testing.T) {
	h := []byte("AA01\x00\x00TYP1LPATP\x04\x00linkLNKP\x06\x00targetXATA\x03\x00")
	binary.LittleEndian.PutUint16(h[4:], uint16(len(h)))
	input := append(h, []byte("xat")...)
	input = append(input, record("next", []byte("data"))...)
	entries, err := Read(bytes.NewReader(input), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Kind != "symlink" || entries[0].Fields["LNK"] != "target" || entries[1].Path != "next" {
		t.Fatalf("entries %+v", entries)
	}
	blob := entries[0].Fields["XAT"].(*io.SectionReader)
	var data [3]byte
	if _, err := blob.ReadAt(data[:], 0); err != nil || string(data[:]) != "xat" {
		t.Fatalf("blob %q %v", data, err)
	}
	truncated := append([]byte(nil), input[:len(h)+2]...)
	if _, err := Read(bytes.NewReader(truncated), 2); err == nil {
		t.Fatal("accepted truncated short blob")
	}
}

func TestRejectMalformedRecords(t *testing.T) {
	good := record("data", []byte("payload"))
	cases := map[string]func([]byte) []byte{
		"header":           func(b []byte) []byte { b[0] = 'B'; return b },
		"short-header":     func(b []byte) []byte { binary.LittleEndian.PutUint16(b[4:], 7); return b },
		"unknown-encoding": func(b []byte) []byte { b[9] = 'Z'; return b },
		"path-bound":       func(b []byte) []byte { binary.LittleEndian.PutUint16(b[15:], 65535); return b },
		"blob-bound": func(b []byte) []byte {
			n := int(binary.LittleEndian.Uint16(b[4:]))
			binary.LittleEndian.PutUint32(b[n-4:], 0xffffffff)
			return b
		},
		"blob-truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":       func(b []byte) []byte { return append(b, 0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(mutate(bytes.Clone(good))), 10); err == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
	if _, err := Read(bytes.NewReader(append(bytes.Clone(good), good...)), 1); err == nil {
		t.Fatal("ignored entry bound")
	}
}
