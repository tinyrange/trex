package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
)

func legacyTestRecord(name, short string, attrs uint32, ref uint64, streams uint16) []byte {
	wide := func(s string) []byte {
		var b []byte
		for _, c := range s {
			b = binary.LittleEndian.AppendUint16(b, uint16(c))
		}
		return b
	}
	n, s := wide(name), wide(short)
	size := 64 + len(n)
	if len(s) > 0 {
		size += len(s) + 2
	}
	b := make([]byte, align8(size))
	binary.LittleEndian.PutUint64(b, uint64(len(b)))
	binary.LittleEndian.PutUint32(b[8:], attrs)
	binary.LittleEndian.PutUint32(b[12:], ^uint32(0))
	binary.LittleEndian.PutUint64(b[16:], ref)
	binary.LittleEndian.PutUint64(b[24:], 1234)
	binary.LittleEndian.PutUint64(b[32:], 2345)
	binary.LittleEndian.PutUint64(b[40:], 3456)
	binary.LittleEndian.PutUint16(b[56:], streams)
	binary.LittleEndian.PutUint16(b[58:], uint16(len(s)))
	binary.LittleEndian.PutUint16(b[60:], uint16(len(n)))
	copy(b[62:], n)
	copy(b[64+len(n):], s)
	return b
}

func legacyTestStream(name string, id uint32) []byte {
	b := make([]byte, align8(20+len(name)*2))
	binary.LittleEndian.PutUint64(b, uint64(len(b)))
	binary.LittleEndian.PutUint32(b[8:], id)
	binary.LittleEndian.PutUint16(b[16:], uint16(len(name)*2))
	for i, c := range name {
		binary.LittleEndian.PutUint16(b[18+i*2:], uint16(c))
	}
	return b
}

func legacyTestArchive(metadata []byte, payloads ...[]byte) []byte {
	data := make([]byte, 96)
	copy(data, []byte("MSWIM\x00\x00\x00"))
	binary.LittleEndian.PutUint32(data[8:], 96)
	binary.LittleEndian.PutUint32(data[12:], 0x10a00)
	binary.LittleEndian.PutUint32(data[20:], 32768)
	var lookup []byte
	for i, payload := range append(payloads, metadata) {
		r := make([]byte, 52)
		binary.LittleEndian.PutUint64(r, uint64(len(payload)))
		if i == len(payloads) {
			r[7] = wimResourceMetadata
		}
		binary.LittleEndian.PutUint64(r[8:], uint64(len(data)))
		binary.LittleEndian.PutUint64(r[16:], uint64(len(payload)))
		binary.LittleEndian.PutUint32(r[24:], uint32(i+1))
		binary.LittleEndian.PutUint32(r[28:], 1)
		hash := sha1.Sum(payload)
		copy(r[32:], hash[:])
		lookup = append(lookup, r...)
		data = append(data, payload...)
	}
	binary.LittleEndian.PutUint64(data[24:], uint64(len(lookup)))
	binary.LittleEndian.PutUint64(data[32:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[40:], uint64(len(lookup)))
	return append(data, lookup...)
}

func TestLegacyWIMNumericStreamsAndFlatRoot(t *testing.T) {
	meta := make([]byte, 8)
	dir := legacyTestRecord("Folder", "", 0x10, 0, 0)
	binary.LittleEndian.PutUint64(dir[16:], uint64(8+len(dir)+8))
	meta = append(meta, dir...)
	meta = append(meta, make([]byte, 8)...)
	meta = append(meta, legacyTestRecord("Long filename.txt", "LONGFI~1.TXT", 0x20, 0, 2)...)
	meta = append(meta, legacyTestStream("", 1)...)
	meta = append(meta, legacyTestStream("Zone.Identifier", 2)...)
	meta = append(meta, make([]byte, 8)...)
	w, err := Open(&countingWIMFile{data: legacyTestArchive(meta, []byte("main"), []byte("zone"))})
	if err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenFile("/image1/folder/long filename.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil || string(b) != "main" {
		t.Fatalf("main stream: %q %v", b, err)
	}
	root := filesystem.New()
	_, err = w.applyBuiltin(nil, nil, starlark.Tuple{root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := root.Snapshot()
	m := snapshot.Metadata["/Folder/Long filename.txt"]
	if m.ShortName != "LONGFI~1.TXT" || m.CreationTime != 1234 || len(m.NamedStreams) != 1 {
		t.Fatalf("metadata: %+v", m)
	}
	s := m.NamedStreams["Zone.Identifier"]
	b, err = io.ReadAll(io.NewSectionReader(s, 0, s.Size()))
	if err != nil || string(b) != "zone" {
		t.Fatalf("named stream: %q %v", b, err)
	}
	// The ID is not a directory pointer merely because it is nonzero.
	if children, err := w.List("/image1/Folder"); err != nil || len(children) != 1 || children[0].Directory {
		t.Fatalf("children: %+v %v", children, err)
	}
}

func TestLegacyWIMRejectsMissingNumericResource(t *testing.T) {
	meta := append(make([]byte, 8), legacyTestRecord("missing", "", 0x20, 77, 0)...)
	meta = append(meta, make([]byte, 8)...)
	w, err := Open(&countingWIMFile{data: legacyTestArchive(meta)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.List("/image1"); err == nil {
		t.Fatal("accepted missing resource")
	}
}

func TestLegacyWIMEmptyFileDoesNotAliasUnhashedMetadata(t *testing.T) {
	meta := append(make([]byte, 8), legacyTestRecord("empty", "", 0x20, 0, 0)...)
	meta = append(meta, make([]byte, 8)...)
	data := legacyTestArchive(meta)
	// Old image metadata has no stored SHA-1 on this generation's media.
	clear(data[len(data)-20:])
	w, err := Open(&countingWIMFile{data: data})
	if err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenFile("/image1/empty")
	if err != nil || f.Size() != 0 {
		t.Fatalf("empty file: %v %v", f, err)
	}
}

func TestLegacySecurityLengthsAndBounds(t *testing.T) {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data, 3)
	binary.LittleEndian.PutUint32(data[4:], 2)
	binary.LittleEndian.PutUint32(data[8:], 4)
	copy(data[16:], []byte("abcdefg"))
	s, root, err := legacySecurity(data)
	if err != nil || root != 24 || len(s) != 2 || !bytes.Equal(s[1], []byte("defg")) {
		t.Fatalf("security: %q %d %v", s, root, err)
	}
	binary.LittleEndian.PutUint32(data[8:], 1000)
	if _, _, err = legacySecurity(data); err == nil {
		t.Fatal("accepted descriptor past input")
	}
}
