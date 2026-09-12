package ziparchive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"testing"

	"go.starlark.net/starlark"
)

func TestEntryNameWithoutReadingPayload(t *testing.T) {
	entry := NewEntry(&zip.File{FileHeader: zip.FileHeader{Name: "images/ReactOS.iso", UncompressedSize64: 123}})
	name, err := entry.Attr("name")
	if err != nil || name != starlark.String("images/ReactOS.iso") {
		t.Fatalf("name=%v, error=%v", name, err)
	}
	if !slices.Contains(entry.AttrNames(), "name") || !slices.Contains(entry.AttrNames(), "size") {
		t.Fatal("metadata or file attributes missing")
	}
	if entry.reader != nil || len(entry.data) != 0 {
		t.Fatal("name lookup read archive data")
	}
}

func testEntry(t *testing.T, payload []byte, method uint16, corruptCRC bool) *Entry {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.CreateHeader(&zip.FileHeader{Name: "payload", Method: method})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	if corruptCRC {
		central := bytes.Index(data, []byte("PK\x01\x02"))
		binary.LittleEndian.PutUint32(data[central+16:], 0x12345678)
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return NewEntry(r.File[0])
}

func TestExactReadValidatesChecksum(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		payload := bytes.Repeat([]byte("data"), 123)
		f := testEntry(t, payload, method, false)
		got := make([]byte, len(payload))
		if n, err := f.ReadAt(got, 0); n != len(got) || err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("method %d: %d %v", method, n, err)
		}
		if !f.verified || f.Verify() != nil {
			t.Fatal("exact read did not validate CRC")
		}
		bad := testEntry(t, payload, method, true)
		if _, err := bad.ReadAt(got, 0); err == nil {
			t.Fatal("accepted bad CRC on exact-sized read")
		}
		if _, err := bad.ReadAt(got[:1], 0); err == nil {
			t.Fatal("served cached bytes after checksum failure")
		}
	}
}

func TestVerifyEmptyAndTruncatedEntry(t *testing.T) {
	oversized := NewEntry(&zip.File{FileHeader: zip.FileHeader{UncompressedSize64: 1 << 63}})
	if err := oversized.Verify(); err == nil {
		t.Fatal("accepted size outside signed file addressing range")
	}
	if err := testEntry(t, nil, zip.Store, false).Verify(); err != nil {
		t.Fatal(err)
	}
	if err := testEntry(t, nil, zip.Store, true).Verify(); err == nil {
		t.Fatal("accepted empty entry with bad checksum")
	}
	f := NewEntry(&zip.File{FileHeader: zip.FileHeader{Name: "short", UncompressedSize64: 5}})
	f.reader = io.NopCloser(bytes.NewReader([]byte("ab")))
	if _, err := f.ReadAt(make([]byte, 5), 0); err != io.ErrUnexpectedEOF {
		t.Fatalf("short reader: %v", err)
	}
}
