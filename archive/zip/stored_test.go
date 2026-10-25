package ziparchive

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

type countingReaderAt struct {
	io.ReaderAt
	bytes int64
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, off)
	r.bytes += int64(n)
	return n, err
}

// A nested MSIX central directory and payload alternate between distant ranges.
// Assert source I/O, not elapsed time: a decoded-window replay used to read the
// entire stored member repeatedly even though it requires no decompression.
func TestStoredRandomReadsDoNotReplay(t *testing.T) {
	payload := make([]byte, 3*decodedWindow+317)
	for i := range payload {
		payload[i] = byte(i*31 + i/997)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	member, err := zw.CreateHeader(&zip.FileHeader{Name: "nested.msix", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = member.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	source := &countingReaderAt{ReaderAt: bytes.NewReader(buf.Bytes())}
	zr, err := zip.NewReader(source, int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	entry := NewEntry(zr.File[0])
	if err = entry.Verify(); err != nil {
		t.Fatal(err)
	}
	before := source.bytes
	for i := 0; i < 16; i++ {
		off := int64(13)
		if i%2 == 0 {
			off = int64(len(payload) - 64)
		}
		got := make([]byte, 64)
		n, err := entry.ReadAt(got, off)
		if n != len(got) || err != nil || !bytes.Equal(got, payload[off:off+64]) {
			t.Fatalf("read %d: n=%d err=%v", i, n, err)
		}
	}
	if delta := source.bytes - before; delta > 16*64 {
		t.Fatalf("random reads replayed stored payload: %d source bytes for 1024 requested bytes", delta)
	}
	if len(entry.data) != 0 {
		t.Fatalf("stored entry retained %d decoded bytes", len(entry.data))
	}
}

func TestStoredPartialReadRejectsCorruption(t *testing.T) {
	// Checking just the requested page must not make the fast path skip CRC.
	f := testEntry(t, bytes.Repeat([]byte("stored data"), 1024), zip.Store, true)
	if _, err := f.ReadAt(make([]byte, 8), 3); err != zip.ErrChecksum {
		t.Fatalf("partial corrupt read: %v", err)
	}
	if err := f.Verify(); err != zip.ErrChecksum {
		t.Fatalf("lost sticky checksum error: %v", err)
	}
}
