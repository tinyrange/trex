package cab

import (
	"bytes"
	"io"
	"testing"
)

func TestIndexedLZXCabinetMemberBoundaries(t *testing.T) {
	a, plain := largeLZXFixture()
	a.lzxCheckpointBytes = 2 << 20
	f := &Entry{archive: a, file: fileRecord{name: "member", uncompressedStart: 65500, size: 250000}}
	want := plain[65500:315500]
	for _, off := range []int{0, 70000, 240000, 1} {
		got := make([]byte, min(70000, len(want)-off))
		if n, err := f.ReadAt(got, int64(off)); n != len(got) || err != nil || !bytes.Equal(got, want[off:off+len(got)]) {
			t.Fatalf("read %d: %d %v", off, n, err)
		}
	}
	data, err := f.Bytes()
	if err != nil || !bytes.Equal(data, want) {
		t.Fatal("Bytes", err)
	}
	var out bytes.Buffer
	if _, err := f.WriteTo(&out); err != nil || !bytes.Equal(out.Bytes(), want) {
		t.Fatal("WriteTo", err)
	}
	if n, err := f.ReadAt(make([]byte, 10), f.Size()-3); n != 3 || err != io.EOF {
		t.Fatal("boundary", n, err)
	}
	bad := &Entry{archive: a, file: fileRecord{name: "bad", uncompressedStart: uint32(len(plain) - 2), size: 4}}
	if _, err := bad.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("member outside folder")
	}
	if a.cacheStore.Stats().Bytes != 0 {
		t.Fatal("indexed read retained whole folder")
	}
	a.ReleaseReadCaches()
	if a.lzxFolders[0].reader == nil {
		t.Fatal("handoff lost checkpoints")
	}
	data, err = f.Bytes()
	if err != nil || !bytes.Equal(data, want) {
		t.Fatal("read after release", err)
	}
}
