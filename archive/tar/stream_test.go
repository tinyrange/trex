package tararchive

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
)

type unknownFile struct {
	data    []byte
	highest int64
}

func (*unknownFile) Size() int64              { panic("stream size must not be requested") }
func (*unknownFile) KnownSize() (int64, bool) { return 0, false }
func (f *unknownFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	f.highest = max(f.highest, off+int64(n))
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func TestStreamingPagesDoNotReadPayloadOrTotal(t *testing.T) {
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	for _, name := range []string{"same", "same", "nested/file"} {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 9 << 20}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, 9<<20)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	source := &unknownFile{data: data.Bytes()}
	node := auto.Open(source, "stream", auto.Options{})
	page, next, total, done, err := node.ChildPage(0, 500)
	if err != nil || len(page) != 1 || next != 1 || total != 1 || done {
		t.Fatalf("%v %d %d %v %v", page, next, total, done, err)
	}
	if source.highest > 64<<10 {
		t.Fatal("eager payload decoding", source.highest)
	}
	first, err := node.Resolve("1")
	if err != nil || first.Reader().Size() != 9<<20 {
		t.Fatal(first, err)
	}
	if source.highest > 64<<10 {
		t.Fatal("resolve decoded payload")
	}
	page, next, _, _, err = node.ChildPage(1, 1)
	if err != nil || next != 2 || page[0].Summary().Attributes["original_path"] != "same" {
		t.Fatal(page, next, err)
	}
	if source.highest > int64(9<<20)+1024 {
		t.Fatal("read beyond next header", source.highest)
	}
	if _, err := node.Resolve("3"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamingTruncationAndEntryLimit(t *testing.T) {
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	_ = w.WriteHeader(&tar.Header{Name: "truncated", Size: 100, Mode: 0600})
	v := newStreamView(&unknownFile{data: data.Bytes()}, 10)
	if p, err := v.Page(0, 1); err != nil || len(p.Entries) != 1 {
		t.Fatal(p, err)
	}
	if _, err := v.Page(1, 1); err == nil {
		t.Fatal("accepted truncated payload")
	}
	if _, err := v.Page(-1, 1); err == nil {
		t.Fatal("accepted invalid cursor")
	}
}
