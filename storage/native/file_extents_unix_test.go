//go:build linux || darwin || freebsd

package native

import (
	"os"
	"testing"
)

func TestOpenFileExtentsCoverClippedRange(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sparse")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const size = 1 << 20
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	const data = size / 2
	if _, err := f.WriteAt([]byte{0x9d}, data); err != nil {
		t.Fatal(err)
	}
	src := osFile{file: f, size: size}
	const start, end = 67, size - 111
	ranges, err := src.Extents(start, end-start)
	if err != nil {
		t.Fatal(err)
	}
	pos := int64(start)
	found := false
	for _, r := range ranges {
		if r.Offset != pos || r.Length <= 0 {
			t.Fatalf("unexpected extent at %d: %+v", pos, r)
		}
		pos += r.Length
		if r.Offset <= data && data < pos {
			found = r.Allocated
		}
	}
	if pos != end || !found {
		t.Fatalf("missing coverage or allocated data: %+v", ranges)
	}
	if ranges, err := src.Extents(size, 0); err != nil || len(ranges) != 0 {
		t.Fatalf("empty range at EOF: %+v, %v", ranges, err)
	}
	if _, err := src.Extents(size, 1); err == nil {
		t.Fatal("accepted extent request past EOF")
	}
}
