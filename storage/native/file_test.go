package native

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/block"
	"go.starlark.net/starlark"
)

type sparseOutputTestFile struct {
	data      []byte
	extents   []block.Extent
	bytesRead int
}

func (f *sparseOutputTestFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	f.bytesRead += n
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *sparseOutputTestFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("read-only")
}

func (f *sparseOutputTestFile) Extents(off, length int64) ([]block.Extent, error) {
	if off != 0 || length != int64(len(f.data)) {
		return nil, fmt.Errorf("unexpected range")
	}
	return append([]block.Extent(nil), f.extents...), nil
}

func (f *sparseOutputTestFile) Size() int64           { return int64(len(f.data)) }
func (f *sparseOutputTestFile) String() string        { return "<sparse test file>" }
func (f *sparseOutputTestFile) Type() string          { return "file" }
func (f *sparseOutputTestFile) Freeze()               {}
func (f *sparseOutputTestFile) Truth() starlark.Bool  { return starlark.True }
func (f *sparseOutputTestFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable") }
func (f *sparseOutputTestFile) Attr(string) (starlark.Value, error) {
	return nil, nil
}
func (f *sparseOutputTestFile) AttrNames() []string { return nil }

func TestWriteFileToPreservesSparseExtents(t *testing.T) {
	want := make([]byte, 1<<20)
	copy(want[:3], "MBR")
	copy(want[len(want)-3:], "END")
	file := &sparseOutputTestFile{
		data: want,
		extents: []block.Extent{
			{Offset: 0, Length: 3, Allocated: true},
			{Offset: 3, Length: int64(len(want) - 6), Allocated: false},
			{Offset: int64(len(want) - 3), Length: 3, Allocated: true},
		},
	}
	name := filepath.Join(t.TempDir(), "disk.raw")
	out, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOutputFileTo(out, file); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if file.bytesRead != 6 {
		t.Fatalf("read %d source bytes, want only 6 allocated bytes", file.bytesRead)
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("sparse output contents differ")
	}
}
