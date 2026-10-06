package ext4

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"io"
	"math/bits"
	"strings"
	"testing"
)

func imageBytes(t *testing.T, entries []unixfs.Entry, size int64) []byte {
	t.Helper()
	r, err := Build(entries, BuildOptions{Size: size, Label: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestBuildUnixMetadataAndAllocationInvariants(t *testing.T) {
	input := []unixfs.Entry{{Path: "bin/tool", Mode: 0104755, UID: 123456, GID: 789012, Mtime: 12345, Data: bytes.NewReader([]byte("hello"))}, {Path: "alias", Mode: 0104755, UID: 123456, GID: 789012, Mtime: 12345, Target: "bin/tool", Hardlink: true}, {Path: "short", Mode: 0120777, Target: "/bin/tool"}, {Path: "long", Mode: 0120777, Target: "/" + strings.Repeat("long/", 30)}, {Path: "dev/node", Mode: 0020660, Major: 511, Minor: 65537}, {Path: "pipe", Mode: 0010600}}
	b := imageBytes(t, input, 256<<20)
	// Independent bitmap accounting across two groups checks builder bookkeeping,
	// including backup metadata and reserved inodes, not just reader/writer agreement.
	sb := b[1024:2048]
	groups := (u32(sb, 4) + 32767) / 32768
	var freeB, freeI uint32
	for g := uint32(0); g < groups; g++ {
		desc := b[4096+g*32:][:32]
		bitmap := b[int(u32(desc, 0))*4096:][:4096]
		ibitmap := b[int(u32(desc, 4))*4096:][:4096]
		allocated, iallocated := 0, 0
		for _, v := range bitmap {
			allocated += bits.OnesCount8(v)
		}
		for _, v := range ibitmap {
			iallocated += bits.OnesCount8(v)
		}
		fb, fi := uint32(32768-allocated), uint32(32768-iallocated)
		if fb != uint32(u16(desc, 12)) || fi != uint32(u16(desc, 14)) {
			t.Fatal("bitmap free count disagreement", g, fb, fi, desc)
		}
		freeB += fb
		freeI += fi
		if g > 0 {
			backup := b[int(g)*32768*4096:][:1024]
			if u16(backup, 56) != 0xef53 || u16(backup, 90) != uint16(g) {
				t.Fatal("invalid backup superblock")
			}
		}
	}
	if freeB != u32(sb, 12) || freeI != u32(sb, 16) {
		t.Fatal("superblock free counts")
	}
	root := auto.Open(bytes.NewReader(b), "root.ext4", auto.Options{})
	tool, err := root.Resolve("bin/tool")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := root.Resolve("alias")
	if err != nil {
		t.Fatal(err)
	}
	m := tool.Summary().Attributes
	if m["mode"] != uint32(0104755) || m["uid"] != uint32(123456) || m["gid"] != uint32(789012) || m["mtime"] != uint32(12345) || m["nlink"] != uint32(2) {
		t.Fatal(m)
	}
	if m["inode"] != alias.Summary().Attributes["inode"] {
		t.Fatal("hardlinks do not share inode")
	}
	data, err := io.ReadAll(io.NewSectionReader(alias.Reader(), 0, alias.Reader().Size()))
	if err != nil || string(data) != "hello" {
		t.Fatal(string(data), err)
	}
	for _, name := range []string{"short", "long"} {
		node, err := root.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		if node.Summary().Kind != "symlink" || node.Reader() != nil {
			t.Fatal("symlink followed")
		}
	}
	dev, err := root.Resolve("dev/node")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Summary().Attributes["major"] != uint32(511) || dev.Summary().Attributes["minor"] != uint32(65537) {
		t.Fatal(dev.Summary())
	}
}

type patternFile int64

func (p patternFile) Size() int64 { return int64(p) }
func (p patternFile) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("offset")
	}
	if off >= int64(p) {
		return 0, io.EOF
	}
	n := int(min(int64(len(b)), int64(p)-off))
	for i := 0; i < n; i++ {
		b[i] = byte((off + int64(i)) * 17)
	}
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}
func TestLazyLargeFileMultiLevelExtentsAndMultiBlockDirectory(t *testing.T) {
	input := []unixfs.Entry{{Path: "large", Mode: 0100644, Data: patternFile(600 << 20)}}
	for i := 0; i < 600; i++ {
		input = append(input, unixfs.Entry{Path: fmt.Sprintf("dir/file-%04d", i), Mode: 0100644, Data: bytes.NewReader([]byte("x"))})
	}
	r, err := Build(input, BuildOptions{Size: 768 << 20})
	if err != nil {
		t.Fatal(err)
	}
	root := auto.Open(r, "", auto.Options{})
	large, err := root.Resolve("large")
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, (128 << 20) - 16, 128 << 20, 599 << 20, (600 << 20) - 31} {
		want, got := make([]byte, 31), make([]byte, 31)
		patternFile(600<<20).ReadAt(want, off)
		if _, err := large.Reader().ReadAt(got, off); err != nil || !bytes.Equal(want, got) {
			t.Fatal(off, err)
		}
	}
	dir, err := root.Resolve("dir")
	if err != nil {
		t.Fatal(err)
	}
	children, err := dir.Children()
	if err != nil || len(children) != 600 {
		t.Fatal(len(children), err)
	}
}

// A hand-authored ext2 fixture exercises a reader layout the writer does not
// produce: 1024-byte blocks, 128-byte inodes and direct + indirect pointers.
func ext2Fixture() []byte {
	b := make([]byte, 64*1024)
	sb := b[1024:2048]
	put32(sb, 0, 16)
	put32(sb, 4, 64)
	put32(sb, 20, 1)
	put32(sb, 32, 64)
	put32(sb, 40, 16)
	put16(sb, 56, 0xef53)
	desc := b[2048:2080]
	put32(desc, 8, 3)
	root := b[3*1024+128:][:128]
	put16(root, 0, 0040755)
	put32(root, 4, 1024)
	put16(root, 26, 2)
	put32(root, 40, 5)
	file := b[3*1024+10*128:][:128]
	put16(file, 0, 0100644)
	put32(file, 4, 14*1024)
	put16(file, 26, 1)
	put32(file, 40, 6)
	put32(file, 88, 7)
	dir := b[5*1024:][:1024]
	put32(dir, 0, 2)
	put16(dir, 4, 12)
	put16(dir, 6, 1)
	dir[8] = '.'
	put32(dir, 12, 2)
	put16(dir, 16, 12)
	put16(dir, 18, 2)
	copy(dir[20:], "..")
	put32(dir, 24, 11)
	put16(dir, 28, 1000)
	put16(dir, 30, 4)
	copy(dir[32:], "file")
	copy(b[6*1024:], "direct")
	put32(b[7*1024:], 0, 8)
	put32(b[7*1024:], 4, 9)
	copy(b[8*1024:], "indirect-a")
	copy(b[9*1024:], "indirect-b")
	return b
}
func TestIndependentExt2AndSparseIndirectReads(t *testing.T) {
	b := ext2Fixture()
	root := auto.Open(bytes.NewReader(b), "", auto.Options{})
	file, err := root.Resolve("file")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		off  int64
		text string
	}{{0, "direct"}, {1024, "\x00\x00\x00"}, {12 * 1024, "indirect-a"}, {13 * 1024, "indirect-b"}} {
		got := make([]byte, len(x.text))
		if _, err := file.Reader().ReadAt(got, x.off); err != nil || string(got) != x.text {
			t.Fatal(x, got, err)
		}
	}
	// Invalid physical pointers are rejected rather than reading outside the disk.
	put32(b[7*1024:], 0, 65)
	file, err = auto.Open(bytes.NewReader(b), "", auto.Options{}).Resolve("file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Reader().ReadAt(make([]byte, 1), 12*1024); err == nil {
		t.Fatal("invalid pointer accepted")
	}
}
func TestMalformedImagesAndLimits(t *testing.T) {
	original := imageBytes(t, []unixfs.Entry{{Path: "a/b", Mode: 0100644}}, 8<<20)
	for _, mutate := range []func([]byte){func(b []byte) { put32(b[1024:], 96, 0x4) }, func(b []byte) { put32(b[1024:], 24, 31) }, func(b []byte) { put32(b[1024:], 72, 1) }, func(b []byte) { put32(b[4096:], 8, 999999) }} {
		b := append([]byte(nil), original...)
		mutate(b)
		root := auto.Open(bytes.NewReader(b), "", auto.Options{})
		if _, err := root.Children(); err == nil {
			t.Fatal("malformed volume accepted")
		}
	}
	for _, size := range []int64{1, 8<<20 + 1, -1} {
		if _, err := Build(nil, BuildOptions{Size: size}); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	root := auto.Open(bytes.NewReader(original), "", auto.Options{MaxDepth: 1})
	if _, err := root.Resolve("a/b"); err == nil {
		t.Fatal("depth bound ignored")
	}
}

var _ storage.Reader = patternFile(0)
