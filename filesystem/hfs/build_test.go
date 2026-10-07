package hfs

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestBuildHFSXNativeMetadataAndIndexLookup(t *testing.T) {
	data := []byte("borrowed app payload")
	entries := []BuildEntry{
		{Entry: unixfs.Entry{Path: ".", Mode: unixfs.Directory | 0755, Mtime: 1345765197}},
		{Entry: unixfs.Entry{Path: "Applications/App", Mode: unixfs.Regular | 0755, UID: 501, GID: 20, Data: bytes.NewReader(data), Mtime: 1345765197}, FinderInfo: make([]byte, 32), Resource: bytes.NewReader([]byte("resource")), Xattrs: map[string]storage.Reader{"com.example.inline": bytes.NewReader([]byte("attr")), "com.example.large": bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4097))}},
		{Entry: unixfs.Entry{Path: "alias", Mode: unixfs.Symlink | 0777, Target: "Applications/App"}},
		{Entry: unixfs.Entry{Path: "dev/console", Mode: unixfs.Character | 0600, Major: 3, Minor: 0x123456}},
	}
	for i := 0; i < 1000; i++ {
		entries = append(entries, BuildEntry{Entry: unixfs.Entry{Path: fmt.Sprintf("many/file%04d", i), Mode: unixfs.Regular | 0644, Data: bytes.NewReader(nil)}})
	}
	image, err := Build(entries, BuildOptions{Size: 32 << 20, Label: "Lion"})
	if err != nil {
		t.Fatal(err)
	}
	file := starfile.NewReader("image", image)
	v, err := Open(file, 2000)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]Entry{}
	for _, e := range v.Entries {
		found[e.Path] = e
	}
	app := found["/Applications/App"]
	if app.Mode != 0100755 || app.UID != 501 || app.GID != 20 || app.Modified != 1345765197+hfsEpoch {
		t.Fatalf("metadata %+v", app)
	}
	data[0] = 'B'
	b, err := io.ReadAll(io.NewSectionReader(app.Data, 0, app.Data.Size()))
	if err != nil || string(b) != "Borrowed app payload" {
		t.Fatalf("data %q %v", b, err)
	}
	if app.Resource.Size() != 8 || app.Xattrs["com.example.large"].Size() != 4097 || found["/alias"].Target != "Applications/App" || found["/dev/console"].Special != 0x03123456 {
		t.Fatal("native forks, attributes or special metadata lost")
	}
	// Independently walk catalog index keys as a guest does: the greatest key
	// <= the target selects the child. Leaf enumeration alone cannot prove this.
	header := make([]byte, 512)
	image.ReadAt(header, 1024)
	r := plusReader{file: file, block: 4096, blocks: 8192, overflow: map[plusKey][]plusExtent{}}
	catalog, err := r.fork(4, 0, header[272:352])
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, treeNodeSize)
	catalog.ReadAt(first, 0)
	depth := be.Uint16(first[14:])
	root := be.Uint32(first[16:])
	if depth < 2 {
		t.Fatal("catalog did not exercise index levels")
	}
	want := catalogKey(found["/many"].ID, []uint16{'f', 'i', 'l', 'e', '0', '7', '5', '0'})
	compare := func(a, b []byte) int {
		if be.Uint32(a[2:]) < be.Uint32(b[2:]) {
			return -1
		}
		if be.Uint32(a[2:]) > be.Uint32(b[2:]) {
			return 1
		}
		return bytes.Compare(a[8:2+int(be.Uint16(a))], b[8:2+int(be.Uint16(b))])
	}
	id := root
	for level := depth; level > 0; level-- {
		node := make([]byte, treeNodeSize)
		if _, err := catalog.ReadAt(node, int64(id)*treeNodeSize); err != nil {
			t.Fatal(err)
		}
		count := int(be.Uint16(node[10:]))
		var child uint32
		matched := false
		for i := 0; i < count; i++ {
			off := int(be.Uint16(node[treeNodeSize-2*(i+1):]))
			end := int(be.Uint16(node[treeNodeSize-2*(i+2):]))
			rec := node[off:end]
			keySize := 2 + int(be.Uint16(rec))
			cmp := compare(rec[:keySize], want)
			if level == 1 && cmp == 0 {
				matched = true
				break
			}
			if level > 1 && cmp <= 0 {
				child = be.Uint32(rec[keySize:])
			}
		}
		if level == 1 {
			if !matched {
				t.Fatal("guest-style catalog lookup failed")
			}
		} else {
			if child == 0 {
				t.Fatal("invalid index child")
			}
			id = child
		}
	}
	alternate := make([]byte, 512)
	image.ReadAt(alternate, image.Size()-1024)
	if !bytes.Equal(header, alternate) {
		t.Fatal("alternate volume header differs")
	}
	bitmap, err := r.fork(6, 0, header[112:192])
	if err != nil {
		t.Fatal(err)
	}
	bits := make([]byte, bitmap.Size())
	bitmap.ReadAt(bits, 0)
	var allocated uint32
	for i := uint32(0); i < r.blocks; i++ {
		if bits[i/8]&(0x80>>uint(i%8)) != 0 {
			allocated++
		}
	}
	if r.blocks-allocated != be.Uint32(header[48:]) {
		t.Fatal("allocation bitmap accounting mismatch")
	}
}
func TestBuildHFSXRejectsInvalidConstruction(t *testing.T) {
	for _, entries := range [][]BuildEntry{
		{{Entry: unixfs.Entry{Path: "../escape", Mode: unixfs.Regular | 0644}}},
		{{Entry: unixfs.Entry{Path: "a", Mode: unixfs.Regular | 0644}}, {Entry: unixfs.Entry{Path: "a/b", Mode: unixfs.Regular | 0644}}},
		{{Entry: unixfs.Entry{Path: "é", Mode: unixfs.Regular | 0644}}, {Entry: unixfs.Entry{Path: "é", Mode: unixfs.Regular | 0644}}},
		{{Entry: unixfs.Entry{Path: "a", Mode: unixfs.Regular | 0644, Hardlink: true, Target: "b"}}},
	} {
		if _, err := Build(entries, BuildOptions{Size: 16 << 20, Label: "Test"}); err == nil {
			t.Fatal("accepted invalid construction")
		}
	}
}
