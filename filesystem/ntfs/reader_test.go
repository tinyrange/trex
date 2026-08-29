package ntfs

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestNTFSMountMergesFileNameAttributesFromExtensionRecords(t *testing.T) {
	root := filesystemapi.New()
	content := []byte("shared through attribute-list extensions")
	for index := 0; index < 24; index++ {
		directory := fmt.Sprintf("/directory-%02d-with-a-long-name", index)
		name := directory + "/hard-link-with-a-long-name.bin"
		root.Mkdir(directory)
		root.PutFile(name, filesystemapi.FileRecord{Data: content, Size: int64(len(content))})
		root.SetMetadata(name, filesystemapi.Metadata{HardLink: 42})
	}
	image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "EXTENSIONS", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	var record uint64
	for index := 0; index < 24; index++ {
		name := fmt.Sprintf("/directory-%02d-with-a-long-name/hard-link-with-a-long-name.bin", index)
		node := volume.paths[name]
		if node == nil {
			t.Fatalf("mounted volume is missing %s", name)
		}
		if index == 0 {
			record = node.id
		} else if node.id != record {
			t.Fatalf("%s uses record %d, want shared record %d", name, node.id, record)
		}
	}
}

func TestNTFSReadOnlyMount(t *testing.T) {
	root := filesystemapi.New()
	root.Mkdir("/Windows")
	content := bytes.Repeat([]byte("trex"), 700)
	root.PutFile("/Windows/example.bin", filesystemapi.FileRecord{Data: content, Size: int64(len(content))})
	image, err := buildNTFSImage(root, 64<<20, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := volume.Get(starlark.String(`/windows/EXAMPLE.bin`))
	if err != nil || !found {
		t.Fatalf("lookup: found=%t err=%v", found, err)
	}
	got, err := io.ReadAll(io.NewSectionReader(value.(starfile.File), 0, value.(starfile.File).Size()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		mismatch := 0
		for mismatch < min(len(got), len(content)) && got[mismatch] == content[mismatch] {
			mismatch++
		}
		t.Fatalf("content differs at offset %d: got %d bytes, runs=%+v", mismatch, len(got), value.(*ntfsReadFile).runs)
	}
	if _, err := value.(starfile.File).WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("mounted file accepted a write")
	}
	extentsValue, err := value.(starlark.HasAttrs).Attr("extents")
	if err != nil {
		t.Fatal(err)
	}
	extents := extentsValue.(*starlark.List)
	if extents.Len() != 1 {
		t.Fatalf("extent count = %d, want 1", extents.Len())
	}
	extent := extents.Index(0).(*starfile.Record)
	if length, _ := starlark.AsInt32(extent.Get("length")); int64(length) != int64(len(content)) {
		t.Fatalf("extent length = %d, want %d", length, len(content))
	}
	if value, _ := extent.Attr("volume_offset"); value == nil {
		t.Fatal("allocated extent has no volume offset")
	}
}

func TestNTFSReadFileCrossesFragmentedAndSparseRuns(t *testing.T) {
	clusterSize := int64(4)
	volume := &starfile.Bytes{Name: "volume", Data: []byte("....ABCD....IJKL")}
	file := &ntfsReadFile{
		name:        "fragmented.bin",
		volume:      volume,
		clusterSize: clusterSize,
		size:        12,
		runs: []ntfsDataRun{
			{start: 1, length: 1},
			{length: 1, sparse: true},
			{start: 3, length: 1},
		},
	}
	got := make([]byte, 8)
	if n, err := file.ReadAt(got, 2); n != len(got) || err != nil {
		t.Fatalf("ReadAt: n=%d err=%v", n, err)
	}
	want := []byte{'C', 'D', 0, 0, 0, 0, 'I', 'J'}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadAt = %q, want %q", got, want)
	}
	extentsValue, err := file.Attr("extents")
	if err != nil {
		t.Fatal(err)
	}
	extents := extentsValue.(*starlark.List)
	if extents.Len() != 3 {
		t.Fatalf("extent count = %d, want 3", extents.Len())
	}
	sparse := extents.Index(1).(*starfile.Record)
	if sparse.Get("sparse") != starlark.True {
		t.Fatal("middle extent is not sparse")
	}
	if value, _ := sparse.Attr("volume_offset"); value != nil {
		t.Fatal("sparse extent exposes a physical volume offset")
	}
}

func TestNTFSReadFileExposesNamedStreams(t *testing.T) {
	stream := &ntfsReadFile{name: "example.bin:metadata", resident: []byte("stream"), size: 6}
	file := &ntfsReadFile{
		name:     "example.bin",
		resident: []byte("data"),
		size:     4,
		streams:  map[string]*ntfsReadFile{"metadata": stream},
	}
	value, err := file.Attr("streams")
	if err != nil {
		t.Fatal(err)
	}
	streams := value.(*starlark.Dict)
	got, found, err := streams.Get(starlark.String("metadata"))
	if err != nil || !found || got != stream {
		t.Fatalf("named stream lookup: got=%v found=%t err=%v", got, found, err)
	}
}
