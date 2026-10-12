package ufs

import (
	"context"
	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestBuildFFSMetadataAndIndirectPayload(t *testing.T) {
	payload := strings.Repeat("large-payload", 20000) // exceeds 12 direct blocks
	input := []unixfs.Entry{
		{Path: "bin/run", Mode: unixfs.Regular | 04755, UID: 70000, GID: 80000, Mtime: 12345, Data: &starfile.Bytes{Data: []byte(payload)}},
		{Path: "bin/alias", Mode: unixfs.Regular | 04755, UID: 70000, GID: 80000, Mtime: 12345, Hardlink: true, Target: "bin/run"},
		{Path: "tmp", Mode: unixfs.Directory | 01777},
		{Path: "link", Mode: unixfs.Symlink | 0777, Target: "bin/run"},
		{Path: "dev/console", Mode: unixfs.Character | 0600, Major: 12, Minor: 0x1234},
	}
	image, err := Build(context.Background(), input, BuildOptions{Layout: "raw", Timestamp: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := Open(starfile.NewReader("image", image), 100, 10000)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]Entry{}
	for _, entry := range volume.Entries {
		entries[entry.Path] = entry
	}
	file := entries["/bin/run"]
	if file.Mode != 0104755 || file.UID != 70000 || file.GID != 80000 || file.Modified != 12345 || file.Links != 2 {
		t.Fatalf("metadata: %+v", file)
	}
	if entries["/bin/alias"].Inode != file.Inode {
		t.Fatal("hardlink is not shared")
	}
	data, err := starfile.ReadAll(file.Data)
	if err != nil || string(data) != payload {
		t.Fatalf("payload: %v, %d bytes", err, len(data))
	}
	link, err := starfile.ReadAll(entries["/link"].Data)
	if err != nil || string(link) != "bin/run" {
		t.Fatalf("symlink: %s %v", link, err)
	}
	if entries["/tmp"].Mode != 0041777 {
		t.Fatalf("sticky directory lost: %#o", entries["/tmp"].Mode)
	}
	if entries["/dev/console"].Device != 0x120c34 {
		t.Fatalf("device: %#x", entries["/dev/console"].Device)
	}
}

func TestBuildFFSRejectsInvalidInputs(t *testing.T) {
	for _, opts := range []BuildOptions{{Layout: "bad"}, {Layout: "raw", Size: -1}, {Layout: "raw", Extra: -1}} {
		if _, err := Build(context.Background(), nil, opts); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
	if _, err := Build(context.Background(), []unixfs.Entry{{Path: "../escape", Mode: unixfs.Regular}}, BuildOptions{Layout: "raw"}); err == nil {
		t.Fatal("accepted traversal")
	}
	if _, err := Build(context.Background(), []unixfs.Entry{{Path: "big", Mode: unixfs.Regular, Data: &starfile.Bytes{Data: make([]byte, 8<<20)}}}, BuildOptions{Layout: "raw", Size: 1 << 20}); err == nil {
		t.Fatal("accepted undersized image")
	}
}
