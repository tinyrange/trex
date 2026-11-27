package efs

import (
	"bytes"
	"testing"

	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestBuildEFS(t *testing.T) {
	data := bytes.Repeat([]byte("extent data 01234"), 228000)
	root := unixfs.Entry{Path: "usr/bin/demo", Mode: unixfs.Regular | 0755, UID: 10, GID: 20, Mtime: 650000000}
	hard := root
	hard.Path, hard.Target, hard.Hardlink = "bin/other", root.Path, true
	root.Data = &starfile.Bytes{Data: data}
	input := []unixfs.Entry{
		root, hard,
		{Path: "bin/demo", Mode: unixfs.Symlink | 0777, Target: "/usr/bin/demo"},
		{Path: "dev/console", Mode: unixfs.Character | 0600, Major: 8, Minor: 1},
		{Path: "dev/later", Mode: unixfs.Block | 0600, Major: 200, Minor: 500},
	}
	image, err := Build(input, 16<<20, "root", 650000000)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(image, 500)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]Entry{}
	for _, e := range v.Entries {
		m[e.Path] = e
	}
	exe, link := m["/usr/bin/demo"], m["/bin/other"]
	if exe.Inode == 0 || exe.Inode != link.Inode || exe.Mode != 0100755 || exe.UID != 10 || exe.GID != 20 {
		t.Fatalf("executable or hardlink metadata: %+v, %+v", exe, link)
	}
	got, err := starfile.ReadAll(exe.Data)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("indirect file data differs: %d bytes, %v", len(got), err)
	}
	symlink, err := starfile.ReadAll(m["/bin/demo"].Data)
	if err != nil || string(symlink) != "/usr/bin/demo" {
		t.Fatalf("symlink data = %q, %v", symlink, err)
	}
	for name, numbers := range map[string][2]uint32{"/dev/console": {8, 1}, "/dev/later": {200, 500}} {
		if e := m[name]; e.Data != nil || [2]uint32{e.Major, e.Minor} != numbers {
			t.Fatalf("device %q metadata: %+v", name, e)
		}
	}
}
