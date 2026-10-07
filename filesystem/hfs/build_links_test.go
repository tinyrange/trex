package hfs

import (
	"bytes"
	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestBuildHFSXHardlinkInodes(t *testing.T) {
	entries := []BuildEntry{
		{Entry: unixfs.Entry{Path: "usr/bin/tool", Mode: unixfs.Regular | 0755, Data: bytes.NewReader([]byte("executable"))}},
		{Entry: unixfs.Entry{Path: "usr/bin/alias", Mode: unixfs.Regular | 0755, Target: "usr/bin/tool", Hardlink: true}},
		{Entry: unixfs.Entry{Path: "usr/bin/chain", Mode: unixfs.Regular | 0755, Target: "usr/bin/alias", Hardlink: true}},
	}
	r, err := Build(entries, BuildOptions{Size: 16 << 20, Label: "Links"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(starfile.NewReader("links", r), 100)
	if err != nil {
		t.Fatal(err)
	}
	var target string
	count := 0
	for _, e := range v.Entries {
		if e.Path == "/usr/bin/tool" || e.Path == "/usr/bin/alias" || e.Path == "/usr/bin/chain" {
			count++
			if e.Data.Size() != 10 || string(e.FinderInfo[:8]) != "hlnkhfs+" {
				t.Fatal("invalid native alias")
			}
			if target != "" && target != e.Target {
				t.Fatal("aliases do not share inode")
			}
			target = e.Target
		}
	}
	if count != 3 || target == "" {
		t.Fatal("missing hardlink aliases")
	}
	for _, e := range v.Entries {
		if e.Path == target && e.Special != 3 {
			t.Fatal("inode link count")
		}
	}
}
