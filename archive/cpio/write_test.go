package cpio

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"io"
	"strings"
	"testing"
)

type countedPayload struct{ reads int }

func (r *countedPayload) Size() int64 { return 7 }
func (r *countedPayload) ReadAt(p []byte, o int64) (int, error) {
	r.reads++
	return bytes.NewReader([]byte("payload")).ReadAt(p, o)
}
func TestBuildNewcMetadataAndLinuxHardlinks(t *testing.T) {
	payload := &countedPayload{}
	entries := []unixfs.Entry{
		{Path: "z/file", Mode: 0104755, UID: 70000, GID: 80000, Mtime: 123, Data: payload},
		{Path: "a-link", Mode: 0104755, UID: 70000, GID: 80000, Mtime: 123, Target: "z/file", Hardlink: true},
		{Path: "sym", Mode: 0120777, Target: "/z/file"},
		{Path: "dev/console", Mode: 0020600, Major: 5, Minor: 1},
	}
	r, err := Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	if payload.reads != 0 {
		t.Fatal("builder read payload")
	}
	b, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		t.Fatal(err)
	}
	// Independently walk raw headers, not the production reader: Linux needs the
	// final hardlink record to carry the group payload and every field is 32-bit.
	records := map[string][]uint32{}
	contents := map[string]string{}
	var order []string
	for at := 0; at < len(b); {
		if string(b[at:at+6]) != "070701" {
			t.Fatal("wrong magic")
		}
		fields := make([]uint32, 13)
		for i := range fields {
			if _, err := fmt.Sscanf(string(b[at+6+i*8:at+14+i*8]), "%08x", &fields[i]); err != nil {
				t.Fatal(err)
			}
		}
		name := string(b[at+110 : at+110+int(fields[11])-1])
		data := (at + 110 + int(fields[11]) + 3) &^ 3
		records[name] = fields
		contents[name] = string(b[data : data+int(fields[6])])
		order = append(order, name)
		at = (data + int(fields[6]) + 3) &^ 3
	}
	if order[len(order)-1] != "TRAILER!!!" {
		t.Fatal(order)
	}
	a, z := records["a-link"], records["z/file"]
	if a[0] != z[0] || a[4] != 2 || z[4] != 2 || contents["a-link"] != "" || contents["z/file"] != "payload" {
		t.Fatal("Linux hardlink emission", records, contents)
	}
	if z[1] != 0104755 || z[2] != 70000 || z[3] != 80000 || z[5] != 123 {
		t.Fatal(z)
	}
	dev := records["dev/console"]
	if dev[9] != 5 || dev[10] != 1 {
		t.Fatal(dev)
	}
	for _, dir := range []string{".", "dev", "z"} {
		if records[dir][1]&0170000 != 0040000 {
			t.Fatal("parent missing", dir)
		}
	}
	root := auto.Open(r, "initramfs", auto.Options{})
	node, err := root.Resolve("a-link")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(node.Reader(), 0, node.Reader().Size()))
	if err != nil || string(data) != "payload" {
		t.Fatal(string(data), err)
	}
	rebuilt, err := Build(entries)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := io.ReadAll(io.NewSectionReader(rebuilt, 0, rebuilt.Size()))
	if !bytes.Equal(b, again) {
		t.Fatal("nondeterministic image")
	}
}
func TestBuildRejectsUnsafeAndConflictingEntries(t *testing.T) {
	for _, input := range [][]unixfs.Entry{
		{{Path: "../escape", Mode: 0100644}},
		{{Path: "file", Mode: 0100644}, {Path: "file/child", Mode: 0100644}},
		{{Path: "x", Mode: 0100644}, {Path: "./x", Mode: 0100644}},
		{{Path: "a", Mode: 0100644, Target: "b", Hardlink: true}, {Path: "b", Mode: 0100644, Target: "a", Hardlink: true}},
		{{Path: "a", Mode: 0100644, Target: "missing", Hardlink: true}},
		{{Path: "TRAILER!!!", Mode: 0100644}},
	} {
		if _, err := Build(input); err == nil {
			t.Fatal("accepted", input)
		}
	}
	_, err := Build([]unixfs.Entry{{Path: "x", Mode: 0100644}, {Path: "y", Mode: 0100755, Target: "x", Hardlink: true}})
	if err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatal(err)
	}
}
