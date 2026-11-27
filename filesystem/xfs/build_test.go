package xfs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestBuildV4(t *testing.T) {
	payload := &starfile.Bytes{Data: []byte(strings.Repeat("payload", 1000))}
	rows := []unixfs.Entry{
		{Path: "dev/null", Mode: unixfs.Character | 0666, Major: 3, Minor: 2},
		{Path: "etc/alias", Mode: unixfs.Symlink | 0777, Target: "payload"},
		{Path: "etc/longlink", Mode: unixfs.Symlink | 0777, Target: strings.Repeat("target/", 40)},
		{Path: "etc/payload", Mode: unixfs.Regular | 0640, GID: 7, UID: 12, Mtime: 1234567, Data: payload},
		{Path: "etc/payload2", Mode: unixfs.Regular | 0640, GID: 7, UID: 12, Mtime: 1234567, Hardlink: true, Target: "etc/payload"},
	}
	for _, dir := range []struct {
		name  string
		count int
	}{{"block", 30}, {"leaf", 300}, {"node", 900}} {
		for i := range dir.count {
			rows = append(rows, unixfs.Entry{Path: fmt.Sprintf("%s/file%05d", dir.name, i), Mode: unixfs.Regular | 0644})
		}
	}
	img, err := Build(rows, 32<<20, "Test", [16]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := Open(img, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(volume.Entries) != 1241 {
		t.Fatalf("got %d entries", len(volume.Entries))
	}
	byPath := make(map[string]Entry)
	for _, e := range volume.Entries {
		byPath[e.Path] = e
	}
	file := byPath["/etc/payload"]
	if file.Inode != byPath["/etc/payload2"].Inode || file.Mode != 0100640 || file.UID != 12 || file.GID != 7 || file.Modified != 1234567 {
		t.Fatalf("payload metadata %+v", file)
	}
	data, err := starfile.ReadAll(file.Data)
	if err != nil || string(data) != string(payload.Data) {
		t.Fatalf("payload read length %d, error %v", len(data), err)
	}
	for _, e := range rows[1:3] {
		link := byPath["/"+e.Path]
		data, err := starfile.ReadAll(link.Data)
		if err != nil || string(data) != e.Target {
			t.Fatalf("symlink %s: %q, %v", e.Path, data, err)
		}
	}
	if device := byPath["/dev/null"]; device.Kind != "character_device" || device.Major != 3 || device.Minor != 2 {
		t.Fatalf("device node %+v", byPath["/dev/null"])
	}
	for name, extents := range map[string]int{"/block": 1, "/leaf": 2, "/node": 3} {
		if n := len(byPath[name].extents); n != extents {
			t.Errorf("%s has %d extents, expected %d", name, n, extents)
		}
	}
}

func TestBuildV4SpansInodeBtreeLeaves(t *testing.T) {
	const count = 16400
	rows := make([]unixfs.Entry, count)
	for i := range rows {
		rows[i] = unixfs.Entry{Path: fmt.Sprintf("%d/%05d", i/1000, i), Mode: unixfs.Regular | 0644}
	}
	img, err := Build(rows, 32<<20, "", [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, xfsBlock)
	if _, err := starfile.ReadFullAt(img, buf, 3*xfsBlock); err != nil {
		t.Fatal(err)
	}
	if string(buf[:4]) != "IABT" || be.Uint16(buf[4:]) != 1 || be.Uint16(buf[6:]) != 2 {
		t.Fatal("expected a level-1 root with two inode btree leaves")
	}
	for i := range 2 {
		key := be.Uint32(buf[16+i*4:])
		block := be.Uint32(buf[16+((xfsBlock-16)/8)*4+i*4:])
		var leaf [24]byte
		if _, err := starfile.ReadFullAt(img, leaf[:], int64(block)*xfsBlock); err != nil {
			t.Fatal(err)
		}
		if string(leaf[:4]) != "IABT" || be.Uint16(leaf[4:]) != 0 || be.Uint32(leaf[16:]) != key {
			t.Fatalf("invalid inode btree child %d", i)
		}
	}
}
