package apfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
)

func TestCompanionVolumesPreserveSystemSealAndAllocateDirectories(t *testing.T) {
	source := sealImageFixture()
	volume := source[6*4096 : 7*4096]
	le.PutUint16(volume[964:], 1)
	copy(volume[1008:1024], volume[240:256])
	seal(volume)
	original := sha256.Sum256(source)
	c, err := Open(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Volumes[0]
	rows, err := v.CanonicalRecords(123456789, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := EncodeSealedTree(rows, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	options := SealImageOptions{SnapshotName: "system", SnapshotTime: 123456789, Companions: []VolumeSpec{
		{Name: "Data", Role: 0x40, Created: 123456789, Directories: []string{"/log", "/db/state", "/db"}},
		{Name: "Preboot", Role: 0x10, Created: 123456789},
	}}
	image, err := v.SealImageWithOptions(rows, tree.RootHash, options)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(source) != original || image.AllocatedBlocks != 22 || image.FreedBlocks != 3 {
		t.Fatalf("source or allocation changed: %+v", image)
	}
	check, err := Open(image.File)
	if err != nil || len(check.Volumes) != 3 {
		t.Fatalf("constructed volumes: %v", err)
	}
	var maxSlots [4]byte
	check.Superblock.ReadAt(maxSlots[:], 180)
	if le.Uint32(maxSlots[:]) != 3 {
		t.Fatal("restore container's single volume slot was not expanded")
	}
	a, err := check.Allocation()
	if err != nil || a.FreeBlocks != 15 {
		t.Fatalf("allocation=%+v err=%v", a, err)
	}
	if _, _, err := check.Volumes[0].VerifySeal(tree.RootHash); err != nil {
		t.Fatal(err)
	}
	snapshot, err := check.Volumes[0].SnapshotVolume("system")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshot.VerifySeal(tree.RootHash); err != nil {
		t.Fatal(err)
	}
	data := check.Volumes[1]
	entries, err := data.Entries(false)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
		if e.Kind != "directory" || e.Mode != 0x41ed {
			t.Fatal("companion directory mode/type")
		}
	}
	if data.Name != "Data" || data.Role != 0x40 || data.Flags != 1 || data.Incompatible != 0 || len(paths) != 4 || paths[1] != "/db" || paths[2] != "/db/state" || paths[3] != "/log" {
		t.Fatalf("Data=%+v paths=%v", data, paths)
	}
	b := make([]byte, 4096)
	data.Superblock.ReadAt(b, 0)
	if le.Uint64(b[88:]) != 5 || le.Uint64(b[224:]) != 0 || le.Uint64(b[232:]) != 0 {
		t.Fatal("empty companion has five metadata blocks and no user data")
	}
	if !bytes.Equal(b[1008:1024], v.UUID[:]) || le.Uint64(b[176:]) != 19 || le.Uint64(b[192:]) != 5 {
		t.Fatal("group, inode allocation or directory accounting")
	}
	omap, err := check.object(le.Uint64(b[128:]), 11)
	if err != nil || le.Uint32(omap[44:]) != 0x40000002 || le.Uint32(omap[36:]) != 0 || le.Uint64(omap[56:]) != 0 {
		t.Fatal("empty object map must still declare its physical snapshot-tree type")
	}
	rootPA, err := resolve(data.omap, data.RootTree)
	if err != nil {
		t.Fatal(err)
	}
	rootNode, err := check.raw(rootPA)
	if err != nil || le.Uint32(rootNode[len(rootNode)-40:]) != 0x42 {
		t.Fatal("companion tree must declare its unpadded values")
	}
	check.Volumes[0].Superblock.ReadAt(b, 0)
	if le.Uint64(b[224:]) != 8 || le.Uint64(b[232:]) != 0 {
		t.Fatal("metadata reconstruction changed lifetime user-data counters")
	}
	prebootEntries, err := check.Volumes[2].Entries(false)
	if err != nil || len(prebootEntries) != 1 || check.Volumes[2].Role != 0x10 {
		t.Fatalf("Preboot: %v", err)
	}
	again, err := v.SealImageWithOptions(rows, tree.RootHash, options)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, image.File.Size()), make([]byte, again.File.Size())
	image.File.ReadAt(x, 0)
	again.File.ReadAt(y, 0)
	if !bytes.Equal(x, y) {
		t.Fatal("companion construction is nondeterministic")
	}
}

func TestCompanionDirectoryPathBounds(t *testing.T) {
	for _, paths := range [][]string{{"relative"}, {"/a/../b"}, {"/a//b"}, {"/a\x00b"}} {
		if _, _, err := companionDirectoryRecords(paths, 1); err == nil {
			t.Fatalf("accepted %q", paths)
		}
	}
}

func TestCompanionMountDirectoriesHaveSyntheticParentEntries(t *testing.T) {
	rows, next, err := companionDirectoryRecords(nil, 123)
	if err != nil || next != 16 || len(rows) != 4 {
		t.Fatalf("rows=%v next=%d err=%v", rows, next, err)
	}
	for i, want := range []struct {
		name string
		id   uint64
	}{{"private-dir", 3}, {"root", 2}} {
		r := rows[i]
		if le.Uint64(r.Key) != 1|9<<60 || int(le.Uint16(r.Key[8:])) != len(want.name)+1 || string(r.Key[10:len(r.Key)-1]) != want.name || r.Key[len(r.Key)-1] != 0 || le.Uint64(r.Value) != want.id || le.Uint64(r.Value[8:]) != 123 || le.Uint16(r.Value[16:]) != 4 {
			t.Fatalf("missing mount lookup entry %s: %+v", want.name, r)
		}
	}
}

func TestCompanionContentsAcrossTreeNodes(t *testing.T) {
	c, err := Open(bytes.NewReader(sealImageFixture()))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Volumes[0]
	rows, err := v.CanonicalRecords(123, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := EncodeSealedTree(rows, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("mutable plaintext\x00"), 300)
	entries := []Entry{{Path: "/d00/content", Kind: "file", Mode: 0x81a0, UID: 501, GID: 20, Data: bytes.NewReader(payload)}, {Path: "/d00/link", Kind: "symlink", Mode: 0xa1ff, Target: "content"}}
	for i := 0; i < 40; i++ {
		entries = append(entries, Entry{Path: fmt.Sprintf("/d%02d", i), Kind: "directory", Mode: 0x41c0, UID: 501, GID: 20})
	}
	image, err := v.SealImageWithOptions(rows, sealed.RootHash, SealImageOptions{Companions: []VolumeSpec{{Name: "Data", Role: 0x40, Created: 123, Entries: entries}}})
	if err != nil {
		t.Fatal(err)
	}
	check, err := Open(image.File)
	if err != nil {
		t.Fatal(err)
	}
	data := check.Volumes[1]
	got, err := data.Entries(false)
	if err != nil || len(got) != 43 {
		t.Fatalf("entries=%d err=%v", len(got), err)
	}
	var streams int
	metadata, err := data.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range metadata {
		if le.Uint64(r.Key)>>60 == 6 {
			streams++
			if len(r.Value) != 4 || le.Uint32(r.Value) != 1 {
				t.Fatal("invalid data-stream reference count")
			}
		}
	}
	if streams != 1 {
		t.Fatalf("data-stream records=%d", streams)
	}
	for _, e := range got {
		switch e.Path {
		case "/d00/content":
			b, err := io.ReadAll(io.NewSectionReader(e.Data, 0, e.Data.Size()))
			if err != nil || !bytes.Equal(b, payload) || e.UID != 501 || e.GID != 20 || e.Mode != 0x81a0 {
				t.Fatalf("content=%+v err=%v", e, err)
			}
		case "/d00/link":
			if e.Target != "content" {
				t.Fatalf("symlink=%+v", e)
			}
		case "/d00":
			if e.UID != 501 || e.GID != 20 || e.Mode != 0x41c0 {
				t.Fatalf("directory=%+v", e)
			}
		}
	}
	b := make([]byte, 4096)
	data.Superblock.ReadAt(b, 0)
	if le.Uint64(b[184:]) != 1 || le.Uint64(b[192:]) != 42 || le.Uint64(b[200:]) != 1 || le.Uint64(b[224:]) != 2 || !bytes.Equal(b[1008:1024], make([]byte, 16)) {
		t.Fatal("content counters or ungrouped source changed")
	}
	check.Volumes[0].Superblock.ReadAt(b, 0)
	if !bytes.Equal(b[1008:1024], make([]byte, 16)) {
		t.Fatal("invented source volume group")
	}
	if _, err := check.Allocation(); err != nil {
		t.Fatal(err)
	}
}
