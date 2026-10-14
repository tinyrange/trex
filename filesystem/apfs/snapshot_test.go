package apfs

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
)

func TestSealedBootSnapshotHistoryAuthenticationAndAllocation(t *testing.T) {
	source := sealImageFixture()
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
	options := SealImageOptions{SnapshotName: "com.apple.os.update-test", SnapshotTime: 123456789}
	image, err := v.SealImageWithOptions(rows, tree.RootHash, options)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(source) != original || image.Transaction != 4 || image.SnapshotTransaction != 3 || image.SnapshotName != options.SnapshotName || image.AllocatedBlocks != 10 || image.FreedBlocks != 3 {
		t.Fatalf("snapshot/source/accounting: %+v", image)
	}
	check, err := Open(image.File)
	if err != nil {
		t.Fatal(err)
	}
	live := check.Volumes[0]
	snaps, err := live.Snapshots()
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots=%+v err=%v", snaps, err)
	}
	if snaps[0].Name != options.SnapshotName || snaps[0].Transaction != 3 || snaps[0].Created != options.SnapshotTime {
		t.Fatal(snaps)
	}
	old, err := live.SnapshotVolume(options.SnapshotName)
	if err != nil {
		t.Fatal(err)
	}
	if old.Transaction != 3 || old.SnapshotCount != 0 || old.RootTree != live.RootTree {
		t.Fatalf("snapshot view: %+v", old)
	}
	if _, _, err = old.VerifySeal(tree.RootHash); err != nil {
		t.Fatal(err)
	}
	entries, err := old.Entries(false)
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	data, err := io.ReadAll(io.NewSectionReader(entries[2].Data, 0, entries[2].Data.Size()))
	if err != nil || string(data) != "data\x00\x00\x00\x00!" {
		t.Fatalf("snapshot data=%q err=%v", data, err)
	}
	alloc, err := check.Allocation()
	if err != nil || alloc.FreeBlocks != 27 {
		t.Fatalf("allocation=%+v err=%v", alloc, err)
	}
	sb := make([]byte, 4096)
	live.Superblock.ReadAt(sb, 0)
	smeID := le.Uint64(sb[1000:])
	if _, exists := old.omap[smeID]; exists {
		t.Fatal("snapshot resolved a mapping newer than its transaction")
	}
	smePA, err := resolve(live.omap, smeID)
	if err != nil {
		t.Fatal(err)
	}
	sme, err := check.object(smePA, 29)
	if err != nil || le.Uint64(sme[40:]) != 3 || !bytes.Equal(sme[48:64], image.SnapshotUUID[:]) {
		t.Fatalf("snapshot extension: %v", err)
	}
	omap, err := check.object(le.Uint64(sb[128:]), 11)
	if err != nil {
		t.Fatal(err)
	}
	if le.Uint32(omap[36:]) != 1 || le.Uint64(omap[64:]) != 3 {
		t.Fatal("object map snapshot accounting")
	}
	seen := 0
	err = check.walkTree(le.Uint64(omap[56:]), nil, func(k, b []byte) error {
		if len(k) != 8 || le.Uint64(k) != 3 || !bytes.Equal(b, make([]byte, 16)) {
			t.Fatal("object map snapshot record")
		}
		seen++
		return nil
	})
	if err != nil || seen != 1 {
		t.Fatalf("object map snapshot count=%d err=%v", seen, err)
	}
	if _, err = live.SnapshotVolume("absent"); err == nil {
		t.Fatal("accepted missing snapshot")
	}
	// A fresh identical construction has deterministic bytes and UUID.
	again, err := v.SealImageWithOptions(rows, tree.RootHash, options)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(io.NewSectionReader(image.File, 0, image.File.Size()))
	want, _ := io.ReadAll(io.NewSectionReader(again.File, 0, again.File.Size()))
	if !bytes.Equal(got, want) {
		t.Fatal("snapshot construction is nondeterministic")
	}
}

func TestSnapshotNameAndRecordBounds(t *testing.T) {
	for _, b := range [][]byte{nil, {0}, []byte("no terminator"), []byte("a\x00b\x00"), []byte("a/b\x00"), {0xff, 0}} {
		if _, err := snapshotName(b, len(b)); err == nil {
			t.Fatalf("accepted name %q", b)
		}
	}
	if _, err := snapshotName([]byte("valid\x00"), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := encodeVariablePhysicalLeaf([]Record{{make([]byte, 8), make([]byte, 4096)}}, 4096, 16, 1, 2); err == nil {
		t.Fatal("accepted oversized leaf")
	}
}

func TestFixedPhysicalSnapshotTreeUsesEightByteKeys(t *testing.T) {
	rows := make([]Record, 500)
	for i := range rows {
		rows[i] = Record{le.AppendUint64(nil, uint64(i+1)), make([]byte, 16)}
	}
	disk := make([]byte, 16*4096)
	next := uint64(0)
	root, _, err := encodeFixedPhysicalTree(rows, 4096, 19, 8, 7, func() (uint64, error) { next++; return next, nil }, func(pa uint64, b []byte) error { copy(disk[pa*4096:], b); return nil })
	if err != nil {
		t.Fatal(err)
	}
	c := &Container{Source: bytes.NewReader(disk), BlockSize: 4096, Blocks: 16}
	n := 0
	err = c.walkTree(root, nil, func(k, b []byte) error {
		if len(k) != 8 || le.Uint64(k) != uint64(n+1) || len(b) != 16 {
			t.Fatal("snapshot tree changed record")
		}
		n++
		return nil
	})
	if err != nil || n != 500 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, _ := c.raw(root)
	if le.Uint32(b[4096-40:]) != 0x11 {
		t.Fatal("uint64 physical flags")
	}
}
