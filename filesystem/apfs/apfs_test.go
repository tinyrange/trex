package apfs

import (
	"bytes"
	"io"
	"testing"
)

type pair struct{ k, v []byte }

func block(kind uint32, id uint64) []byte {
	b := make([]byte, 4096)
	le.PutUint64(b[8:], id)
	le.PutUint64(b[16:], 2)
	le.PutUint32(b[24:], kind)
	return b
}
func seal(b []byte) { le.PutUint64(b, checksum(b)) }
func tree(records []pair, fixed bool) []byte {
	b := block(2, 1028)
	flags, width := uint16(3), 8
	if fixed {
		flags |= 4
		width = 4
	}
	le.PutUint16(b[32:], flags)
	le.PutUint32(b[36:], uint32(len(records)))
	le.PutUint16(b[42:], uint16(width*len(records)))
	keyPos, valuePos := 56+width*len(records), 4096-40
	for i, r := range records {
		toc := b[56+i*width:]
		le.PutUint16(toc, uint16(keyPos-56-width*len(records)))
		valuePos -= len(r.v)
		if fixed {
			le.PutUint16(toc[2:], uint16(4096-40-valuePos))
		} else {
			le.PutUint16(toc[2:], uint16(len(r.k)))
			le.PutUint16(toc[4:], uint16(4096-40-valuePos))
			le.PutUint16(toc[6:], uint16(len(r.v)))
		}
		copy(b[keyPos:], r.k)
		copy(b[valuePos:], r.v)
		keyPos += len(r.k)
	}
	le.PutUint32(b[4096-36:], 4096)
	if fixed {
		le.PutUint32(b[4096-32:], 16)
		le.PutUint32(b[4096-28:], 16)
	}
	seal(b)
	return b
}
func mapPair(id, address uint64) pair {
	k, v := make([]byte, 16), make([]byte, 16)
	le.PutUint64(k, id)
	le.PutUint64(k[8:], 2)
	le.PutUint32(v[4:], 4096)
	le.PutUint64(v[8:], address)
	return pair{k, v}
}
func fsKey(id, kind uint64) []byte { return le.AppendUint64(nil, id|kind<<60) }
func inodePair(id, private, size uint64, mode uint16) pair {
	b := make([]byte, 140)
	le.PutUint64(b, 2)
	le.PutUint64(b[8:], private)
	le.PutUint16(b[80:], mode)
	le.PutUint16(b[92:], 1)
	le.PutUint16(b[94:], 44)
	b[96] = 8
	le.PutUint16(b[98:], 40)
	le.PutUint64(b[100:], size)
	return pair{fsKey(id, 3), b}
}
func drec(text string, id uint64) pair {
	k := le.AppendUint32(fsKey(2, 9), uint32(len(text)+1))
	k = append(k, []byte(text)...)
	k = append(k, 0)
	v := make([]byte, 18)
	le.PutUint64(v, id)
	return pair{k, v}
}
func extentPair(logical, length, physical uint64) pair {
	k := le.AppendUint64(fsKey(11, 8), logical)
	v := make([]byte, 24)
	le.PutUint64(v, length)
	le.PutUint64(v[8:], physical)
	return pair{k, v}
}
func fixture() []byte {
	disk := make([]byte, 16*4096)
	put := func(address int, b []byte) { seal(b); copy(disk[address*4096:], b) }
	nx := block(1, 1)
	copy(nx[32:], "NXSB")
	le.PutUint32(nx[36:], 4096)
	le.PutUint64(nx[40:], 16)
	le.PutUint64(nx[160:], 4)
	le.PutUint32(nx[180:], 1)
	le.PutUint64(nx[184:], 1024)
	put(0, nx)
	omap := block(11, 4)
	le.PutUint32(omap[40:], 0x40000002)
	le.PutUint64(omap[48:], 5)
	put(4, omap)
	put(5, tree([]pair{mapPair(1024, 6)}, true))
	vol := block(13, 1024)
	copy(vol[32:], "APSB")
	le.PutUint64(vol[56:], 8)
	le.PutUint32(vol[116:], 2)
	le.PutUint64(vol[128:], 7)
	le.PutUint64(vol[136:], 1028)
	le.PutUint64(vol[264:], 1)
	copy(vol[240:256], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	copy(vol[704:], "Test")
	put(6, vol)
	omap = block(11, 7)
	le.PutUint32(omap[40:], 0x40000002)
	le.PutUint64(omap[48:], 8)
	put(7, omap)
	put(8, tree([]pair{mapPair(1028, 9)}, true))
	put(9, tree([]pair{inodePair(2, 2, 0, 0x41ed), inodePair(10, 11, 9, 0x81a4), drec("hello", 10), drec("again", 10), extentPair(0, 4, 12), extentPair(8, 1, 13)}, false))
	copy(disk[12*4096:], "data")
	disk[13*4096] = '!'
	return disk
}

func TestNativeTreeHardlinksSparseAndBorrowedStreams(t *testing.T) {
	b := fixture()
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Volumes) != 1 || c.Volumes[0].Name != "Test" {
		t.Fatalf("volumes %+v", c.Volumes)
	}
	if c.Volumes[0].UUID != [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
		t.Fatalf("volume UUID %x", c.Volumes[0].UUID)
	}
	entries, err := c.Volumes[0].Entries(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[1].Path != "/again" || entries[2].Path != "/hello" || entries[1].ID != entries[2].ID {
		t.Fatalf("entries %+v", entries)
	}
	b[12*4096] = 'D'
	got, err := io.ReadAll(io.NewSectionReader(entries[2].Data, 0, 9))
	if err != nil || !bytes.Equal(got, []byte("Data\x00\x00\x00\x00!")) {
		t.Fatalf("data %q %v", got, err)
	}
	p := make([]byte, 4)
	if n, err := entries[2].Data.ReadAt(p, 7); n != 2 || err != io.EOF {
		t.Fatalf("short read %d %v", n, err)
	}
}

func TestMalformedContainerTreeAndExtents(t *testing.T) {
	for label, edit := range map[string]func([]byte){
		"container-checksum":  func(b []byte) { b[80] ^= 1 },
		"truncated-container": func(b []byte) { le.PutUint64(b[40:], 17); seal(b[:4096]) },
		"node-checksum":       func(b []byte) { b[9*4096+80] ^= 1 },
		"node-table":          func(b []byte) { n := b[9*4096 : 10*4096]; le.PutUint16(n[42:], 65535); seal(n) },
		"missing-root":        func(b []byte) { n := b[9*4096 : 10*4096]; le.PutUint64(n[104:], 3|3<<60); seal(n) },
	} {
		t.Run(label, func(t *testing.T) {
			b := fixture()
			edit(b)
			c, err := Open(bytes.NewReader(b))
			if err == nil {
				_, err = c.Volumes[0].Entries(false)
			}
			if err == nil {
				t.Fatal("accepted malformed APFS")
			}
		})
	}
}

func TestSnapshotMetadataUsesSelectedVolumeSuperblock(t *testing.T) {
	b := fixture()
	vol := b[6*4096 : 7*4096]
	le.PutUint64(vol[216:], 7)
	le.PutUint64(vol[152:], 1030)
	le.PutUint32(vol[124:], 2)
	seal(vol)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Volumes[0]
	if v.SnapshotCount != 7 || v.SnapshotTree != 1030 || v.SnapshotTreeType != 2 {
		t.Fatalf("snapshot metadata count=%d tree=%d type=%x", v.SnapshotCount, v.SnapshotTree, v.SnapshotTreeType)
	}
	metadata, err := io.ReadAll(io.NewSectionReader(v.Superblock, 0, v.Superblock.Size()))
	if err != nil || !bytes.Equal(metadata, vol) {
		t.Fatalf("selected volume superblock bytes: %v", err)
	}
	nx, err := io.ReadAll(io.NewSectionReader(c.Superblock, 0, c.Superblock.Size()))
	if err != nil || string(nx[32:36]) != "NXSB" || le.Uint64(nx[16:]) != c.Transaction {
		t.Fatalf("selected container superblock bytes: %v", err)
	}
	// These fields remain checksum protected, even when only metadata is read.
	vol[216] ^= 1
	if _, err := Open(bytes.NewReader(b)); err == nil {
		t.Fatal("accepted corrupted snapshot metadata")
	}
}

func TestVirtualChildrenAndObjectMapVersionSelection(t *testing.T) {
	b := fixture()
	put := func(address int, block []byte) { seal(block); copy(b[address*4096:], block) }
	old := mapPair(1028, 14)
	le.PutUint64(old.k[8:], 1)
	future := mapPair(1028, 15)
	le.PutUint64(future.k[8:], 3)
	put(8, tree([]pair{old, mapPair(1028, 9), future, mapPair(1029, 10)}, true))
	leaf := tree([]pair{inodePair(2, 2, 0, 0x41ed), inodePair(10, 11, 9, 0x81a4), drec("hello", 10), extentPair(0, 4, 12), extentPair(8, 1, 13)}, false)
	le.PutUint32(leaf[24:], 3)
	le.PutUint16(leaf[32:], 2)
	for i := 0; i < 5; i++ {
		toc := leaf[56+i*8:]
		le.PutUint16(toc[4:], le.Uint16(toc[4:])+40)
	}
	put(10, leaf)
	root := tree([]pair{{fsKey(2, 3), le.AppendUint64(nil, 1029)}}, false)
	le.PutUint16(root[32:], 1)
	le.PutUint16(root[34:], 1)
	put(9, root)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := c.Volumes[0].Entries(false)
	if err != nil || len(entries) != 2 || entries[1].Path != "/hello" {
		t.Fatalf("children: %+v %v", entries, err)
	}
	// Resolve the child to its ancestor: cycles must stop before recursion.
	put(8, tree([]pair{mapPair(1028, 9), mapPair(1029, 9)}, true))
	c, err = Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Volumes[0].Entries(false); err == nil {
		t.Fatal("accepted cyclic tree")
	}
}

func TestRejectOverlappingRecordsAndFileExtents(t *testing.T) {
	for _, records := range [][]pair{
		{inodePair(2, 2, 0, 0x41ed), inodePair(10, 11, 9, 0x81a4), drec("hello", 10), extentPair(0, 8, 12), extentPair(4, 1, 13)},
		{inodePair(2, 2, 0, 0x41ed), inodePair(10, 11, 9, 0x81a4), drec("hello", 10), extentPair(0, 8192, 15)},
	} {
		b := fixture()
		copy(b[9*4096:], tree(records, false))
		c, err := Open(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Volumes[0].Entries(false); err == nil {
			t.Fatal("accepted invalid data extent")
		}
	}
	b := fixture()
	node := b[9*4096 : 10*4096]
	// Point the second key at the first while leaving each pair in bounds.
	le.PutUint16(node[64:], le.Uint16(node[56:]))
	seal(node)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Volumes[0].Entries(false); err == nil {
		t.Fatal("accepted overlapping records")
	}
}
