package apfs

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
)

func sealImageFixture() []byte {
	b := allocationFixture(false)
	for _, pa := range []int{0, 16} {
		p := b[pa*4096 : (pa+1)*4096]
		le.PutUint64(p[88:], 1100)
		seal(p)
	}
	vol := b[6*4096 : 7*4096]
	le.PutUint64(vol[88:], 8)
	le.PutUint64(vol[224:], 8)
	seal(vol)
	sm := b[27*4096 : 28*4096]
	le.PutUint32(sm[80:], 2576)
	le.PutUint16(sm[320:], 1)
	le.PutUint16(sm[322:], 15)
	le.PutUint32(sm[324:], 2520)
	le.PutUint32(sm[328:], 2528)
	le.PutUint32(sm[332:], 2536)
	le.PutUint64(sm[2520:], 2)
	le.PutUint16(sm[2528:], 0)
	for i := 0; i < 16; i++ {
		next := uint16(i + 1)
		if i == 0 || i == 15 {
			next = 65535
		}
		le.PutUint16(sm[2536+i*2:], next)
	}
	le.PutUint64(sm[2576:], 29)
	// Make the last chunk the first useful free range. Its bitmap must be
	// allocated in the internal pool rather than counted as a device block.
	le.PutUint64(sm[72:], 34)
	seal(sm)
	cib := b[29*4096 : 30*4096]
	le.PutUint32(cib[92:], 0)
	seal(cib)
	le.PutUint32(b[31*4096:], 0xffffffff)
	b[32*4096] = 0x0e // CIB and the two existing chunk bitmaps; pool block 28 free.
	old := append([]byte(nil), b[16*4096:17*4096]...)
	le.PutUint64(old[16:], 1)
	seal(old)
	copy(b[17*4096:], old)
	return b
}

func TestSealImageAllocationAuthenticationAndBorrowedData(t *testing.T) {
	b := sealImageFixture()
	originalHash := sha256.Sum256(b)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Volumes[0]
	records, err := v.CanonicalRecords(123456789, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := EncodeSealedTree(records, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	image, err := v.SealImage(records, tree.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(b) != originalHash || image.Transaction != 3 || image.AllocatedBlocks != 5 || image.FreedBlocks != 3 {
		t.Fatalf("source immutability or accounting: %+v", image)
	}
	check, err := Open(image.File)
	if err != nil {
		t.Fatal(err)
	}
	sealed := check.Volumes[0]
	if sealed.RootTree != 1100 || sealed.Integrity != 1101 || sealed.Incompatible&0x20 == 0 {
		t.Fatalf("sealed metadata pointers: %+v", sealed)
	}
	if n, hashes, err := sealed.VerifySeal(tree.RootHash); err != nil || n != uint64(len(records)) || hashes != 0 {
		t.Fatalf("seal records=%d hashes=%d err=%v", n, hashes, err)
	}
	a, err := check.Allocation()
	if err != nil || a.FreeBlocks != 32 || a.Chunks[2].BitmapAddress != 28 {
		t.Fatalf("allocation: %+v err=%v", a, err)
	}
	ip, _ := check.raw(32)
	if ip[0] != 15 {
		t.Fatal("new chunk bitmap missing from internal-pool allocation map")
	}
	retired, _ := check.raw(17)
	if !bytes.Equal(retired, make([]byte, 4096)) {
		t.Fatal("historical checkpoint retained after replacing shared metadata")
	}
	entries, err := sealed.Entries(false)
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries: %v", err)
	}
	data, err := io.ReadAll(io.NewSectionReader(entries[2].Data, 0, 9))
	if err != nil || string(data) != "data\x00\x00\x00\x00!" {
		t.Fatalf("file extents changed: %q %v", data, err)
	}
	// Installing the same trusted records from a sealed source follows its
	// separate fext tree and releases all replaced metadata exactly once.
	again, err := sealed.SealImage(records, tree.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	if again.Transaction != 4 || again.AllocatedBlocks != again.FreedBlocks {
		t.Fatalf("reseal accounting: %+v", again)
	}
	final, err := Open(again.File)
	if err != nil {
		t.Fatal(err)
	}
	fa, err := final.Allocation()
	if err != nil || fa.FreeBlocks != a.FreeBlocks || final.Volumes[0].RootTree <= sealed.Integrity {
		t.Fatalf("reseal allocation/ID reuse: %+v %v", fa, err)
	}
}

func TestSealImageRejectsUntrustedOrSnapshotInputWithoutMutation(t *testing.T) {
	b := sealImageFixture()
	original := sha256.Sum256(b)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Volumes[0]
	records, _ := v.CanonicalRecords(1, nil)
	tree, _ := EncodeSealedTree(records, 4096, 1)
	for _, expected := range [][]byte{nil, make([]byte, 32), make([]byte, 64)} {
		if _, err := v.SealImage(records, expected); err == nil {
			t.Fatal("accepted absent/incorrect external root")
		}
	}
	v.SnapshotCount = 1
	if _, err := v.SealImage(records, tree.RootHash); err == nil {
		t.Fatal("accepted snapshots while retiring checkpoints")
	}
	if sha256.Sum256(b) != original {
		t.Fatal("failed construction changed source")
	}
}
