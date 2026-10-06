package ext4

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
)

// Independently compute CRC32C bit by bit, without the reader's table/helper.
func fixtureCRC(seed uint32, data []byte) uint32 {
	for _, b := range data {
		seed ^= uint32(b)
		for i := 0; i < 8; i++ {
			if seed&1 != 0 {
				seed = (seed >> 1) ^ 0x82f63b78
			} else {
				seed >>= 1
			}
		}
	}
	return seed
}

// Upgrade the hand-authored ext2 fixture, not an ext4.Build image, with
// metadata checksums, a leaf directory tail and an external extent leaf.
func checksumFixture() []byte {
	b := ext2Fixture()
	sb := b[1024:2048]
	put32(sb, 76, 1)
	put16(sb, 88, 128)
	put32(sb, 96, 0x42)
	put32(sb, 100, 0x400)
	copy(sb[104:120], "checksum-fixture")
	sb[373] = 1
	seed := fixtureCRC(0xffffffff, sb[104:120])
	desc := b[2048:2080]
	put16(desc, 30, uint16(fixtureCRC(fixtureCRC(seed, []byte{0, 0, 0, 0}), desc)))
	inodeSeed := func(id uint32) uint32 {
		var fields [8]byte
		put32(fields[:], 0, id)
		return fixtureCRC(seed, fields[:])
	}
	root := b[3*1024+128:][:128]
	put16(root, 124, uint16(fixtureCRC(inodeSeed(2), root)))
	file := b[3*1024+10*128:][:128]
	put32(file, 4, 1024)
	put32(file, 32, 0x80000)
	clear(file[40:100])
	// Inline index -> external extent leaf at block 7 -> data block 6.
	put16(file, 40, 0xf30a)
	put16(file, 42, 1)
	put16(file, 44, 4)
	put16(file, 46, 1)
	put32(file, 56, 7)
	leaf := b[7*1024:][:1024]
	clear(leaf)
	put16(leaf, 0, 0xf30a)
	put16(leaf, 2, 1)
	put16(leaf, 4, 84)
	put16(leaf, 16, 1)
	put32(leaf, 20, 6)
	put32(leaf, 1020, fixtureCRC(inodeSeed(11), leaf[:1020]))
	put16(file, 124, uint16(fixtureCRC(inodeSeed(11), file)))
	dir := b[5*1024:][:1024]
	dir[7], dir[19], dir[31] = 2, 2, 1
	put16(dir, 28, 988)
	put16(dir, 1016, 12)
	dir[1019] = 0xde
	put32(dir, 1020, fixtureCRC(inodeSeed(2), dir[:1012]))
	put32(sb, 1020, fixtureCRC(0xffffffff, sb[:1020]))
	return b
}

func TestIndependentMetadataChecksumsAndCorruption(t *testing.T) {
	original := checksumFixture()
	file, err := auto.Open(bytes.NewReader(original), "", auto.Options{}).Resolve("file")
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(io.NewSectionReader(file.Reader(), 0, 6))
	if err != nil || string(text) != "direct" {
		t.Fatal(string(text), err)
	}
	for _, tc := range []struct {
		name    string
		at      int
		message string
	}{
		{"superblock", 1024 + 120, "superblock checksum"},
		{"descriptor", 2048 + 12, "group descriptor checksum"},
		{"inode", 3*1024 + 128 + 16, "inode checksum"},
		{"directory", 5*1024 + 32, "directory checksum"},
		{"extent", 7*1024 + 24, "extent checksum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			b[tc.at] ^= 1
			f, err := auto.Open(bytes.NewReader(b), "", auto.Options{}).Resolve("file")
			if err == nil {
				_, err = f.Reader().ReadAt(make([]byte, 1), 0)
			}
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("got %v, want %s", err, tc.message)
			}
		})
	}
}

func TestLegacyGroupChecksum(t *testing.T) {
	if crc16(0xffff, []byte("123456789")) != 0x4b37 {
		t.Fatal("CRC16 check vector")
	}
	b := ext2Fixture()
	sb := b[1024:2048]
	put32(sb, 76, 1)
	put16(sb, 88, 128)
	put32(sb, 100, 0x10)
	desc := b[2048:2080]
	// Independent Linux GDT checksum vector for zero UUID/group and this
	// 32-byte descriptor (inode table at block 3), calculated below bitwise.
	var crc uint16 = 0xffff
	data := append(make([]byte, 20), desc[:30]...)
	for _, value := range data {
		crc ^= uint16(value)
		for bit := 0; bit < 8; bit++ {
			low := crc & 1
			crc >>= 1
			crc ^= low * 0xa001
		}
	}
	put16(desc, 30, crc)
	if _, err := auto.Open(bytes.NewReader(b), "", auto.Options{}).Resolve("file"); err != nil {
		t.Fatal(err)
	}
	desc[14] ^= 1
	if _, err := auto.Open(bytes.NewReader(b), "", auto.Options{}).Resolve("file"); err == nil {
		t.Fatal("corrupt GDT accepted")
	}
}
