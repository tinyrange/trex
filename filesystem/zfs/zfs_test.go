package zfs

import (
	"bytes"
	"crypto/sha256"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func testPool() ([]byte, int) {
	image := make([]byte, 8<<20)
	copy(image[16384:], []byte{1, 1, 0, 0, 0, 0, 0, 0})
	copy(image[16400:], "version")
	next := labelBias
	store := func(data []byte) []byte {
		at := next
		next += len(data)
		copy(image[at:], data)
		bp := make([]byte, 128)
		le.PutUint64(bp, uint64(len(data)/512))
		le.PutUint64(bp[8:], uint64((at-labelBias)/512))
		prop := uint64(len(data)/512 - 1)
		le.PutUint64(bp[48:], prop|prop<<16|2<<32|7<<40|1<<63)
		var sum [4]uint64
		for i := 0; i < len(data); i += 4 {
			sum[0] += uint64(le.Uint32(data[i:]))
			sum[1] += sum[0]
			sum[2] += sum[1]
			sum[3] += sum[2]
		}
		for i, v := range sum {
			le.PutUint64(bp[96+i*8:], v)
		}
		return bp
	}
	node := func(kind byte, blockSize int, bp, bonus []byte, bonusType byte) []byte {
		b := make([]byte, 512)
		b[0] = kind
		b[1] = 14
		b[3] = 1
		b[4] = bonusType
		if bp != nil {
			b[2] = 1
			copy(b[64:], bp)
		}
		le.PutUint16(b[8:], uint16(blockSize/512))
		le.PutUint16(b[10:], uint16(len(bonus)))
		copy(b[192:], bonus)
		return b
	}
	zap := func(name string, value uint64) []byte {
		b := make([]byte, 512)
		le.PutUint64(b, 0x8000000000000003)
		le.PutUint64(b[64:], value)
		copy(b[78:], name)
		return b
	}
	payload := make([]byte, 512)
	copy(payload, "hello")
	payloadAt := next
	fileBP := store(payload)
	bonus := make([]byte, 144)
	le.PutUint64(bonus[72:], 0100644)
	le.PutUint64(bonus[80:], 5)
	fsMeta := make([]byte, 16384)
	copy(fsMeta[3*512:], node(19, 512, fileBP, bonus, 17))
	copy(fsMeta[2*512:], node(20, 512, store(zap("hello", 8<<60|3)), nil, 0))
	copy(fsMeta[512:], node(21, 512, store(zap("ROOT", 2)), nil, 0))
	fsOS := make([]byte, 1024)
	copy(fsOS, node(10, 16384, store(fsMeta), nil, 0))
	dsBonus := make([]byte, 256)
	copy(dsBonus[128:], store(fsOS))
	mosMeta := make([]byte, 16384)
	copy(mosMeta[3*512:], node(16, 0, nil, dsBonus, 16))
	dirBonus := make([]byte, 256)
	le.PutUint64(dirBonus[8:], 3)
	copy(mosMeta[2*512:], node(12, 0, nil, dirBonus, 12))
	copy(mosMeta[512:], node(1, 512, store(zap("root_dataset", 2)), nil, 0))
	mosOS := make([]byte, 1024)
	copy(mosOS, node(10, 16384, store(mosMeta), nil, 0))
	root := store(mosOS)
	uber := image[128<<10 : (128<<10)+1024]
	le.PutUint64(uber, 0xbab10c)
	le.PutUint64(uber[8:], 5000)
	le.PutUint64(uber[16:], 42)
	copy(uber[40:], root)
	le.PutUint64(uber[984:], 0x210da7ab10c7a11)
	le.PutUint64(uber[992:], 128<<10)
	h := sha256.Sum256(uber)
	for i := 0; i < 4; i++ {
		le.PutUint64(uber[992+i*8:], be.Uint64(h[i*8:]))
	}
	return image, payloadAt
}
func TestDatasetReadAndChecksums(t *testing.T) {
	b, at := testPool()
	root := auto.Open(&starfile.Bytes{Data: b}, "pool", auto.Options{})
	n, err := root.Resolve("files/hello")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(n.Reader(), 0, n.Reader().Size()))
	if err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", got, err)
	}
	b[at] ^= 1
	root = auto.Open(&starfile.Bytes{Data: b}, "pool", auto.Options{})
	n, err = root.Resolve("files/hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.Reader().ReadAt(make([]byte, 5), 0); err == nil {
		t.Fatal("ignored data checksum")
	}
	b[128<<10+16] ^= 1
	if _, err = Open(&starfile.Bytes{Data: b}, auto.Options{}); err == nil {
		t.Fatal("ignored uberblock checksum")
	}
}
func TestBlockCodecsAndBounds(t *testing.T) {
	// LZ4 literal abc + overlapping match abcabc + a final literal xyz.
	lz4 := []byte{0x32, 'a', 'b', 'c', 3, 0, 0x30, 'x', 'y', 'z'}
	encoded := be.AppendUint32(nil, uint32(len(lz4)))
	encoded = append(encoded, lz4...)
	out, err := decompress(15, encoded, 12)
	if err != nil || string(out) != "abcabcabcxyz" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := decompress(15, encoded, 11); err == nil {
		t.Fatal("ignored output bound")
	}
	if _, err := decompress(15, []byte{0, 0, 0, 10}, 12); err == nil {
		t.Fatal("ignored input bound")
	}
	// LZJB literal abc then a six-byte overlapping copy.
	out, err = decompress(3, []byte{8, 'a', 'b', 'c', 12, 3}, 9)
	if err != nil || string(out) != "abcabcabc" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := newObject(&pool{}, make([]byte, 512), le); err == nil {
		t.Fatal("accepted unused dnode")
	}
	b, _ := testPool()
	u := b[128<<10 : (128<<10)+1024]
	if !validUber(u, 128<<10, le) || validUber(u, 129<<10, le) {
		t.Fatal("uber location binding")
	}
}
func FuzzBlockCodecs(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 0x10, 'a'}, uint16(1))
	f.Fuzz(func(t *testing.T, b []byte, size uint16) {
		for _, codec := range []int{3, 15} {
			out, err := decompress(codec, b, int(size))
			if err == nil && len(out) != int(size) {
				t.Fatal("size mismatch")
			}
		}
	})
}
func TestEmbeddedBlock(t *testing.T) {
	b := make([]byte, 128)
	copy(b, "hello")
	le.PutUint64(b[48:], 4|4<<25|2<<32|1<<39|1<<63)
	p := &pool{}
	got, _, err := p.block(pointer{b, le})
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("%q %v", got, err)
	}
}
