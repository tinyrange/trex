package cab

import (
	"bytes"
	"encoding/binary"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"sync"
	"testing"
)

func largeLZXFixture() (*Archive, []byte) {
	const block = 32768
	plain := make([]byte, 256*block)
	for i := range plain {
		plain[i] = byte((i/73 + i/65536) % 251)
	}
	// One LZX uncompressed block: no Intel transform, type3, 24-bit size,
	// word alignment, three repeated offsets, then the literal payload.
	header := make([]byte, 16)
	bits := uint32(3<<24|len(plain)) << 4
	binary.LittleEndian.PutUint16(header, uint16(bits>>16))
	binary.LittleEndian.PutUint16(header[2:], uint16(bits))
	for _, off := range []int{4, 8, 12} {
		binary.LittleEndian.PutUint32(header[off:], 1)
	}
	var encoded []byte
	for i := 0; i < 256; i++ {
		payload := plain[i*block : (i+1)*block]
		if i == 0 {
			payload = append(append([]byte{}, header...), payload...)
		}
		data := make([]byte, 8)
		binary.LittleEndian.PutUint16(data[4:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(data[6:], block)
		encoded = append(append(encoded, data...), payload...)
	}
	a := &Archive{file: &starfile.Bytes{Data: encoded}, cache: true, cacheStore: bytecache.New(2 << 20), cacheSource: 18,
		folders: []folder{{compression: 15<<8 | 3, blocks: 256}}}
	return a, plain
}

func TestPackedLZXFolderRandomAccessAndEviction(t *testing.T) {
	a, plain := largeLZXFixture()
	a.cacheStore = bytecache.New(64 << 20)
	a.ReleaseReadCaches()
	f := &Entry{archive: a, file: fileRecord{name: "member", uncompressedStart: 65500, size: 250000}}
	expected := plain[65500:315500]
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := int64(i * 10003)
			buf := make([]byte, 70000)
			n, err := f.ReadAt(buf, off)
			if n != len(buf) || err != nil || !bytes.Equal(buf, expected[off:off+int64(len(buf))]) {
				t.Errorf("read %d: %d %v", off, n, err)
			}
		}(i)
	}
	wg.Wait()
	stats := a.cacheStore.Stats()
	if stats.Loads != 1 || stats.Bytes > 32<<20 {
		t.Fatalf("expanded folder retained or repeated: %+v", stats)
	}
	all, err := f.Bytes()
	if err != nil || !bytes.Equal(all, expected) {
		t.Fatalf("Bytes: %v", err)
	}
	var dst bytes.Buffer
	if n, err := f.WriteTo(&dst); err != nil || n != int64(len(expected)) || !bytes.Equal(dst.Bytes(), expected) {
		t.Fatalf("WriteTo: %d %v", n, err)
	}
	tail := make([]byte, 10)
	if n, err := f.ReadAt(tail, f.Size()-3); n != 3 || err != io.EOF || !bytes.Equal(tail[:3], expected[len(expected)-3:]) {
		t.Fatalf("tail: %d %v", n, err)
	}
	a.ReleaseReadCaches()
	if a.cacheStore.Stats().Bytes != 0 {
		t.Fatal("packed folder survived cache release")
	}
	got, err := f.Bytes()
	if err != nil || !bytes.Equal(got, all) {
		t.Fatalf("reloaded member: %v", err)
	}
	bad := &Entry{archive: a, file: fileRecord{name: "bad", uncompressedStart: uint32(len(plain) - 4), size: 8}}
	if _, err := bad.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("out-of-folder member accepted")
	}
	a.ReleaseReadCaches()
	a.file = &starfile.Bytes{Data: []byte("truncated")}
	if _, err := f.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("corrupt reload accepted")
	}
}
