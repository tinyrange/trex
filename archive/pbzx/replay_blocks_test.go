package pbzx

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	encoder "github.com/ulikunitz/xz"
)

func blockFixture(t testing.TB) ([]byte, []byte, int) {
	t.Helper()
	chunkSize := 2*ReplayBlockSize + 7 // deliberately not page-aligned
	framed := make([]byte, 12)
	copy(framed, "pbzx")
	binary.BigEndian.PutUint64(framed[4:], uint64(chunkSize))
	rng := rand.New(rand.NewSource(41))
	var all []byte
	for _, size := range []int{chunkSize, chunkSize, ReplayBlockSize + 13} {
		data := make([]byte, size)
		_, _ = rng.Read(data)
		// Exercise literal-heavy as well as highly compressible replay blocks.
		copy(data[ReplayBlockSize:], bytes.Repeat([]byte("repeated"), ReplayBlockSize/8))
		var b bytes.Buffer
		w, err := (encoder.WriterConfig{DictCap: 1 << 20}).NewWriter(&b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		var h [16]byte
		binary.BigEndian.PutUint64(h[:], uint64(size))
		binary.BigEndian.PutUint64(h[8:], uint64(b.Len()))
		framed = append(framed, h[:]...)
		framed = append(framed, b.Bytes()...)
		all = append(all, data...)
	}
	return framed, all, chunkSize
}

func TestReplayBlocksBoundSmallReadWork(t *testing.T) {
	packed, plain, chunkSize := blockFixture(t)
	source := &observedReader{Reader: bytes.NewReader(packed)}
	f, err := OpenWithReplayCache(source, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		var b [1]byte
		if _, err = f.ReadAt(b[:], int64(i*chunkSize)); err != nil {
			t.Fatal(err)
		}
	}
	if s := f.Stats(); s.XZChunks != 3 || s.XZBytes != uint64(len(plain)) {
		t.Fatalf("decode counts: %+v", s)
	}
	// Ensure the first requested page does not retain the whole XZ output.
	data, err := f.cache.Get(bytecache.Key{Index: 0}, func() ([]byte, error) { t.Error("missing first page"); return nil, io.EOF })
	if err != nil || len(data) != ReplayBlockSize || cap(data) != len(data) {
		t.Fatal("decoded page retention", len(data), cap(data), err)
	}
	f.cache = bytecache.New(0) // require genuine replay rather than a decoded hit
	source.fail.Store(true)
	for _, r := range [][2]int{{0, 4096}, {ReplayBlockSize - 7, 32}, {chunkSize - 5, 19}, {len(plain) - 11, 32}, {2*chunkSize + ReplayBlockSize, 13}} {
		b := make([]byte, r[1])
		n, err := f.ReadAt(b, int64(r[0]))
		want := plain[r[0]:min(len(plain), r[0]+r[1])]
		if n != len(want) || !bytes.Equal(b[:n], want) || (n < len(b) && err != io.EOF) || (n == len(b) && err != nil) {
			t.Fatalf("range %v n=%d err=%v", r, n, err)
		}
	}
	before := f.Stats()
	var b [4096]byte
	if _, err := f.ReadAt(b[:], 128); err != nil {
		t.Fatal(err)
	}
	after := f.Stats()
	if after.XZChunks != before.XZChunks || after.ReplayBlocks-before.ReplayBlocks != 1 || after.ReplayBytes-before.ReplayBytes != ReplayBlockSize {
		t.Fatalf("4KiB replay expanded more than one page: before=%+v after=%+v", before, after)
	}
}

func TestReplayConcurrentDifferentBlocksShareXZ(t *testing.T) {
	packed, plain, _ := blockFixture(t)
	f, err := OpenWithReplayCache(bytes.NewReader(packed), 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		off := i * 7000
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var b [4096]byte
			n, err := f.ReadAt(b[:], int64(off))
			if err != nil || n != len(b) || !bytes.Equal(b[:], plain[off:off+len(b)]) {
				t.Errorf("concurrent read %d: %v", off, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if s := f.Stats(); s.XZChunks != 1 || s.ReplayCache.Loads != 1 {
		t.Fatalf("duplicate XZ for simultaneous page misses: %+v", s)
	}
}

func TestReplayTinyBudgetDoesNotDecodePerPage(t *testing.T) {
	packed, plain, chunkSize := blockFixture(t)
	f, err := OpenWithReplayCache(bytes.NewReader(packed), 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.cache = bytecache.New(0)
	b := make([]byte, chunkSize)
	if _, err := f.ReadAt(b, 0); err != nil || !bytes.Equal(b, plain[:chunkSize]) {
		t.Fatal(err)
	}
	if s := f.Stats(); s.XZChunks != 1 || s.ReplayCache.Bytes != 0 || s.DecodedCache.Bytes != 0 {
		t.Fatalf("unadmitted chunk decoded repeatedly: %+v", s)
	}
}

func TestReplayBlockIndexRejectsBadBounds(t *testing.T) {
	good := encodeReplay(bytes.Repeat([]byte{'x'}, ReplayBlockSize+3))
	for _, modify := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:3] },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[:], 0); return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 0xffffffff); return b },
		func(b []byte) []byte { b[12] = 0; return b },
	} {
		if _, err := decodeReplayBlock(modify(bytes.Clone(good)), ReplayBlockSize+3, 0); err == nil {
			t.Fatal("invalid internal replay block accepted")
		}
	}
}

// Measures a decoded-cache miss with fast replay retained, not an XZ miss.
func BenchmarkPBZXSmallReplay(b *testing.B) {
	packed, _, _ := blockFixture(b)
	f, err := OpenWithReplayCache(bytes.NewReader(packed), 0, 1<<20)
	if err != nil {
		b.Fatal(err)
	}
	var out [4096]byte
	if _, err = f.ReadAt(out[:], 0); err != nil {
		b.Fatal(err)
	}
	f.cache = bytecache.New(0)
	b.SetBytes(int64(len(out)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.ReadAt(out[:], int64(i%16*4096)); err != nil {
			b.Fatal(err)
		}
	}
}
