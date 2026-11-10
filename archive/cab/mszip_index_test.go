package cab

import (
	"bytes"
	"io"
	"sync"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestMSZIPIndexedRandomReads(t *testing.T) {
	var cabinet, want, history []byte
	for i := 0; i < 256; i++ {
		block := bytes.Repeat([]byte("dictionary contents that cross small CFDATA boundaries"), 19)
		block = append(block, byte(i), byte(i>>8))
		cabinet = appendMSZIPTestDataBlock(cabinet, mszipTestBlock(t, block, history), len(block))
		want = append(want, block...)
		history = want[max(0, len(want)-32768):]
	}
	a := &Archive{file: &starfile.Bytes{Data: cabinet}, folders: []folder{{compression: 1, blocks: 256}}, cache: true, cacheStore: bytecache.New(1 << 20)}
	entry := &Entry{archive: a, file: fileRecord{name: "nested", uncompressedStart: 17, size: uint32(len(want) - 40)}}
	expected := want[17 : len(want)-23]
	// Start at the end, then seek backward across checkpoints and block edges.
	var wg sync.WaitGroup
	for _, off := range []int{len(expected) - 4000, 0, 32000, 900, 180000, 7, 64000} {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			p := make([]byte, 3000)
			n, err := entry.ReadAt(p, int64(off))
			if err != nil || n != len(p) || !bytes.Equal(p, expected[off:off+len(p)]) {
				t.Errorf("read at %d: n=%d err=%v", off, n, err)
			}
		}(off)
	}
	wg.Wait()
	x := a.mszipFolder(0)
	if x.fallback {
		t.Fatal("normal MSZIP required whole-folder fallback")
	}
	retained := len(x.data) + len(x.history)
	for _, checkpoint := range x.checkpoints {
		retained += len(checkpoint)
	}
	if retained > 10*32768 {
		t.Fatalf("checkpoint storage not bounded: %d", retained)
	}
	if a.cacheStore.Stats().Loads != 0 {
		t.Fatal("expanded whole folder retained")
	}
	p := make([]byte, 40)
	if n, err := entry.ReadAt(p, int64(len(expected)-13)); n != 13 || err != io.EOF || !bytes.Equal(p[:n], expected[len(expected)-13:]) {
		t.Fatalf("tail n=%d err=%v", n, err)
	}
	full, err := entry.Bytes()
	if err != nil || !bytes.Equal(full, expected) {
		t.Fatalf("full entry mismatch: %v", err)
	}
}

func BenchmarkMSZIPIndexedRandomSeek(b *testing.B) {
	var cabinet, want, history []byte
	for i := 0; i < 256; i++ {
		block := bytes.Repeat([]byte("dictionary across CFDATA blocks."), 1024)
		block = append(block, byte(i))
		cabinet = appendMSZIPTestDataBlock(cabinet, mszipTestBlock(b, block, history), len(block))
		want = append(want, block...)
		history = want[max(0, len(want)-32768):]
	}
	a := &Archive{file: &starfile.Bytes{Data: cabinet}, folders: []folder{{compression: 1, blocks: 256}}, cache: true, cacheStore: bytecache.New(1 << 20)}
	entry := &Entry{archive: a, file: fileRecord{name: "member", size: uint32(len(want))}}
	p := make([]byte, 4096)
	if _, err := entry.ReadAt(p, int64(len(want)-len(p))); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		off := (i * 7919) % (len(want) - len(p))
		if n, err := entry.ReadAt(p, int64(off)); n != len(p) || err != nil || !bytes.Equal(p, want[off:off+len(p)]) {
			b.Fatalf("seek: %d %v", n, err)
		}
	}
}
