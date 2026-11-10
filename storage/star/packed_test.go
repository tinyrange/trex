package star

import (
	"bytes"
	"io"
	"math/rand/v2"
	"sync"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

func TestRetainedFileRandomReadsEvictionAndOwnership(t *testing.T) {
	store, err := NewPackedFileStore(64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	store.cache = bytecache.New(PackedChunkBytes) // Exactly one decoded chunk.
	rng := rand.New(rand.NewPCG(12, 34))
	input := make([]byte, PackedChunkBytes*3+13)
	for i := 0; i < PackedChunkBytes; i++ {
		input[i] = byte(rng.Uint32())
	}
	copy(input[PackedChunkBytes:], bytes.Repeat([]byte("verified PE output "), PackedChunkBytes/4))
	want := bytes.Clone(input)
	file, err := store.Pack("first", input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	packed := file.(*PackedFile)
	if !packed.chunks[0].raw || packed.chunks[1].raw {
		t.Fatal("incompressible and compressed chunk selection")
	}
	// Reusing the encoder must neither alias prior chunks nor its decoded cache.
	other, err := store.Pack("other", bytes.Repeat([]byte{0x7a}, len(want)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		off := rng.IntN(len(want))
		size := rng.IntN(PackedChunkBytes*2) + 1
		got := make([]byte, size)
		n, err := file.ReadAt(got, int64(off))
		expected := min(size, len(want)-off)
		if n != expected || !bytes.Equal(got[:n], want[off:off+n]) || (n < size && err != io.EOF) || (n == size && err != nil) {
			t.Fatalf("read %d+%d: n=%d err=%v", off, size, n, err)
		}
		if _, err := other.ReadAt(got[:1], int64(off)); err != nil || got[0] != 0x7a {
			t.Fatalf("cache namespace: %v", err)
		}
	}
	if stats := store.cache.Stats(); stats.Bytes > PackedChunkBytes || stats.Evictions == 0 {
		t.Fatalf("cache not bounded/evicted: %+v", stats)
	}
	if _, err := file.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("mutable retained file")
	}
	if _, err := file.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative offset accepted")
	}
	if n, err := file.ReadAt(make([]byte, 1), file.Size()); n != 0 || err != io.EOF {
		t.Fatalf("EOF: %d %v", n, err)
	}
	if n, err := file.ReadAt(nil, file.Size()); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
}

func TestRetainedFileConcurrentReadsAndCompactRetention(t *testing.T) {
	store, err := NewPackedFileStore(64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("verified target instructions and metadata"), 16000)
	file, err := store.Pack("target", input)
	if err != nil {
		t.Fatal(err)
	}
	packed := file.(*PackedFile)
	stored := 0
	for _, chunk := range packed.chunks {
		stored += len(chunk.data)
	}
	if stored >= len(input)/4 {
		t.Fatalf("retained %d of %d compressible bytes", stored, len(input))
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for off := i; off < len(input); off += 997 {
				data := make([]byte, min(8192, len(input)-off))
				if _, err := file.ReadAt(data, int64(off)); err != nil || !bytes.Equal(data, input[off:off+len(data)]) {
					t.Errorf("concurrent read at%d: %v", off, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRetainedChunksShareExactImmutableContent(t *testing.T) {
	store, err := NewPackedFileStore(64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("abcdefgh"), PackedChunkBytes/4)
	first, err := store.Pack("first", input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Pack("second", input)
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.(*PackedFile), second.(*PackedFile)
	if len(store.chunks) != 1 || &a.chunks[0].data[0] != &a.chunks[1].data[0] || &a.chunks[0].data[0] != &b.chunks[0].data[0] {
		t.Fatal("identical regions were retained independently")
	}
	want := bytes.Clone(input)
	clear(input)
	got := make([]byte, len(want))
	if _, err := second.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("shared chunk changed: %v", err)
	}
	// A hash-index collision must never substitute different encoded bytes.
	for key := range store.chunks {
		store.chunks[key] = []byte("wrong bytes")
	}
	third, err := store.Pack("collision", want)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("digest-only deduplication: %v", err)
	}
}

func TestRetainedFileSmallAndEmpty(t *testing.T) {
	store, err := NewPackedFileStore(64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{nil, []byte("small manifest")} {
		want := bytes.Clone(input)
		file, err := store.Pack("small", input)
		if err != nil {
			t.Fatal(err)
		}
		clear(input)
		got, err := ReadAll(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("small file: %q %v", got, err)
		}
	}
}

type snapshotSource struct {
	data           []byte
	calls, largest int
	fail           bool
}

func (s *snapshotSource) Size() int64 { return int64(len(s.data)) }
func (s *snapshotSource) ReadAt(p []byte, off int64) (int, error) {
	s.calls++
	s.largest = max(s.largest, len(p))
	if s.fail {
		return 0, io.ErrUnexpectedEOF
	}
	return bytes.NewReader(s.data).ReadAt(p, off)
}

func TestPackedSnapshotStreamingBoundsAndOwnership(t *testing.T) {
	store, err := NewPackedFileStore(PackedChunkBytes, false)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("snapshot test bytes"), 10000)
	source := &snapshotSource{data: bytes.Clone(want)}
	if _, err := store.Snapshot("too big", source, int64(len(want)-1)); err == nil || source.calls != 0 {
		t.Fatal("bound must reject before reading")
	}
	file, err := store.Snapshot("snapshot", source, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if source.largest > PackedChunkBytes || source.calls < 2 {
		t.Fatal("unbounded read", source.largest, source.calls)
	}
	before := source.calls
	clear(source.data)
	source.fail = true
	got, err := ReadAll(file)
	if err != nil || !bytes.Equal(got, want) || source.calls != before {
		t.Fatalf("snapshot retained source: %v", err)
	}
	if _, err := store.Snapshot("failed", source, int64(len(want))); err == nil {
		t.Fatal("read failure accepted")
	}
	source.fail = false
	// A failed snapshot must not poison subsequent source IDs/cache contents.
	other, err := store.Snapshot("zeros", source, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	got, err = ReadAll(other)
	if err != nil || !bytes.Equal(got, source.data) {
		t.Fatal("failed snapshot contaminated later content", err)
	}
	got, err = ReadAll(file)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("later snapshot contaminated first", err)
	}
	if stats := store.CacheStats(); stats.Bytes > PackedChunkBytes || stats.Evictions == 0 {
		t.Fatal(stats)
	}
	if store.Deduplicates() {
		t.Fatal("unbounded encoded dedup retention")
	}
}
