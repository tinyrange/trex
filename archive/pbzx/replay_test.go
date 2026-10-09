package pbzx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	encoder "github.com/ulikunitz/xz"
)

func replayFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	framed := make([]byte, 12)
	copy(framed, "pbzx")
	binary.BigEndian.PutUint64(framed[4:], 4096)
	var plain []byte
	for i := 0; i < 4; i++ {
		data := bytes.Repeat([]byte{byte('A' + i)}, 4096)
		var b bytes.Buffer
		w, err := (encoder.WriterConfig{DictCap: 1 << 20}).NewWriter(&b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var h [16]byte
		binary.BigEndian.PutUint64(h[:], uint64(len(data)))
		binary.BigEndian.PutUint64(h[8:], uint64(b.Len()))
		framed = append(framed, h[:]...)
		framed = append(framed, b.Bytes()...)
		plain = append(plain, data...)
	}
	return framed, plain
}

type observedReader struct {
	*bytes.Reader
	calls atomic.Int64
	fail  atomic.Bool
}

func (r *observedReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls.Add(1)
	if r.fail.Load() {
		return 0, fmt.Errorf("source unavailable")
	}
	return r.Reader.ReadAt(p, off)
}

func TestReplayAvoidsXZAfterDecodedEviction(t *testing.T) {
	packed, plain := replayFixture(t)
	source := &observedReader{Reader: bytes.NewReader(packed)}
	f, err := OpenWithReplayCache(source, 0, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.cache = bytecache.New(4096) // exactly one decoded chunk
	for i := 0; i < 4; i++ {
		b := make([]byte, 4096)
		if _, err := f.ReadAt(b, int64(i*4096)); err != nil || !bytes.Equal(b, plain[i*4096:(i+1)*4096]) {
			t.Fatalf("first read %d: %v", i, err)
		}
	}
	if f.cache.Stats().Evictions != 3 {
		t.Fatal("decoded cache did not evict")
	}
	calls := source.calls.Load()
	source.fail.Store(true)
	// Cross-chunk, backwards, partial EOF, and concurrent reads must all work
	// without touching the now-unavailable original compressed source.
	var wg sync.WaitGroup
	for _, off := range []int64{0, 4090, 8192, 16380, 200, 9000} {
		wg.Add(1)
		go func(off int64) {
			defer wg.Done()
			b := make([]byte, 32)
			n, err := f.ReadAt(b, off)
			end := min(off+32, int64(len(plain)))
			wantErr := error(nil)
			if end-off < 32 {
				wantErr = io.EOF
			}
			if err != wantErr || n != int(end-off) || !bytes.Equal(b[:n], plain[off:end]) {
				t.Errorf("read %d: n=%d err=%v", off, n, err)
			}
		}(off)
	}
	wg.Wait()
	if source.calls.Load() != calls {
		t.Fatal("replayed XZ after decoded eviction")
	}
	if s := f.replay.Stats(); s.Loads != 4 || s.Hits == 0 || s.Bytes > 2048 {
		t.Fatalf("replay stats: %+v", s)
	}
	// The cache's byte charge must equal retained allocations, not the smaller
	// length of a slice backed by an uncompressed-sized encoder allocation.
	for i := 0; i < 4; i++ {
		encoded, err := f.replay.Get(bytecache.Key{Index: i}, func() ([]byte, error) { t.Error("missing replay"); return nil, io.EOF })
		if err != nil || len(encoded) != cap(encoded) {
			t.Fatalf("retention len=%d cap=%d err=%v", len(encoded), cap(encoded), err)
		}
	}
}

func TestReplayEvictionAndDisabled(t *testing.T) {
	packed, _ := replayFixture(t)
	one := int64(len(encodeReplay(bytes.Repeat([]byte{'A'}, 4096))))
	for _, budget := range []int64{0, 1, one} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			source := &observedReader{Reader: bytes.NewReader(packed)}
			f, err := OpenWithReplayCache(source, 0, budget)
			if err != nil {
				t.Fatal(err)
			}
			f.cache = bytecache.New(0)
			for _, index := range []int64{0, 1, 2, 3, 0} {
				before := source.calls.Load()
				var p [1]byte
				if _, err := f.ReadAt(p[:], index*4096); err != nil || p[0] != byte('A'+index) {
					t.Fatalf("%q %v", p, err)
				}
				if source.calls.Load() == before {
					t.Fatal("expected source reload after eviction")
				}
				if f.replay != nil && f.replay.Stats().Bytes > budget {
					t.Fatal("budget exceeded")
				}
			}
		})
	}
	if _, err := OpenWithReplayCache(bytes.NewReader(packed), 0, -1); err == nil {
		t.Fatal("negative budget")
	}
}

func TestReplayDoesNotCacheFailedXZ(t *testing.T) {
	packed := fixture(t)
	packed[12+16+40] ^= 1
	f, err := OpenWithReplayCache(bytes.NewReader(packed), 0, 1<<20)
	if err != nil {
		return
	} // framing/index rejection is also valid
	for i := 0; i < 2; i++ {
		var p [1]byte
		if _, err := f.ReadAt(p[:], 0); err == nil {
			t.Fatal("corrupt XZ accepted")
		}
	}
	if s := f.replay.Stats(); s.Bytes != 0 || s.Loads != 0 {
		t.Fatalf("cached corrupt data: %+v", s)
	}
}
