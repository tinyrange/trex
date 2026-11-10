package cab

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

type rawCountingSource struct {
	*starfile.Bytes
	bytes atomic.Int64
}

func (r *rawCountingSource) ReadAt(p []byte, off int64) (int, error) {
	n, e := r.Bytes.ReadAt(p, off)
	r.bytes.Add(int64(n))
	return n, e
}

func TestRawFolderRandomAccess(t *testing.T) {
	// An entry starts inside a block and crosses a split block with reserves.
	var data, logical []byte
	for i, s := range []string{"012345", "678", "9abc", "defghi"} {
		header := make([]byte, 10)
		binary.LittleEndian.PutUint16(header[4:], uint16(len(s)))
		decoded := len(s)
		if i == 1 {
			decoded = 0
		}
		if i == 2 {
			decoded = 7
		}
		binary.LittleEndian.PutUint16(header[6:], uint16(decoded))
		data = append(append(data, header...), s...)
		logical = append(logical, s...)
	}
	source := &rawCountingSource{Bytes: &starfile.Bytes{Data: data}}
	a := &Archive{file: source, dataReserve: 2, folders: []folder{{blocks: 4}}, cache: true, cacheStore: bytecache.New(1 << 20)}
	entry := &Entry{archive: a, file: fileRecord{name: "slice", uncompressedStart: 2, size: 14}}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := make([]byte, 5)
			off := int64(i % 9)
			n, err := entry.ReadAt(b, off)
			if err != nil || n != 5 || !bytes.Equal(b, logical[2+off:7+off]) {
				t.Errorf("read %d = %q %d %v", off, b, n, err)
			}
		}(i)
	}
	wg.Wait()
	if got := source.bytes.Load(); got != 40+12*5 {
		t.Fatalf("read %d bytes; want headers once plus requested extents", got)
	}
	b := make([]byte, 5)
	if n, err := entry.ReadAt(b, 12); n != 2 || err != io.EOF || string(b[:n]) != "ef" {
		t.Fatalf("tail %q %d %v", b, n, err)
	}
	if a.cacheStore.Stats().Loads != 0 {
		t.Fatal("raw folder was materialized")
	}
	full, err := entry.Bytes()
	if err != nil || !bytes.Equal(full, logical[2:16]) {
		t.Fatalf("Bytes %q %v", full, err)
	}
	var out bytes.Buffer
	if n, err := entry.WriteTo(&out); n != 14 || err != nil || !bytes.Equal(out.Bytes(), full) {
		t.Fatalf("WriteTo %d %v", n, err)
	}
}

func TestRawFolderRejectsInvalidExtents(t *testing.T) {
	for _, kind := range []string{"short-header", "short-block", "bad-length", "split-tail", "member-overrun"} {
		t.Run(kind, func(t *testing.T) {
			data := make([]byte, 12)
			binary.LittleEndian.PutUint16(data[4:], 4)
			binary.LittleEndian.PutUint16(data[6:], 4)
			size := uint32(4)
			switch kind {
			case "short-header":
				data = data[:7]
			case "short-block":
				data = data[:11]
			case "bad-length":
				binary.LittleEndian.PutUint16(data[6:], 3)
			case "split-tail":
				binary.LittleEndian.PutUint16(data[6:], 0)
			case "member-overrun":
				size = 5
			}
			a := &Archive{file: &starfile.Bytes{Data: data}, folders: []folder{{blocks: 1}}}
			e := &Entry{archive: a, file: fileRecord{size: size}}
			if _, err := e.ReadAt(make([]byte, 1), 0); err == nil {
				t.Fatal("invalid extent accepted")
			}
		})
	}
}
