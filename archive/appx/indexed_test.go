package appx

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"
)

type countedPackage struct {
	*bytes.Reader
	read atomic.Int64
}

func (r *countedPackage) ReadAt(p []byte, off int64) (int, error) {
	n, e := r.Reader.ReadAt(p, off)
	r.read.Add(int64(n))
	return n, e
}

func indexedFixture(t *testing.T, payload []byte, badHash bool) []byte {
	t.Helper()
	var compressed bytes.Buffer
	body := fmt.Sprintf(`<File Name="data.bin" Size="%d">`, len(payload))
	for off := 0; off < len(payload); off += blockSize {
		block := payload[off:min(off+blockSize, len(payload))]
		start := compressed.Len()
		w, err := flate.NewWriter(&compressed, flate.BestSpeed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(block); err != nil {
			t.Fatal(err)
		}
		if err = w.Flush(); err != nil {
			t.Fatal(err)
		}
		// Fresh writers give independent dictionaries; Flush leaves BFINAL unset.
		size := compressed.Len() - start
		hash := sha256.Sum256(block)
		if badHash && off == 0 {
			hash[0] ^= 1
		}
		body += fmt.Sprintf(`<Block Hash="%s" Size="%d"/>`, base64.StdEncoding.EncodeToString(hash[:]), size)
	}
	compressed.Write([]byte{1, 0, 0, 255, 255})
	body += `</File>` + mapFile("AppxManifest.xml", []byte(manifest))
	bm := `<BlockMap xmlns="` + blockMapNamespace + `" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">` + body + `</BlockMap>`
	var result bytes.Buffer
	z := zip.NewWriter(&result)
	raw, err := z.CreateRaw(&zip.FileHeader{Name: "data.bin", Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(payload), CompressedSize64: uint64(compressed.Len()), UncompressedSize64: uint64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Write(compressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []fixtureEntry{{"AppxManifest.xml", []byte(manifest)}, {"AppxBlockMap.xml", []byte(bm)}} {
		w, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestIndexedBlocksRandomRead(t *testing.T) {
	payload := make([]byte, 10<<20|123)
	rand.New(rand.NewSource(51)).Read(payload)
	source := &countedPackage{Reader: bytes.NewReader(indexedFixture(t, payload, false))}
	a, err := Open(source)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Entries[0]
	if e.index == nil {
		t.Fatal("index missing")
	}
	// Cold reads near the end must not decode/re-read the prefix.
	source.read.Store(0)
	buf := make([]byte, 37)
	off := int64(len(payload) - 100)
	n, err := e.ReadAt(buf, off)
	if err != nil || n != len(buf) || !bytes.Equal(buf, payload[off:off+int64(len(buf))]) {
		t.Fatalf("cold read %d %v", n, err)
	}
	if got := source.read.Load(); got > blockSize+1024 {
		t.Fatalf("random read replayed prefix: %d", got)
	}
	// Across blocks, backwards across the old 8MiB window, and partial EOF.
	for _, off := range []int64{blockSize - 5, 3, int64(len(payload)) - 300, 0, 9 << 20, 10} {
		p := make([]byte, 900)
		n, err := e.ReadAt(p, off)
		want := min(len(p), len(payload)-int(off))
		if n != want || !bytes.Equal(p[:n], payload[off:off+int64(want)]) || (err != nil && err != io.EOF) {
			t.Fatalf("offset %d: %d %v", off, n, err)
		}
	}
	if n, err := e.ReadAt(buf, int64(len(payload))); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	if _, err := e.ReadAt(buf, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
	if n, err := e.ReadAt(nil, int64(len(payload))); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if err := a.VerifyBlockMap(20 << 20); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	// Starlark bytes/slice methods must retain the indexed Entry, not its
	// embedded generic ZIP reader (which would reintroduce prefix replay).
	source.read.Store(0)
	method, err := e.Attr("bytes")
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(&starlark.Thread{}, method, starlark.Tuple{starlark.MakeInt(9 << 20), starlark.MakeInt(11)}, nil)
	if err != nil || string(value.(starlark.Bytes)) != string(payload[9<<20:(9<<20)+11]) {
		t.Fatal(value, err)
	}
	if source.read.Load() > blockSize+1024 {
		t.Fatal("Starlark method bypassed index")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := make([]byte, 87)
			off := int64(i*blockSize + 17)
			if _, err := e.ReadAt(p, off); err != nil || !bytes.Equal(p, payload[off:off+87]) {
				t.Errorf("concurrent read %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestIndexedBlockHashFailure(t *testing.T) {
	a, err := Open(bytes.NewReader(indexedFixture(t, bytes.Repeat([]byte("payload"), 20000), true)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Entries[0].ReadAt(make([]byte, 5), 3); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered map accepted: %v", err)
	}
	if err = a.VerifyBlockMap(1 << 20); err == nil {
		t.Fatal("verification accepted bad hash")
	}
}
