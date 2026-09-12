package sevenzip

import (
	"bytes"
	"io"
	"sync"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestSevenZipSparseReadsBoundCacheAndVerifyCRC(t *testing.T) {
	payload := make([]byte, 5<<20)
	for i := range payload {
		payload[i] = byte(i*31 + i/251)
	}
	encoded := sevenZipTestCopyArchive("large.bin", payload)
	a, err := Open(&starfile.Bytes{Data: encoded}, 10, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	value, _, _ := a.Get(starlark.String("large.bin"))
	entry := value.(*Entry)
	for off := int64(0); off < int64(len(payload)); off += sevenZipPageSize {
		got := make([]byte, 31)
		if _, err := entry.ReadAt(got, off); err != nil || !bytes.Equal(got, payload[off:off+31]) {
			t.Fatalf("offset%d: %v", off, err)
		}
	}
	if len(entry.folder.pages) > sevenZipCachedPages {
		t.Fatalf("cached %d pages", len(entry.folder.pages))
	}
	if !entry.verified {
		t.Fatal("full stream did not verify entry CRC")
	}
	// Evicted earlier pages replay without losing cached pages or checksum state.
	var wg sync.WaitGroup
	for _, off := range []int64{17, 1 << 20, 3 << 20, 4 << 20} {
		wg.Add(1)
		go func(off int64) {
			defer wg.Done()
			got := make([]byte, 101)
			_, err := entry.ReadAt(got, off)
			if err != nil || !bytes.Equal(got, payload[off:off+101]) {
				t.Errorf("backward offset%d: %v", off, err)
			}
		}(off)
	}
	wg.Wait()
	encoded[32+len(payload)-1] ^= 1
	bad, err := Open(&starfile.Bytes{Data: encoded}, 10, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	corrupt, _, _ := bad.Get(starlark.String("large.bin"))
	if _, err := corrupt.(*Entry).ReadAt(make([]byte, 1), int64(len(payload)-1)); err == nil {
		t.Fatal("discarded-prefix decoding skipped CRC verification")
	}
}
func TestLZMAHistoryAcrossDictionaryWrap(t *testing.T) {
	model := &lzmaReader{dictionary: make([]byte, 257), dictionarySize: 257}
	output := make([]byte, 2000)
	for i := range output {
		output[i] = byte(i*7 + i/13)
		model.put(output[i])
	}
	for _, off := range []int{1743, 1800, 1950} {
		p := make([]byte, min(100, len(output)-off))
		if !model.history(p, uint64(off)) || !bytes.Equal(p, output[off:off+len(p)]) {
			t.Fatalf("history offset%d", off)
		}
	}
	if model.history(make([]byte, 1), 1742) {
		t.Fatal("accepted evicted history")
	}
	if model.history(make([]byte, 2), 1999) {
		t.Fatal("accepted future history")
	}
	for distance := uint32(0); distance < 257; distance++ {
		b, err := model.dictionaryByte(distance)
		if err != nil || b != output[len(output)-1-int(distance)] {
			t.Fatalf("distance%d: %v", distance, err)
		}
	}
}
func TestSevenZipUsesDictionaryWithoutReplaying(t *testing.T) {
	model := &lzmaReader{dictionary: make([]byte, 4*sevenZipPageSize), dictionarySize: uint64(4 * sevenZipPageSize)}
	output := make([]byte, 6*sevenZipPageSize)
	for i := range output {
		output[i] = byte(i * 17)
		model.put(output[i])
	}
	folder := &sevenZipFolderData{reader: model, position: int64(len(output)), unpackSize: int64(len(output)), done: true}
	p := make([]byte, 50)
	if _, err := folder.readAtLocked(p, 3*sevenZipPageSize+33); err != nil || !bytes.Equal(p, output[3*sevenZipPageSize+33:3*sevenZipPageSize+83]) {
		t.Fatal(err)
	}
	if folder.reader != model || folder.position != int64(len(output)) {
		t.Fatal("history read restarted decoder")
	}
}
func TestSevenZipPartialEOF(t *testing.T) {
	a, err := Open(&starfile.Bytes{Data: sevenZipTestCopyArchive("x", []byte("abc"))}, 10, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	v, _, _ := a.Get(starlark.String("x"))
	p := make([]byte, 5)
	n, err := v.(*Entry).ReadAt(p, 1)
	if n != 2 || err != io.EOF || string(p[:n]) != "bc" {
		t.Fatal(n, err, string(p))
	}
}
