package compressed

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/ulikunitz/xz/lzma"
)

func lzmaFixture(t *testing.T, data []byte, known bool) []byte {
	t.Helper()
	var output bytes.Buffer
	cfg := lzma.WriterConfig{DictCap: 4096}
	if known {
		cfg.SizeInHeader = true
		cfg.Size = int64(len(data))
	}
	w, err := cfg.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestLZMAFramingAndLimits(t *testing.T) {
	content := bytes.Repeat([]byte("bounded standalone LZMA payload\n"), 50000)
	for _, known := range []bool{false, true} {
		encoded := lzmaFixture(t, content, known)
		source := &starfile.Bytes{Data: encoded}
		file, err := OpenLZMA(source, int64(len(content)), 4096)
		if err != nil {
			t.Fatalf("known=%v: %v", known, err)
		}
		got := make([]byte, len(content))
		if _, err := file.ReadAt(got, 0); err != nil || !bytes.Equal(got, content) {
			t.Fatalf("roundtrip: %v", err)
		}
		// Exercise reads across the immutable chunk boundary and past EOF.
		cross := make([]byte, 32)
		if _, err := file.ReadAt(cross, chunkSize-8); err != nil || !bytes.Equal(cross, content[chunkSize-8:chunkSize+24]) {
			t.Fatalf("cross-chunk: %v", err)
		}
		if n, err := file.ReadAt(cross, int64(len(content)-3)); n != 3 || err != io.EOF {
			t.Fatalf("EOF: %d %v", n, err)
		}
		variants := map[string][]byte{
			"truncated":      encoded[:len(encoded)-3],
			"trailing":       append(append([]byte{}, encoded...), 0),
			"concatenated":   append(append([]byte{}, encoded...), encoded...),
			"bad-properties": append([]byte{255}, encoded[1:]...),
		}
		excessiveDict := append([]byte{}, encoded...)
		binary.LittleEndian.PutUint32(excessiveDict[1:5], 1<<30)
		variants["dictionary"] = excessiveDict
		wrongSize := append([]byte{}, encoded...)
		binary.LittleEndian.PutUint64(wrongSize[5:13], uint64(len(content)+1))
		variants["size"] = wrongSize
		for name, value := range variants {
			if _, err := OpenLZMA(&starfile.Bytes{Data: value}, int64(len(content)+2), 4096); err == nil {
				t.Fatalf("accepted %s known=%v", name, known)
			}
		}
		if _, err := OpenLZMA(source, int64(len(content)-1), 4096); err == nil {
			t.Fatal("accepted output beyond limit")
		}
	}
}
