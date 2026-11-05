package omaha

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/ulikunitz/xz/lzma"
)

func TestPayloadFraming(t *testing.T) {
	// One transformed call: absolute address 0x12345678 becomes a relative
	// displacement 0x12345673. Header sizes are independent stream bounds.
	framed := make([]byte, 20)
	for i, v := range []uint32{5, 1, 4, 0, 5} {
		binary.LittleEndian.PutUint32(framed[4*i:], v)
	}
	framed = append(framed, 0xe8, 0x12, 0x34, 0x56, 0x78, 0, 0x7f, 0xff, 0xfc, 0)
	var compressed bytes.Buffer
	w, err := (lzma.WriterConfig{DictCap: 4096, SizeInHeader: true, Size: int64(len(framed))}).NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(framed); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	decoded, err := Open(&starfile.Bytes{Data: compressed.Bytes()}, 1000, 4096)
	if err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(io.NewSectionReader(decoded, 0, decoded.Size()))
	if err != nil || !bytes.Equal(result, []byte{0xe8, 0x73, 0x56, 0x34, 0x12}) {
		t.Fatalf("decoded %x: %v", result, err)
	}
	invalid := map[string][]byte{
		"short":            framed[:19],
		"truncated-stream": framed[:len(framed)-1],
		"trailing":         append(append([]byte{}, framed...), 0),
	}
	for name, index := range map[string]int{"output-overflow": 0, "main-overflow": 1, "call-overflow": 2, "jump-overflow": 3, "range-overflow": 4} {
		b := append([]byte{}, framed...)
		binary.LittleEndian.PutUint32(b[index*4:], 0xffffffff)
		invalid[name] = b
	}
	b := append([]byte{}, framed...)
	b[len(b)-1] = 1
	invalid["unfinished-range"] = b
	for name, b := range invalid {
		if _, err := decodeBCJ2(&starfile.Bytes{Data: b}, 1000); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, err := decodeBCJ2(&starfile.Bytes{Data: framed}, 4); err == nil {
		t.Fatal("accepted output beyond limit")
	}
}
