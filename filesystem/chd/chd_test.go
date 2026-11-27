package chd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func testImage() []byte {
	b := make([]byte, 1536)
	copy(b, "MComprHD")
	be := binary.BigEndian
	be.PutUint32(b[8:], headerSize)
	be.PutUint32(b[12:], 5)
	be.PutUint64(b[32:], 1408)
	be.PutUint64(b[40:], headerSize)
	be.PutUint32(b[56:], 512)
	be.PutUint32(b[60:], 128)
	be.PutUint32(b[124:], 2)
	be.PutUint32(b[132:], 1)
	copy(b[512:], bytes.Repeat([]byte{0x2a}, 512))
	copy(b[1024:], bytes.Repeat([]byte{0x81}, 512))
	return b
}

func TestUncompressedHunks(t *testing.T) {
	im, err := Open(&starfile.Bytes{Data: testImage()})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1000)
	n, err := im.ReadAt(data, 500)
	if n != 908 || !errors.Is(err, io.EOF) || im.Size() != 1408 {
		t.Fatalf("read returned %d bytes, %v at size %d", n, err, im.Size())
	}
	want := append(bytes.Repeat([]byte{0x81}, 12), make([]byte, 512)...)
	want = append(want, bytes.Repeat([]byte{0x2a}, 384)...)
	if !bytes.Equal(data[:n], want) {
		t.Fatal("contents did not follow the hunk map")
	}
}

func TestRejectInvalidCHDMap(t *testing.T) {
	for name, offset := range map[string]int{"compression": 16, "out-of-range hunk": 124, "parent": 104} {
		t.Run(name, func(t *testing.T) {
			b := testImage()
			b[offset] = 1
			if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
				t.Fatal("accepted invalid CHD")
			}
		})
	}
}
