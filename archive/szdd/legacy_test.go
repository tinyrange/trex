package szdd

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestLegacySZHeaderAndWindowOrigin(t *testing.T) {
	header := []byte{'S', 'Z', ' ', 0x88, 0xf0, 0x27, 0x33, 0xd1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(header[8:], 6)
	file := &starfile.Bytes{Data: append(header, 7, 'a', 'b', 'c', 0xee, 0xf0)}
	data, err := decodeSZDD(file, 100)
	if err != nil || string(data) != "abcabc" {
		t.Fatal(string(data), err)
	}
	if _, err := decodeSZDD(file, 5); err == nil {
		t.Fatal("size limit ignored")
	}
	if _, err := decodeSZDD(&starfile.Bytes{Data: file.Data[:len(file.Data)-1]}, 100); err == nil {
		t.Fatal("truncated match accepted")
	}
}
