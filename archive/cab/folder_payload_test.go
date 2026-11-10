package cab

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestFolderPayloadExactAllocationAndExtents(t *testing.T) {
	// A small, highly compressed folder in a much larger cabinet must not size
	// its input allocation from either the expanded size or the enclosing file.
	const reserve = 7
	var raw []byte
	var want []byte
	for i := 0; i < 300; i++ {
		header := make([]byte, 8+reserve)
		binary.LittleEndian.PutUint16(header[4:], 3)
		binary.LittleEndian.PutUint16(header[6:], 32768)
		payload := []byte{byte(i), 0, byte(i >> 8)}
		raw = append(raw, header...)
		raw = append(raw, payload...)
		want = append(want, payload...)
	}
	folderEnd := len(raw)
	raw = append(raw, make([]byte, 4<<20)...)
	a := &Archive{file: &starfile.Bytes{Data: raw}, dataReserve: reserve}
	f := folder{blocks: 300}
	got, size, err := a.readFolderPayload(f)
	if err != nil || size != 300*32768 || !bytes.Equal(got, want) {
		t.Fatalf("payload: size=%d err=%v", size, err)
	}
	if cap(got) != len(want) {
		t.Fatalf("retained excess input capacity %d for %d bytes", cap(got), len(want))
	}
	for _, end := range []int{0, 7, 8 + reserve - 1, folderEnd - 1} {
		a.file = &starfile.Bytes{Data: raw[:end]}
		if _, _, err := a.readFolderPayload(f); err == nil {
			t.Fatalf("accepted truncated extent %d", end)
		}
	}
}
