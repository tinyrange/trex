package windows

import (
	"encoding/binary"
	"testing"
)

func TestBitmapInfoLayout(t *testing.T) {
	header := make([]byte, 40)
	binary.LittleEndian.PutUint32(header, 40)
	binary.LittleEndian.PutUint32(header[4:], 3)
	binary.LittleEndian.PutUint32(header[8:], 0xfffffffe)
	binary.LittleEndian.PutUint16(header[12:], 1)
	binary.LittleEndian.PutUint16(header[14:], 24)
	info, err := parseBitmapInfo(header)
	if err != nil || info.Width != 3 || info.Height != 2 || info.Stride != 12 || info.Size != 24 || !info.TopDown {
		t.Fatalf("layout: %+v, %v", info, err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[12:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[14:], 8) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 1) },
	} {
		bad := append([]byte(nil), header...)
		mutate(bad)
		if _, err := parseBitmapInfo(bad); err == nil {
			t.Fatal("accepted unsupported/invalid DIB")
		}
	}
}
