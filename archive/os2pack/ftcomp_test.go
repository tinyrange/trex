package os2pack

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func storedBlock(body []byte, flag byte) []byte {
	chunk := []byte{byte(len(body) + 1), byte((len(body) + 1) >> 8), flag}
	chunk = append(chunk, body...)
	b := []byte{0, 0, 0, 0, 'f', 'T', '1', '9', 255, 255, byte(len(chunk)), byte(len(chunk) >> 8)}
	return append(b, chunk...)
}
func TestFT19BlocksAndOverlappingHistory(t *testing.T) {
	b := storedBlock([]byte{'a', 'b', 'c', 0x9e, 3, 2, 0x9e, 0x40}, 1)
	want := []byte("abcabcabc\x9e")
	got, err := DecodeFT19(b, int64(len(want)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal(got, err)
	}
	// History survives block boundaries; distance 0 repeats the previous byte.
	second := storedBlock([]byte{0x9e, 0, 0}, 1)
	joined := append(append([]byte(nil), b...), second[4:]...)
	got, err = DecodeFT19(joined, 13)
	if err != nil || !bytes.Equal(got, append(want, 0x9e, 0x9e, 0x9e)) {
		t.Fatal(got, err)
	}
	for i := 0; i < len(b); i++ {
		if _, err := DecodeFT19(b[:i], 10); err == nil {
			t.Fatalf("accepted prefix %d", i)
		}
	}
	if _, err := DecodeFT19(b, 9); err == nil {
		t.Fatal("accepted output overflow")
	}
	if _, err := DecodeFT19([]byte("\x00\x00\x00\x00fT21"), 4); err == nil {
		t.Fatal("FT21 silently treated as stored")
	}
}
func packMember(name string, body []byte) []byte {
	b := make([]byte, 41+len(name)+1)
	copy(b, []byte{0xa5, 0x96, 0xfd, 0xff})
	copy(b[24:], "FTCOMP\x00")
	binary.LittleEndian.PutUint32(b[16:], uint32(len(body)))
	binary.LittleEndian.PutUint16(b[39:], uint16(len(name)+1))
	copy(b[41:], name)
	b = append(b, 0, 0, 0, 0)
	return append(b, body...)
}
func TestPACK2BoundsAndLimits(t *testing.T) {
	opts := auto.Options{MaxEntries: 8, MaxExpandedBytes: 1024}
	b := packMember("OS2\\sample", []byte("hello"))
	if _, err := Read(&starfile.Bytes{Data: b}, opts); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 42) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[39:], 65535) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 2048) },
	} {
		bad := bytes.Clone(b)
		mutate(bad)
		if _, err := Read(&starfile.Bytes{Data: bad}, opts); err == nil {
			t.Fatal("accepted malformed member")
		}
	}
	if _, err := Read(&starfile.Bytes{Data: packMember("../bad", nil)}, opts); err == nil {
		t.Fatal("accepted traversal")
	}
	second := packMember("second", []byte("world"))
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)))
	b = append(b, second...)
	opts.MaxEntries = 1
	if _, err := Read(&starfile.Bytes{Data: b}, opts); err == nil {
		t.Fatal("ignored member limit")
	}
	opts.MaxEntries = 8
	opts.MaxExpandedBytes = 9
	if _, err := Read(&starfile.Bytes{Data: b}, opts); err == nil {
		t.Fatal("ignored cumulative output limit")
	}
}
func FuzzFT19Bounded(f *testing.F) {
	f.Add(storedBlock([]byte("sample"), 0), uint16(6))
	f.Add(storedBlock([]byte{'A', 0x9e, 0, 0}, 1), uint16(4))
	f.Fuzz(func(t *testing.T, b []byte, n uint16) {
		if len(b) > 65536 {
			return
		}
		out, err := DecodeFT19(b, int64(n))
		if err == nil && len(out) != int(n) {
			t.Fatal("size mismatch")
		}
	})
}
