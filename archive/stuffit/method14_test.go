package stuffit

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func block14(symbol int) []byte {
	w := bitWriter{}
	for _, spec := range [][2]int{{308, symbol}, {75, 0}} {
		w.put(5, 8) // Four-bit lengths: token14=zero, token0=length1.
		for i := 0; i < spec[0]; i++ {
			v := uint32(14)
			if i == spec[1] {
				v = 0
			}
			w.put(v, 4)
		}
		w.put(0, (8-w.pos%8)%8)
	}
	w.put(0, 1) // The only literal/length code is zero.
	decoded := uint32(1)
	if symbol >= 256 {
		w.put(0, 1)
		decoded = 4
	} // distance1, length4.
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header, uint32(len(w.data)+8))
	binary.LittleEndian.PutUint32(header[4:], decoded)
	return append(header, w.data...)
}
func fixture14() []byte {
	b := append([]byte{2, 0}, block14('A')...)
	return append(b, block14(256)...)
}
func TestInstaller14History(t *testing.T) {
	out, err := decode14(fixture14(), 5)
	if err != nil || !bytes.Equal(out, []byte("AAAAA")) {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := decode14(append([]byte{1, 0}, block14(256)...), 4); err == nil {
		t.Fatal("invented initial history")
	}
	if _, err := decode14(fixture14(), 4); err == nil {
		t.Fatal("ignored output size")
	}
}

func TestInstaller14ArchiveCRC(t *testing.T) {
	b := fixture()[:134]
	b[22] = 14
	binary.BigEndian.PutUint32(b[22+84:], 5)
	compressed := fixture14()
	binary.BigEndian.PutUint32(b[22+92:], uint32(len(compressed)))
	binary.BigEndian.PutUint16(b[22+100:], crc16([]byte("AAAAA")))
	binary.BigEndian.PutUint16(b[22+110:], crc16(b[22:132]))
	b = append(b, compressed...)
	b = append(b, []byte("data")...)
	binary.BigEndian.PutUint32(b[6:], uint32(len(b)))
	a, err := Open(&starfile.Bytes{Data: b}, 10, 4096)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(a.Entries[0].Resource)
	if err != nil || string(got) != "AAAAA" {
		t.Fatalf("%q %v", got, err)
	}
	b[22+100] ^= 1
	binary.BigEndian.PutUint16(b[22+110:], crc16(b[22:132]))
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 4096); err == nil || !strings.Contains(err.Error(), "fork 0: CRC mismatch") {
		t.Fatalf("did not verify decoded fork CRC: %v", err)
	}
}
func TestInstaller14Malformed(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:1] },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[0] = 3; return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[2:], 7); return b },
		func(b []byte) []byte { binary.LittleEndian.PutUint32(b[6:], 65537); return b },
	} {
		if _, err := decode14(mutate(fixture14()), 5); err == nil {
			t.Fatal("accepted malformed blocks")
		}
	}
}
func FuzzInstaller14(f *testing.F) {
	f.Add(fixture14(), 5)
	f.Fuzz(func(t *testing.T, input []byte, size int) {
		if size < 0 || size > 4096 || len(input) > 4096 {
			return
		}
		out, err := decode14(input, size)
		if err == nil && len(out) != size {
			t.Fatal("decoded size")
		}
	})
}
