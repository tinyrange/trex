package floppy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
)

// Hand-authored codes, packed MSB first. This is not a compressor: tests state
// the dictionary operations and expected strings independently of the reader.
func ibmCodes(codes ...uint16) []byte {
	var out []byte
	var bits uint32
	var n uint
	for _, c := range codes {
		bits = bits<<12 | uint32(c)
		n += 12
		for n >= 8 {
			n -= 8
			out = append(out, byte(bits>>n))
		}
	}
	if n != 0 {
		out = append(out, byte(bits<<(8-n)))
	}
	return out
}
func TestIBMLZW(t *testing.T) {
	tests := []struct {
		name  string
		codes []uint16
		want  string
	}{
		{"literals", []uint16{66, 67, 68, 0}, "ABC"},
		{"prefix", []uint16{66, 67, 257, 0}, "ABAB"},
		{"KwKwK", []uint16{66, 257, 258, 0}, "AAAAAA"},
	}
	// Fill all dynamic slots, evict the oldest leaf, then use recycled entries
	// and a prefix dependency. All entries initially encode AA.
	codes := bytes.Repeat([]byte{'A'}, 3841)
	var reuse []uint16
	for range codes {
		reuse = append(reuse, 66)
	}
	reuse = append(reuse, 257, 66, 259, 0)
	tests = append(tests, struct {
		name  string
		codes []uint16
		want  string
	}{"LRU wrap and dependency", reuse, string(bytes.Repeat([]byte{'A'}, 3847))})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeIBMLZW(bytes.NewReader(ibmCodes(tt.codes...)), len(tt.want))
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %d bytes, %v; want %d", len(got), err, len(tt.want))
			}
		})
	}
	for _, codes := range [][]uint16{{257, 0}, {66, 300, 0}, {66, 0}, {66, 67, 0}} {
		if _, err := decodeIBMLZW(bytes.NewReader(ibmCodes(codes...)), 3); err == nil {
			t.Fatalf("accepted malformed/short stream %v", codes)
		}
	}
	valid := ibmCodes(66, 67, 0)
	for end := 0; end < len(valid); end++ {
		if _, err := decodeIBMLZW(bytes.NewReader(valid[:end]), 2); err == nil {
			t.Fatalf("accepted truncation %d", end)
		}
	}
	if _, err := decodeIBMLZW(bytes.NewReader(valid), 1); err == nil {
		t.Fatal("accepted overflow")
	}
}
func savedskfFixture(version byte, data []byte) []byte {
	h := make([]byte, 512)
	h[0], h[1] = 0xaa, version
	put16(h, 2, 0xf0)
	put16(h, 4, 512)
	put16(h, 24, 80)
	put16(h, 26, 2)
	put16(h, 28, 18)
	put16(h, 34, len(data)/512)
	// Zero data offset denotes the historical 512-byte header.
	var checksum uint32
	for i := 0; i < len(data); i += 2 {
		checksum += uint32(binary.LittleEndian.Uint16(data[i:]))
	}
	binary.LittleEndian.PutUint32(h[20:], checksum)
	if version == 0x5a {
		var codes []uint16
		for _, v := range data {
			codes = append(codes, uint16(v)+1)
		}
		return append(h, ibmCodes(append(codes, 0)...)...)
	}
	return append(h, data...)
}
func TestSaveDskFVariantsAndMissingTail(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i * 31)
	}
	for _, v := range []byte{0x58, 0x59, 0x5a} {
		raw := savedskfFixture(v, data)
		f, err := OpenSaveDskF(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if f.Size() != 1474560 || f.ContiguousPrefixSize() != 1024 {
			t.Fatal("incorrect geometry or prefix")
		}
		buf := make([]byte, 8)
		if n, e := f.ReadAt(buf, 509); n != 8 || e != nil || !bytes.Equal(buf, data[509:517]) {
			t.Fatalf("cross-sector read: %d %v", n, e)
		}
		if n, e := f.ReadAt(buf, 1020); n != 4 || !errors.Is(e, ErrMissingTrack) || !bytes.Equal(buf[:n], data[1020:]) {
			t.Fatalf("missing tail: %d %v", n, e)
		}
		if _, e := f.ReadAt(buf, f.Size()); e != io.EOF {
			t.Fatal(e)
		}
		result, e := auto.Identify(bytes.NewReader(raw), auto.Options{})
		if e != nil || result.Format != "savedskf" {
			t.Fatalf("identify: %v %v", result, e)
		}
		if _, e = OpenSaveDskF(bytes.NewReader(raw[:len(raw)-1])); e == nil {
			t.Fatal("accepted truncated image")
		}
	}
}
func TestSaveDskFRejectsInvalidHeaderAndChecksum(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0 }, func(b []byte) { b[1] = 0x57 },
		func(b []byte) { put16(b, 4, 0) }, func(b []byte) { put16(b, 24, 65535) },
		func(b []byte) { put16(b, 26, 0) }, func(b []byte) { put16(b, 28, 65535) },
		func(b []byte) { put16(b, 34, 65535) }, func(b []byte) { put16(b, 34, 0) },
		func(b []byte) { put16(b, 38, 39) }, func(b []byte) { put16(b, 38, 65535) },
		func(b []byte) { put16(b, 36, 513) }, func(b []byte) { b[20] ^= 1 },
	} {
		raw := savedskfFixture(0x5a, make([]byte, 512))
		mutate(raw)
		if _, err := OpenSaveDskF(bytes.NewReader(raw)); err == nil {
			t.Fatal("accepted invalid image")
		}
	}
	raw := savedskfFixture(0x59, make([]byte, 512))
	raw[600] = 1
	if _, err := OpenSaveDskF(bytes.NewReader(raw)); err == nil {
		t.Fatal("accepted bad payload checksum")
	}
}
func FuzzSaveDskF(f *testing.F) {
	f.Add(savedskfFixture(0x5a, make([]byte, 512)))
	f.Add(savedskfFixture(0x59, make([]byte, 512)))
	f.Fuzz(func(t *testing.T, b []byte) {
		disk, err := OpenSaveDskF(bytes.NewReader(b))
		if err == nil {
			if disk.Size() > 84*2*40*512 {
				t.Fatal("unbounded image")
			}
			var p [513]byte
			disk.ReadAt(p[:], 0)
			disk.ReadAt(p[:], disk.ContiguousPrefixSize()-1)
		}
	})
}
