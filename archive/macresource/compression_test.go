package macresource

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func compressedSample(id uint16, size int, payload []byte) []byte {
	b := make([]byte, 18)
	be := binary.BigEndian
	be.PutUint32(b, 0xa89f6572)
	be.PutUint16(b[4:], 18)
	b[6], b[7] = 8, 1
	be.PutUint32(b[8:], uint32(size))
	be.PutUint16(b[14:], id)
	return append(b, payload...)
}
func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCompressedTokens(t *testing.T) {
	if len(dcmp0Words) != 0xfd-0x4b+1 || len(dcmp1Words) != 0xfd-0xd5+1 {
		t.Fatal("dictionary lengths")
	}
	for _, tc := range []struct {
		name        string
		id          uint16
		input, want string
		trim        bool
	}{
		{"word dictionary", 0, "116162234b4cfdff", "6162616200004eba4841", false},
		{"long word literal", 0, "1001616223ff", "61626162", false},
		{"byte dictionary", 1, "1261626320d5fdff", "61626361626300003637", false},
		{"long byte literal", 1, "d102616220d00163ff", "6162616263", false},
		{"byte RLE", 1, "fe024102ff", "414141", false},
		{"word RLE", 0, "fe03c12301ff", "01230123", false},
		{"delta16 wrap", 0, "fe04feff0201ffff", "3eff3f003eff", false},
		{"delta16 signed", 0, "fe04bfff0201ffff", "ffff0000ffff", false},
		{"delta32 wrap", 0, "fe06ffffffffff0201bfffff", "ffffffff00000000ffffffff", false},
		{"jump table", 0, "010010fe000202200eff", "00103f3c0002a9f000203f3c0002a9f000283f3c0002a9f0", false},
		{"jump veneer delta", 0, "fe01200401bffeff", "610000204eedfffe610000184eed0002", false},
		{"jump veneer explicit", 0, "fe012000010206ff", "610000204eed0002610000184eed0006", false},
		{"odd word padding", 0, "026162637fff", "616263", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := unhex(tc.want)
			f, err := DecodeCompressed(&starfile.Bytes{Data: compressedSample(tc.id, len(want), unhex(tc.input))}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := starfile.ReadAll(f)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x: %v", got, want, err)
			}
		})
	}
}
func TestCompressedMalformed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    uint16
		size  int
		input string
	}{
		{"missing end", 0, 2, "4b"}, {"trailing", 0, 2, "4bff00"},
		{"short output", 1, 2, "0041ff"}, {"overflow", 1, 1, "014142ff"},
		{"bad dictionary", 0, 2, "23ff"}, {"short literal", 0, 4, "026162"},
		{"bad token", 1, 0, "d3ff"}, {"bad extended", 1, 0, "fe030000ff"},
		{"negative count", 0, 1, "fe0241bfffff"}, {"large count", 0, 1, "fe0241ff7fffffff"},
		{"byte value overflow", 0, 1, "fe02c10000ff"}, {"word value overflow", 0, 2, "fe03ff0001000000ff"},
		{"bad jump count", 0, 6, "fe000000ff"}, {"jump range", 0, 14, "fe000001ffffffffff"},
		{"short integer", 0, 4, "fe06ff0000"}, {"extra word padding", 0, 1, "0241424344ff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeCompressed(&starfile.Bytes{Data: compressedSample(tc.id, tc.size, unhex(tc.input))}, 1<<20); err == nil {
				t.Fatal("accepted malformed stream")
			}
		})
	}
	b := compressedSample(0, 100, []byte{0xff})
	if _, err := DecodeCompressed(&starfile.Bytes{Data: b}, 99); err == nil {
		t.Fatal("ignored output limit")
	}
	if _, err := DecodeCompressed(&starfile.Bytes{Data: b}, 18); err == nil {
		t.Fatal("ignored input limit")
	}
}

func TestLongLiteralInteger(t *testing.T) {
	// Extended literal lengths use the same variable-length integer as the
	// extended commands, not a single byte (PowerPC Enabler lpch resources).
	for _, id := range []uint16{0, 1} {
		for _, store := range []bool{false, true} {
			tag := byte(0)
			if store {
				tag = 0x10
			}
			width := 2
			if id == 1 {
				tag = 0xd0
				if store {
					tag++
				}
				width = 1
			}
			want := bytes.Repeat([]byte{0x41}, 128*width)
			input := append([]byte{tag, 0xc0, 0x80}, want...)
			if store {
				if id == 0 {
					input = append(input, 0x23)
				} else {
					input = append(input, 0x20)
				}
				want = append(want, want...)
			}
			input = append(input, 0xff)
			f, err := DecodeCompressed(&starfile.Bytes{Data: compressedSample(id, len(want), input)}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := starfile.ReadAll(f)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("codec%d store%v: %x %v", id, store, got, err)
			}
		}
	}
}

func TestResourceCompressedIntegration(t *testing.T) {
	b := sample()
	payload := compressedSample(1, 3, unhex("02414243ff"))
	binary.BigEndian.PutUint32(b[8:], uint32(4+len(payload)))
	binary.BigEndian.PutUint32(b[256:], uint32(len(payload)))
	copy(b[260:], payload)
	binary.BigEndian.PutUint16(b[546:], 0) // One resource.
	b[554] = 1
	f, err := OpenWithLimits(&starfile.Bytes{Data: b}, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	e := f.Entries[0]
	got, err := starfile.ReadAll(e.Data)
	if err != nil || string(got) != "ABC" || e.StoredData.Size() != int64(len(payload)) {
		t.Fatalf("%q %+v %v", got, e, err)
	}
	if _, err := OpenWithLimits(&starfile.Bytes{Data: b}, 1, 2); err == nil {
		t.Fatal("ignored fork limit")
	}
}

func compressed9(id uint16, size int, parameters, payload []byte) []byte {
	b := compressedSample(0, size, nil)
	b[6] = 9
	binary.BigEndian.PutUint16(b[12:], id)
	copy(b[14:], parameters)
	return append(b, payload...)
}
func TestDcmp2(t *testing.T) {
	if len(dcmp2Words) != 256 {
		t.Fatal("dictionary length")
	}
	for _, tc := range []struct{ name, params, input, want string }{
		{"default", "00000000", "0002ff", "00004eba0220"},
		{"custom odd", "00000101", "414243440001005a", "4142434441425a"},
		{"tagged", "00000103", "41424344a000585901", "414258594344"},
		{"tagged odd", "00000002", "80025a", "4eba5a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := unhex(tc.want)
			f, err := DecodeCompressed(&starfile.Bytes{Data: compressed9(2, len(want), unhex(tc.params), unhex(tc.input))}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := starfile.ReadAll(f)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got%x want%x: %v", got, want, err)
			}
		})
	}
	for _, tc := range []struct {
		params, input string
		size          int
	}{
		{"00000004", "00", 2}, {"00000001", "414201", 2}, {"00000002", "00ff", 2},
		{"00000002", "80", 0}, {"00000000", "00", 4}, {"00000000", "0000", 2},
		{"00000101", "4142", 2}, {"00000000", "", 1},
	} {
		if _, err := DecodeCompressed(&starfile.Bytes{Data: compressed9(2, tc.size, unhex(tc.params), unhex(tc.input))}, 1<<20); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
func packedBits(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b := make([]byte, (len(s)+7)/8)
	for i, c := range s {
		if c == '1' {
			b[i/8] |= 0x80 >> uint(i%8)
		} else if c != '0' {
			panic("bad test bits")
		}
	}
	return b
}
func TestDcmp3(t *testing.T) {
	// Literal 'A', overlapping distance-one copy of three bytes, literal 'Z'.
	payload := packedBits("00 0 01000001 00 0 00 0 01011010")
	want := []byte("AAAAZ")
	f, err := DecodeCompressed(&starfile.Bytes{Data: compressed9(3, len(want), nil, payload)}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]byte{payload[:len(payload)-1], append(append([]byte{}, payload...), 0), packedBits("01 0"), packedBits("00 0 01000001 00 10 11")} {
		if _, err := DecodeCompressed(&starfile.Bytes{Data: compressed9(3, len(want), nil, bad)}, 1<<20); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}

func FuzzCompressedBounded(f *testing.F) {
	f.Add(compressedSample(0, 2, []byte{0x4b, 0xff}))
	f.Add(compressedSample(1, 3, unhex("fe024102ff")))
	f.Add(compressed9(2, 2, nil, []byte{0}))
	f.Add(compressed9(3, 4, nil, packedBits("00 0 01000001 00 0")))
	f.Fuzz(func(t *testing.T, b []byte) {
		file, err := DecodeCompressed(&starfile.Bytes{Data: b}, 1<<16)
		if err != nil {
			return
		}
		if file.Size() > 1<<16 {
			t.Fatal("output escaped limit")
		}
		if _, err := starfile.ReadAll(file); err != nil {
			t.Fatal(err)
		}
	})
}
