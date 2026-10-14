package ibmiimd

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestIntermediateLengthWidths(t *testing.T) {
	for width := 3; width <= 7; width++ {
		length := 1 << (width - 1)
		bits := "0 01000001 1 " + strings.Repeat("0", width-2) + fmt.Sprintf("%0*b", width, length) + " 1 0000001"
		got, err := DecodeFrame(testFrame(bits, uint32(length+1)))
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("A"), length+1)) {
			t.Fatal(width, len(got), err)
		}
	}
}
func TestDistanceBoundaries(t *testing.T) {
	for _, distance := range []int{127, 128, 2047} {
		var bits strings.Builder
		want := make([]byte, distance+2)
		for i := 0; i < distance; i++ {
			want[i] = byte(i % 251)
			fmt.Fprintf(&bits, "0%08b", want[i])
		}
		if distance <= 127 {
			fmt.Fprintf(&bits, "1101%07b", distance)
		} else {
			fmt.Fprintf(&bits, "1100%011b", distance)
		}
		want[distance] = want[0]
		want[distance+1] = want[1]
		got, err := DecodeFrame(testFrame(bits.String(), uint32(len(want))))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal(distance, err)
		}
	}
}
func TestEndControlAndPadding(t *testing.T) {
	raw := testFrame("0 01000001", 1)
	out, info, err := DecodeFrameWithInfo(raw)
	if err != nil || string(out) != "A" || info.OutputConsumedBits != 9 || info.EndControlBits != 15 || !info.StopBit || !info.PostStopZero || !info.TerminationVerified || info.TailByteOffset != 13 || info.TailFirstBit != 1 {
		t.Fatal(out, info, err)
	}
	// Exactly-sized output plus noncanonical tail must not pass the strict reader.
	for name, mutate := range map[string]func([]byte){
		"missing stop":    func(b []byte) { b[15] &= 0x7f },
		"padding garbage": func(b []byte) { b[15] |= 1 },
		"wrong control":   func(b []byte) { b[14] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(raw)
			mutate(b)
			if _, err := DecodeFrame(b); err == nil {
				t.Fatal("bad tail accepted")
			}
			_, diag, err := DecodeFrameWithInfo(b)
			if err != nil || diag.TerminationVerified {
				t.Fatal(diag, err)
			}
		})
	}
	p, err := OpenPacked(&starfile.Bytes{Data: testPacked(raw)}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	p.Frames = append(p.Frames, Frame{})
	if _, _, err := p.InspectFrame(1); err == nil {
		t.Fatal("mutable frame metadata extended validated table")
	}
}
func FuzzLICFrame(f *testing.F) {
	f.Add(testFrame("0 01000001 1 11 1 0000001", 4))
	f.Add([]byte{3, 0, 0, 128})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		out, info, err := DecodeFrameWithInfo(b)
		if err == nil {
			if len(out) > 32768 || info.OutputConsumedBits > (len(b)-12)*8 || info.TailByteOffset < 12 || info.TailByteOffset > len(b) {
				t.Fatal("invalid decoded range")
			}
			strict, e := DecodeFrame(b)
			if info.TerminationVerified && (e != nil || !bytes.Equal(strict, out)) {
				t.Fatal("strict/diagnostic disagreement")
			}
		}
	})
}
func FuzzIMDDirectory(f *testing.F) {
	f.Add(fixture())
	f.Add([]byte{0xc9, 0xd4, 0xc4, 0xf1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		image, err := Open(&starfile.Bytes{Data: b}, 128, 1<<20)
		if err == nil {
			for _, e := range image.Entries {
				if e.Offset < 0 || e.StoredBytes > int64(len(b))-e.Offset {
					t.Fatal("invalid stored extent")
				}
			}
		}
	})
}
func FuzzPackedHeaders(f *testing.F) {
	f.Add(testPacked(testFrame("0 01000001", 1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		p, err := OpenPacked(&starfile.Bytes{Data: b}, 128, 1<<20)
		if err == nil {
			if p.StoredBytes > uint32(len(b)) || p.ExpandedBytes > 1<<20 {
				t.Fatal("invalid header bounds")
			}
			small := make([]byte, 32)
			_, _ = p.Data.ReadAt(small, 0)
		}
	})
}
