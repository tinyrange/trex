package compressed

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

// Pack explicitly supplied codes, independent of dictionary construction.
func packCodes(codes []int, width int, pad bool) []byte {
	bits := len(codes) * width
	if pad {
		bits = ((len(codes) + 7) / 8) * 8 * width
	}
	out := make([]byte, (bits+7)/8)
	for i, c := range codes {
		for b := 0; b < width; b++ {
			if c&(1<<b) != 0 {
				p := i*width + b
				out[p/8] |= 1 << uint(p%8)
			}
		}
	}
	return out
}
func checkUnix(t *testing.T, input, want []byte) {
	t.Helper()
	f, err := Open(&starfile.Bytes{Data: input}, "compress", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d: %v", len(got), len(want), err)
	}
}
func TestUnixDictionarySpecialCase(t *testing.T) {
	checkUnix(t, append([]byte{0x1f, 0x9d, 0x90}, packCodes([]int{65, 257, 258}, 9, false)...), []byte("AAAAAA"))
}

func TestUnixExplicitZeroPadding(t *testing.T) {
	// Complete zero-valued codes are payload, not discarded padding.
	full := append([]byte{0x1f, 0x9d, 0x90}, packCodes([]int{65, 0, 0, 0, 0, 0, 0, 0}, 9, false)...)
	full = append(full, 0)
	f, err := OpenPaddedUnix(&starfile.Bytes{Data: full}, 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || !bytes.Equal(got, []byte{'A', 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatal(got, err)
	}
	if _, err := OpenPaddedUnix(&starfile.Bytes{Data: full}, 7); err == nil {
		t.Fatal("padding bypassed decoded size limit")
	}
	// Eight literals fill one nine-byte code group; a single extra byte
	// cannot hold another code. Nonzero tails remain errors in both modes.
	codes := []int{65, 66, 67, 68, 69, 70, 71, 72}
	for _, tail := range []byte{0, 1, 128} {
		input := append([]byte{0x1f, 0x9d, 0x90}, packCodes(codes, 9, false)...)
		input = append(input, tail)
		source := &starfile.Bytes{Data: input}
		if _, err := Open(source, "compress", 100); err == nil {
			t.Fatal("strict mode accepted incomplete code")
		}
		f, err := OpenPaddedUnix(source, 100)
		if tail != 0 {
			if err == nil {
				t.Fatal("accepted nonzero padding")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(f)
		if err != nil || string(got) != "ABCDEFGH" {
			t.Fatal(string(got), err)
		}
	}
	if _, err := OpenPaddedUnix(&starfile.Bytes{Data: []byte{0x1f, 0x9d, 0x90, 0}}, 100); err == nil {
		t.Fatal("padding cannot replace first literal")
	}
}
func TestUnixWidthAndClearAlignment(t *testing.T) {
	for _, block := range []bool{false, true} {
		h := byte(16)
		firstCount := 257
		if block {
			h |= 0x80
			firstCount = 256
		}
		var first, second []int
		var want []byte
		for i := 0; i < firstCount; i++ {
			first = append(first, i%256)
			want = append(want, byte(i))
		}
		for i := 0; i < 345; i++ {
			second = append(second, i%256)
			want = append(want, byte(i))
		}
		input := append([]byte{0x1f, 0x9d, h}, packCodes(first, 9, true)...)
		if block {
			second = append(second, 256)
			input = append(input, packCodes(second, 10, true)...)
			input = append(input, packCodes([]int{65, 66, 257}, 9, false)...)
			want = append(want, []byte("ABAB")...)
		} else {
			input = append(input, packCodes(second, 10, false)...)
		}
		checkUnix(t, input, want)
	}
}
func TestUnixRejectInvalid(t *testing.T) {
	for _, input := range [][]byte{{0x1f, 0x9d, 0x88}, {0x1f, 0x9d, 0xf0}, append([]byte{0x1f, 0x9d, 0x90}, packCodes([]int{257}, 9, false)...), append([]byte{0x1f, 0x9d, 0x90}, packCodes([]int{65, 300}, 9, false)...)} {
		if _, err := Open(&starfile.Bytes{Data: input}, "compress", 100); err == nil {
			t.Fatalf("accepted %x", input)
		}
	}
	input := append([]byte{0x1f, 0x9d, 0x90}, packCodes([]int{65, 257, 258}, 9, false)...)
	if _, err := Open(&starfile.Bytes{Data: input}, "compress", 5); err == nil {
		t.Fatal("ignored limit")
	}
}
