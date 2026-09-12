package lha

import (
	"bytes"
	"testing"
)

func constantBlock(count, literal, distance int) []byte {
	var out []byte
	pos := 0
	write := func(value, width int) {
		for n := width - 1; n >= 0; n-- {
			if pos%8 == 0 {
				out = append(out, 0)
			}
			out[pos/8] |= byte((value>>n)&1) << uint(7-pos%8)
			pos++
		}
	}
	write(count, 16)
	write(0, 5)
	write(0, 5)
	write(0, 9)
	write(literal, 9)
	write(0, 4)
	write(distance, 4)
	return out
}
func TestConstantBlocks(t *testing.T) {
	for _, test := range []struct {
		code, size int
		want       string
	}{{65, 8, "AAAAAAAA"}, {256, 3, "   "}} {
		count := test.size
		if test.code >= 256 {
			count = 1
		}
		got, err := decodeLH5(constantBlock(count, test.code, 0), test.size)
		if err != nil || string(got) != test.want {
			t.Fatal(string(got), err)
		}
	}
}
func TestLH5Malformed(t *testing.T) {
	for _, input := range [][]byte{nil, {0, 0}, constantBlock(0, 65, 0), constantBlock(1, 511, 0), constantBlock(1, 65, 14), append(constantBlock(1, 65, 0), 1)} {
		if _, err := decodeLH5(input, 1); err == nil {
			t.Fatalf("accepted %x", input)
		}
	}
	if _, err := decodeLH5(constantBlock(2, 65, 0), 1); err == nil {
		t.Fatal("ignored output size")
	}
	if _, err := canonical([]int{1, 1, 1}); err == nil {
		t.Fatal("oversubscribed")
	}
	if _, err := canonical([]int{2, 2}); err == nil {
		t.Fatal("incomplete")
	}
}
func TestCanonicalCodes(t *testing.T) {
	tree, err := canonical([]int{1, 2, 2})
	if err != nil {
		t.Fatal(err)
	}
	b := bits{data: []byte{0x58}} // 0,10,11
	got := []byte{byte(tree.symbol(&b)), byte(tree.symbol(&b)), byte(tree.symbol(&b))}
	if b.err != nil || !bytes.Equal(got, []byte{0, 1, 2}) {
		t.Fatal(got, b.err)
	}
}

func FuzzLH5(f *testing.F) {
	f.Add(constantBlock(8, 65, 0), uint16(8))
	f.Add(constantBlock(1, 256, 0), uint16(3))
	f.Fuzz(func(t *testing.T, data []byte, size uint16) {
		out, err := decodeLH5(data, int(size))
		if err == nil && len(out) != int(size) {
			t.Fatal("decoded size mismatch")
		}
	})
}
