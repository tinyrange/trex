package xpress

import "testing"

func TestDecodeTableFullAlphabetAndInvalidTrees(t *testing.T) {
	lengths := make([]byte, xpressSymbols)
	for i := range lengths {
		lengths[i] = 9
	}
	table, err := newXPRESSDecodeTable(lengths)
	if err != nil {
		t.Fatal(err)
	}
	// All 512 symbols have canonical nine-bit codes. Every possible peek
	// must resolve correctly, including match symbols above byte range.
	for prefix, symbol := range table {
		if int(symbol) != prefix>>6 {
			t.Fatalf("prefix %d: symbol %d", prefix, symbol)
		}
	}
	for _, invalid := range [][]byte{nil, make([]byte, 511), make([]byte, 512), append([]byte{1, 1, 1}, make([]byte, 509)...)} {
		partial, err := newXPRESSDecodeTable(invalid)
		if err == nil || partial != nil {
			t.Fatal("published invalid Huffman tree")
		}
	}
}
