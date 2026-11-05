package msdelta

import (
	"reflect"
	"testing"
)

func TestRiftMapForwardWrapsBeforeFirstBreakpoint(t *testing.T) {
	rift := riftTable{entries: []riftEntry{
		{source: 0, target: 0},
		{source: 0x1000, target: 0x1010},
		{source: 0x2000, target: 0x2090},
	}}
	if got := rift.mapForward(-0x100); got != -0x70 {
		t.Fatalf("pre-first mapping = %#x, want final-segment mapping %#x", got, -0x70)
	}
	if got := rift.mapForward(0x1800); got != 0x1810 {
		t.Fatalf("ordinary mapping = %#x, want %#x", got, 0x1810)
	}
	if got := (riftTable{}).mapForward(0x800); got != 0x800 {
		t.Fatalf("empty mapping = %#x, want identity %#x", got, 0x800)
	}
}

// Default integer code lengths shorten once across both signed halves. With
// many explicit codes, the old loop incorrectly shortened a second time.
func TestIntegerFormatDefaultLengthsShortenOnlyOnce(t *testing.T) {
	w := newTestBitWriter()
	writeTestRawBits(w, 70, 8)
	writeTestRawBits(w, 70, 8)
	writeTestRawBits(w, 0, 8)
	for range 140 {
		writeTestRawBits(w, 15, 4)
	}
	writeTestRawBits(w, 9, 4)
	r, err := newBitReader(w.bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, err := readIntFormat(r)
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]byte, 252)
	for i := range expected {
		expected[i] = 9
	}
	for i := 0; i < 70; i++ {
		expected[i] = 16
		expected[126+i] = 16
	}
	want, err := newHuffman(expected, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.tree, want) {
		t.Fatal("default code lengths shortened more than once")
	}
}

func TestRiftEntryCountBoundsAndLargePlayback(t *testing.T) {
	const count = maxRiftEntries + 1
	tree, err := newHuffman([]byte{1, 1}, 1)
	if err != nil {
		t.Fatal(err)
	}
	format := &intFormat{tree: tree}
	w := newTestBitWriter()
	w.number(count)
	for range count * 2 {
		w.bit(0)
	}
	encoded := w.bytes()
	read := func(data []byte, limit uint64) (riftTable, error) {
		r, err := newBitReader(data)
		if err != nil {
			return riftTable{}, err
		}
		return readRiftWithFormatsBounded(r, format, format, limit)
	}
	if _, err := read(encoded, maxRiftEntries); err == nil {
		t.Fatal("ignored caller limit")
	}
	if _, err := read(encoded[:8], count); err == nil {
		t.Fatal("accepted impossible encoded count")
	}
	got, err := read(encoded, count)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.entries) != count || got.entries[count-1] != (riftEntry{}) {
		t.Fatal("large table decoded incorrectly")
	}
}
