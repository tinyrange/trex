package lzms

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestGeneratedSlotTables(t *testing.T) {
	if positionSlotsError != nil {
		t.Fatal(positionSlotsError)
	}
	if lengthSlotsError != nil {
		t.Fatal(lengthSlotsError)
	}
	if len(positionSlots.bases) != 799 || positionSlots.bases[0] != 1 || positionSlots.bases[len(positionSlots.bases)-1] != 0x065be4a5 {
		t.Fatalf("position slots = count %d first %#x last %#x", len(positionSlots.bases), positionSlots.bases[0], positionSlots.bases[len(positionSlots.bases)-1])
	}
	if len(lengthSlots.bases) != 54 || lengthSlots.bases[0] != 1 || lengthSlots.bases[len(lengthSlots.bases)-1] != 0x000108ab {
		t.Fatalf("length slots = count %d first %#x last %#x", len(lengthSlots.bases), lengthSlots.bases[0], lengthSlots.bases[len(lengthSlots.bases)-1])
	}
	if positionSlots.extraBits[len(positionSlots.extraBits)-1] != 30 || lengthSlots.extraBits[len(lengthSlots.extraBits)-1] != 30 {
		t.Fatalf("final extra bits = position %d length %d", positionSlots.extraBits[len(positionSlots.extraBits)-1], lengthSlots.extraBits[len(lengthSlots.extraBits)-1])
	}
	symbols, err := positionSlots.symbolsForOutputSize(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if symbols != 729 {
		t.Fatalf("64 MiB position symbols = %d, want 729", symbols)
	}
}

func TestSlotDecodeUsesMSBFirstExtraBits(t *testing.T) {
	reader := backwardFixture(0x8000)
	value, err := lengthSlots.decode(26, reader)
	if err != nil {
		t.Fatal(err)
	}
	if value != 28 {
		t.Fatalf("decoded length = %d, want 28", value)
	}
}

func TestRecentOffsetDelayedInsertion(t *testing.T) {
	recent := newRecentOffsets()
	recent.beginItem()
	recent.explicit(100)
	recent.endItem()
	if recent.queue != [4]uint32{1, 2, 3, 4} || recent.pending != 100 {
		t.Fatalf("after explicit = queue %v pending %d", recent.queue, recent.pending)
	}
	recent.beginItem()
	recent.endItem()
	if recent.queue != [4]uint32{100, 1, 2, 3} || recent.pending != 0 {
		t.Fatalf("after literal = queue %v pending %d", recent.queue, recent.pending)
	}
}

func TestRecentOffsetRepeatRemovalAndReinsertion(t *testing.T) {
	recent := newRecentOffsets()
	recent.beginItem()
	value, err := recent.repeat(1)
	if err != nil {
		t.Fatal(err)
	}
	if value != 2 || recent.queue != [4]uint32{1, 3, 4, 0} {
		t.Fatalf("selected = %d, queue %v", value, recent.queue)
	}
	recent.endItem()
	recent.beginItem()
	recent.endItem()
	if recent.queue != [4]uint32{2, 1, 3, 4} {
		t.Fatalf("reinserted queue = %v", recent.queue)
	}
}

func TestRecentDeltaPairsMoveTogether(t *testing.T) {
	recent := newRecentDeltaPairs()
	recent.beginItem()
	pair := deltaPair{power: 7, rawOffset: 99}
	recent.explicit(pair)
	recent.endItem()
	recent.beginItem()
	recent.endItem()
	if recent.queue[0] != pair {
		t.Fatalf("front pair = %+v, want %+v", recent.queue[0], pair)
	}
	selected, err := recent.repeat(2)
	if err != nil {
		t.Fatal(err)
	}
	if selected != (deltaPair{power: 0, rawOffset: 2}) {
		t.Fatalf("selected pair = %+v", selected)
	}
}

func TestMatchCopySemanticsAndBounds(t *testing.T) {
	d := decoder{output: []byte{'a', 'b'}, want: 8}
	if err := d.copyLZ(2, 6); err != nil {
		t.Fatal(err)
	}
	if string(d.output) != "abababab" {
		t.Fatalf("overlapping LZ output = %q", d.output)
	}
	d = decoder{output: []byte{1, 2, 3, 4}, want: 6}
	if err := d.copyDelta(deltaPair{power: 0, rawOffset: 1}, 2); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.output, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("overlapping delta output = %v", d.output)
	}
	if err := d.copyLZ(7, 1); err == nil {
		t.Fatal("out-of-range LZ offset accepted")
	}
	if err := d.copyDelta(deltaPair{power: 7, rawOffset: 1}, 1); err == nil {
		t.Fatal("out-of-range delta distance accepted")
	}
}

func TestRestoreX86AddressesUsesRepeatedTargetHeuristic(t *testing.T) {
	data := make([]byte, 64)
	data[1], data[6], data[11] = 0xe8, 0xe8, 0xe8
	binary.LittleEndian.PutUint32(data[2:6], 0x1000)
	binary.LittleEndian.PutUint32(data[7:11], 0x0ffb)
	// Once the repeated-target heuristic is active, the compressor stores the
	// absolute-style value (relative operand + instruction position).
	binary.LittleEndian.PutUint32(data[12:16], 0x1001)
	restoreX86Addresses(data)
	if got := binary.LittleEndian.Uint32(data[2:6]); got != 0x1000 {
		t.Fatalf("first target changed to %#x", got)
	}
	if got := binary.LittleEndian.Uint32(data[7:11]); got != 0x0ffb {
		t.Fatalf("second target changed to %#x", got)
	}
	if got := binary.LittleEndian.Uint32(data[12:16]); got != 0x0ff6 {
		t.Fatalf("third target = %#x, want %#x", got, uint32(0x0ff6))
	}
}

func TestRestoreX86AddressesTracksLikelyCodeAtOperandEnd(t *testing.T) {
	data := make([]byte, 560)
	data[1], data[6], data[521] = 0xe8, 0xe8, 0xe8
	binary.LittleEndian.PutUint32(data[2:6], 0x1000)
	binary.LittleEndian.PutUint32(data[7:11], 0x0ffb)
	// The second candidate makes operand end 10 the closest likely-code
	// position. Position 521 is exactly 511 bytes after that position, so a
	// CALL is eligible. It would be ineligible if position 6, the instruction
	// start, had been recorded instead.
	binary.LittleEndian.PutUint32(data[522:526], 0x2000+521)
	restoreX86Addresses(data)
	if got := binary.LittleEndian.Uint32(data[522:526]); got != 0x2000 {
		t.Fatalf("boundary CALL operand = %#x, want %#x", got, uint32(0x2000))
	}
}

func TestRestoreX86AddressesTreatsJumpAsScanOnly(t *testing.T) {
	data := make([]byte, 64)
	data[1], data[6], data[11] = 0xe9, 0xe9, 0xe8
	binary.LittleEndian.PutUint32(data[2:6], 0x1000)
	binary.LittleEndian.PutUint32(data[7:11], 0x0ffb)
	binary.LittleEndian.PutUint32(data[12:16], 0x0ff6)
	restoreX86Addresses(data)
	if got := binary.LittleEndian.Uint32(data[12:16]); got != 0x0ff6 {
		t.Fatalf("CALL after repeated E9 operands changed to %#x", got)
	}
}

func TestX86CandidateForms(t *testing.T) {
	for _, test := range []struct {
		bytes  []byte
		offset int
		window int
	}{{[]byte{0x48, 0x8b, 0x05}, 3, 1023}, {[]byte{0x48, 0x8d, 0xfd}, 3, 1023}, {[]byte{0x4c, 0x8d, 0x0d}, 3, 1023}, {[]byte{0xe8, 0, 0}, 1, 511}, {[]byte{0xe9, 0, 0}, 1, 0}, {[]byte{0xf0, 0x83, 0x05}, 3, 1023}, {[]byte{0xff, 0x15, 0}, 2, 1023}} {
		data := append([]byte{0}, test.bytes...)
		data = append(data, make([]byte, 16)...)
		offset, window, recognized := x86Candidate(data, 1)
		if !recognized || offset != test.offset || window != test.window {
			t.Fatalf("candidate %x = %d/%d/%t", test.bytes, offset, window, recognized)
		}
	}
}

func TestDecompressStrictStructuralValidation(t *testing.T) {
	for _, test := range []struct {
		data []byte
		size int
	}{{nil, 0}, {[]byte{0, 0}, 0}, {[]byte{0, 0, 0, 0, 0}, 0}, {[]byte{0, 0, 0, 0}, -1}} {
		if _, err := Decompress(test.data, test.size); err == nil {
			t.Fatalf("accepted data length %d and output %d", len(test.data), test.size)
		}
	}
	output, err := Decompress([]byte{0, 0, 0, 0}, 0)
	if err != nil || len(output) != 0 {
		t.Fatalf("zero output = %v, %v", output, err)
	}
}

func FuzzDecompressDoesNotPanic(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, uint8(16))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		_, _ = Decompress(data, int(size))
	})
}
