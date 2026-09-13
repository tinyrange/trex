package lzms

import (
	"encoding/binary"
	"testing"
)

func rangeFixture(words ...uint16) []byte {
	data := make([]byte, len(words)*2)
	for index, word := range words {
		binary.LittleEndian.PutUint16(data[index*2:], word)
	}
	return data
}

func TestRangeDecoderInitializationAndPartitions(t *testing.T) {
	decoder, err := newRangeDecoder(rangeFixture(0x1234, 0x5678))
	if err != nil {
		t.Fatal(err)
	}
	if decoder.code != 0x12345678 || decoder.rangeValue != 0xffffffff || decoder.next != 4 {
		t.Fatalf("initial state = code %#x range %#x next %d", decoder.code, decoder.rangeValue, decoder.next)
	}
	bit, err := decoder.decodeBit(48)
	if err != nil {
		t.Fatal(err)
	}
	const bound = uint32(0xbfffffd0)
	if bit != 0 || decoder.rangeValue != bound || decoder.code != 0x12345678 {
		t.Fatalf("zero partition = bit %d code %#x range %#x", bit, decoder.code, decoder.rangeValue)
	}

	decoder, err = newRangeDecoder(rangeFixture(0xf234, 0x5678))
	if err != nil {
		t.Fatal(err)
	}
	bit, err = decoder.decodeBit(48)
	if err != nil {
		t.Fatal(err)
	}
	if bit != 1 || decoder.rangeValue != 0x4000002f || decoder.code != 0x323456a8 {
		t.Fatalf("one partition = bit %d code %#x range %#x", bit, decoder.code, decoder.rangeValue)
	}
}

func TestRangeDecoderNormalization(t *testing.T) {
	decoder, err := newRangeDecoder(rangeFixture(0, 0, 0xbeef))
	if err != nil {
		t.Fatal(err)
	}
	decoder.rangeValue = 0xffff
	decoder.code = 0x1234
	bit, err := decoder.decodeBit(32)
	if err != nil {
		t.Fatal(err)
	}
	if bit != 0 || decoder.next != 6 || decoder.code != 0x1234beef || decoder.rangeValue != 0x7fff8000 {
		t.Fatalf("normalized state = bit %d code %#x range %#x next %d", bit, decoder.code, decoder.rangeValue, decoder.next)
	}
	decoder.rangeValue = 0xffff
	if _, err := decoder.decodeBit(32); err == nil {
		t.Fatal("normalization accepted exhausted forward stream")
	}
}

func TestRangeDecoderClampsProbability(t *testing.T) {
	zero, err := newRangeDecoder(rangeFixture(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	one, err := newRangeDecoder(rangeFixture(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zero.decodeBit(0); err != nil {
		t.Fatal(err)
	}
	if _, err := one.decodeBit(1); err != nil {
		t.Fatal(err)
	}
	if zero.rangeValue != one.rangeValue || zero.code != one.code {
		t.Fatal("probability 0 was not clamped to 1")
	}
	sixtyFour, _ := newRangeDecoder(rangeFixture(0, 0))
	sixtyThree, _ := newRangeDecoder(rangeFixture(0, 0))
	_, _ = sixtyFour.decodeBit(64)
	_, _ = sixtyThree.decodeBit(63)
	if sixtyFour.rangeValue != sixtyThree.rangeValue || sixtyFour.code != sixtyThree.code {
		t.Fatal("probability 64 was not clamped to 63")
	}
}

func TestProbabilityEntryMaintainsExactHistory(t *testing.T) {
	entry := newProbabilityEntry()
	if entry.history != initialProbabilityHistory || entry.zeros != 48 {
		t.Fatalf("initial entry = %#x/%d", entry.history, entry.zeros)
	}
	for range 64 {
		entry.observe(1)
	}
	if entry.history != ^uint64(0) || entry.zeros != 0 {
		t.Fatalf("all-one history = %#x/%d", entry.history, entry.zeros)
	}
	for range 64 {
		entry.observe(0)
	}
	if entry.history != 0 || entry.zeros != 64 {
		t.Fatalf("all-zero history = %#x/%d", entry.history, entry.zeros)
	}
}

func TestContextModelStateAndIndependence(t *testing.T) {
	model, err := newContextModel(4)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := newRangeDecoder(rangeFixture(0xffff, 0xffff, 0xffff))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		if _, err := model.decode(decoder); err != nil {
			t.Fatal(err)
		}
	}
	if model.state != 0x0f {
		t.Fatalf("state = %#x, want %#x", model.state, uint8(0x0f))
	}
	if model.entries[0].zeros == model.entries[2].zeros {
		t.Fatal("used and unused probability contexts have identical state")
	}
	if _, err := newContextModel(0); err == nil {
		t.Fatal("zero-width context accepted")
	}
	if _, err := newContextModel(7); err == nil {
		t.Fatal("seven-bit context accepted")
	}
}

func TestRangeDecoderRejectsInvalidInput(t *testing.T) {
	for _, data := range [][]byte{nil, {0, 0}, {0, 0, 0, 0, 0}} {
		if _, err := newRangeDecoder(data); err == nil {
			t.Fatalf("accepted input of length %d", len(data))
		}
	}
}
