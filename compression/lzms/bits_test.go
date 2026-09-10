package lzms

import (
	"encoding/binary"
	"testing"
)

func TestBackwardBitReaderWordAndBitOrder(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:2], 0x1234)
	binary.LittleEndian.PutUint16(data[2:4], 0xabcd)
	reader, err := newBackwardBitReader(data)
	if err != nil {
		t.Fatal(err)
	}
	for index, test := range []struct {
		bits uint
		want uint32
	}{{4, 0xa}, {12, 0xbcd}, {16, 0x1234}} {
		got, err := reader.readBits(test.bits)
		if err != nil {
			t.Fatalf("read %d: %v", index, err)
		}
		if got != test.want {
			t.Fatalf("read %d = %#x, want %#x", index, got, test.want)
		}
	}
	if _, err := reader.readBits(1); err == nil {
		t.Fatal("exhausted reader accepted another bit")
	}
}

func TestBackwardBitReaderCrossesWordBoundary(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:2], 0x5678)
	binary.LittleEndian.PutUint16(data[2:4], 0x1234)
	reader, err := newBackwardBitReader(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.readBits(20)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x12345 {
		t.Fatalf("read = %#x, want %#x", got, uint32(0x12345))
	}
}

func TestBackwardBitReaderRejectsInvalidRequests(t *testing.T) {
	if _, err := newBackwardBitReader([]byte{0}); err == nil {
		t.Fatal("odd input accepted")
	}
	reader, err := newBackwardBitReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.readBits(33); err == nil {
		t.Fatal("33-bit read accepted")
	}
}

func FuzzBackwardBitReader(f *testing.F) {
	f.Add([]byte{0x34, 0x12, 0xcd, 0xab}, uint8(17))
	f.Fuzz(func(t *testing.T, data []byte, count uint8) {
		reader, err := newBackwardBitReader(data)
		if err != nil {
			return
		}
		_, _ = reader.readBits(uint(count % 33))
	})
}
