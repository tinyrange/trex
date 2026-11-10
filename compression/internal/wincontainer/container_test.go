package wincontainer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestDecodeDestinationBoundsAndFailure(t *testing.T) {
	frame := make([]byte, 24)
	binary.LittleEndian.PutUint32(frame, CompressionAPIMagic)
	binary.LittleEndian.PutUint16(frame[4:], 24)
	frame[7] = 5
	binary.LittleEndian.PutUint64(frame[8:], 12)
	binary.LittleEndian.PutUint32(frame[16:], 8)
	frame[6] = containerHeaderCRC(frame)
	frame = append(frame, 1, 0, 0, 0, 'A', 4, 0, 0, 0, 't', 'a', 'i', 'l')
	calls := 0
	decode := func(data, destination []byte) error {
		calls++
		if len(destination) != 8 || cap(destination) != 8 || string(data) != "A" {
			t.Fatalf("unbounded destination: len=%d cap=%d", len(destination), cap(destination))
		}
		for i := range destination {
			destination[i] = 'A'
		}
		return nil
	}
	got, err := DecodeInto(frame, 12, 5, decode)
	if err != nil || string(got) != "AAAAAAAAtail" || calls != 1 {
		t.Fatalf("%q %d %v", got, calls, err)
	}
	copy(frame[len(frame)-4:], "xxxx")
	if string(got) != "AAAAAAAAtail" {
		t.Fatal("result aliases frame")
	}
	calls = 0
	if got, err := DecodeInto(frame, 11, 5, decode); err == nil || got != nil || calls != 0 {
		t.Fatal("limit checked after decode")
	}
	sentinel := errors.New("codec failed")
	if got, err := DecodeInto(frame, 12, 5, func(_, dst []byte) error { copy(dst, "partial"); return sentinel }); got != nil || !errors.Is(err, sentinel) {
		t.Fatal("partial output or lost codec error")
	}
	for _, size := range []int{7, 9} {
		if got, err := Decode(frame, 12, 5, func(_ []byte, _ int) ([]byte, error) { return bytes.Repeat([]byte{'A'}, size), nil }); err == nil || got != nil {
			t.Fatalf("accepted codec length %d", size)
		}
	}
}
