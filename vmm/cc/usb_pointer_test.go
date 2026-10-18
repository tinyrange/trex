package cc

import (
	"encoding/binary"
	"testing"
)

func TestUSBPointerMotionDoesNotDelayOrMoveTransitions(t *testing.T) {
	d := newUSBHID(true)
	d.configuration = 1
	point := func(x uint16, buttons byte, wheel int) {
		t.Helper()
		if err := d.point(x, 20, buttons, wheel); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10000; i++ {
		point(uint16(i), 0, 0)
	}
	point(10000, 1, 0)
	for i := 10001; i < 20000; i++ {
		point(uint16(i), 1, 0)
	}
	point(20000, 1, -1)
	point(20001, 1, 1)
	point(20002, 0, 0)
	for i := 20003; i < 30000; i++ {
		point(uint16(i), 0, 0)
	}
	want := []struct {
		x       uint16
		buttons byte
		wheel   int8
	}{
		{9999, 0, 0}, {10000, 1, 0}, {19999, 1, 0}, {20000, 1, -1},
		{20001, 1, 1}, {20002, 0, 0}, {29999, 0, 0},
	}
	if len(d.pending) != len(want) {
		t.Fatalf("motion backlog: %d", len(d.pending))
	}
	for _, w := range want {
		var report [6]byte
		n, status := d.transaction(0x69, 1, report[:])
		if n != 6 || status != 0 || binary.LittleEndian.Uint16(report[1:]) != w.x || report[0] != w.buttons || int8(report[5]) != w.wheel {
			t.Fatalf("got %v (%d,%d), want %+v", report, n, status, w)
		}
	}
	if _, status := d.transaction(0x69, 1, make([]byte, 6)); status != 1 {
		t.Fatal("expected NAK")
	}
	// An emptied queue must accept a fresh motion report.
	point(42, 0, 0)
	if len(d.pending) != 1 {
		t.Fatal("motion lost after draining")
	}
}

func TestUSBPointerWheelIsNotReplayedByControlRequests(t *testing.T) {
	d := newUSBHID(true)
	d.configuration = 1
	if err := d.point(123, 456, 1, -3); err != nil {
		t.Fatal(err)
	}
	if !d.setup([]byte{0xa1, 1, 0, 1, 0, 0, 6, 0}) {
		t.Fatal("GET_REPORT stalled")
	}
	var report [6]byte
	n, status := d.transaction(0x69, 0, report[:])
	if n != 6 || status != 0 || report[0] != 1 || report[5] != 0 {
		t.Fatalf("state report: %v", report)
	}
	// The control request must not consume the queued relative wheel event.
	n, status = d.transaction(0x69, 1, report[:])
	if n != 6 || status != 0 || int8(report[5]) != -3 {
		t.Fatalf("wheel lost: %v", report)
	}
	if !d.setup([]byte{0, 9, 1, 0, 0, 0, 0, 0}) {
		t.Fatal("SET_CONFIGURATION stalled")
	}
	n, status = d.transaction(0x69, 1, report[:])
	if n != 6 || status != 0 || report[5] != 0 {
		t.Fatalf("wheel replayed: %v", report)
	}
}
