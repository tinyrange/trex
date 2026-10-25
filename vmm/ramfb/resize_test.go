package ramfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func resizeFixture() []byte {
	m := make([]byte, Size)
	for offset, value := range map[int]uint32{0: Magic, 4: 1, 8: 1280, 12: 720, 16: 5120, 20: 1, 24: ResizeMagic, 28: 1, 52: MaxWidth, 56: MaxHeight} {
		binary.LittleEndian.PutUint32(m[offset:], value)
	}
	return m
}

func TestResizeRequiresGuestAcknowledgementAndCommittedLayout(t *testing.T) {
	m := resizeFixture()
	before := append([]byte(nil), m[:24]...)
	seq, err := RequestResize(m, 1024, 768)
	if err != nil || seq == 0 {
		t.Fatalf("request: %d %v", seq, err)
	}
	if !bytes.Equal(before, m[:24]) {
		t.Fatal("host request changed active mode")
	}
	if done, err := ResizeComplete(m, seq, 1024, 768); done || err != nil {
		t.Fatalf("unacknowledged request: %v %v", done, err)
	}
	binary.LittleEndian.PutUint32(m[44:], seq)
	if done, err := ResizeComplete(m, seq, 1024, 768); done || err == nil {
		t.Fatal("acknowledgement accepted without guest mode change")
	}
	binary.LittleEndian.PutUint32(m[8:], 1024)
	binary.LittleEndian.PutUint32(m[12:], 768)
	binary.LittleEndian.PutUint32(m[16:], 4096)
	if done, err := ResizeComplete(m, seq, 1024, 768); !done || err != nil {
		t.Fatalf("completed request: %v %v", done, err)
	}
	for _, result := range []uint32{1, 0xffffffff, 0xfffffffe} {
		binary.LittleEndian.PutUint32(m[48:], result)
		if done, err := ResizeComplete(m, seq, 1024, 768); done || err == nil {
			t.Fatalf("guest result %d accepted", result)
		}
	}
}

func TestResizeSupersessionAndSequenceWrap(t *testing.T) {
	m := resizeFixture()
	binary.LittleEndian.PutUint32(m[40:], 0xffffffff)
	binary.LittleEndian.PutUint32(m[44:], 1)
	seq, err := RequestResize(m, 800, 600)
	if err != nil || seq != 2 {
		t.Fatalf("wrapped sequence: %d %v", seq, err)
	}
	next, err := RequestResize(m, 1024, 768)
	if err != nil || next != 3 {
		t.Fatal(next, err)
	}
	if _, err := ResizeComplete(m, seq, 800, 600); !errors.Is(err, ErrResizeSuperseded) {
		t.Fatal("superseded request:", err)
	}
	// A late completion from the previous request cannot complete its replacement.
	binary.LittleEndian.PutUint32(m[44:], seq)
	if done, err := ResizeComplete(m, next, 1024, 768); done || err != nil {
		t.Fatal(done, err)
	}
}

func TestResizeReadinessAndUntrustedBounds(t *testing.T) {
	for _, size := range [][2]int{{0, 600}, {-1, 600}, {800, 0}, {MaxWidth + 1, 600}, {800, MaxHeight + 1}, {int(^uint(0) >> 1), 600}} {
		m := resizeFixture()
		before := append([]byte(nil), m[:64]...)
		if _, err := RequestResize(m, size[0], size[1]); err == nil || !bytes.Equal(before, m[:64]) {
			t.Fatalf("invalid request %v mutated mailbox or was accepted", size)
		}
	}
	for _, mutation := range [][2]uint32{{0, 0}, {24, 0}, {28, 0}, {28, 2}, {52, 0}, {56, 0xffffffff}} {
		m := resizeFixture()
		binary.LittleEndian.PutUint32(m[mutation[0]:], mutation[1])
		if _, _, ready := ResizeLimits(m); ready {
			t.Fatalf("invalid mailbox accepted: %v", mutation)
		}
	}
	for _, size := range []int{0, 24, 59, Pixels, Pixels + 4} {
		m := resizeFixture()[:size]
		if _, err := RequestResize(m, 800, 600); !errors.Is(err, ErrResizeUnavailable) {
			t.Fatalf("short aperture (%d): %v", size, err)
		}
	}
}

func TestMonochromeResizeLimitsUseWordAlignedPixelCapacity(t *testing.T) {
	m := resizeFixture()[:Pixels+102*603]
	binary.LittleEndian.PutUint32(m[20:], 2)
	binary.LittleEndian.PutUint32(m[52:], 801)
	binary.LittleEndian.PutUint32(m[56:], 603)
	if _, _, ready := ResizeLimits(m); !ready {
		t.Fatal("valid monochrome aperture rejected")
	}
	if _, _, ready := ResizeLimits(m[:len(m)-1]); ready {
		t.Fatal("short word-aligned aperture accepted")
	}
	binary.LittleEndian.PutUint32(m[20:], 1)
	if _, _, ready := ResizeLimits(m); ready {
		t.Fatal("monochrome capacity accepted for BGRX")
	}
}
