package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCompleteInputGestures(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		valid      bool
	}{
		{"move", "00025e01a500", true},
		{"click", "01025e01a50002025e01a500", true},
		{"drag", "01020a001400000264006400020264006400", true},
		{"right click", "04020a00140005020a001400", true},
		{"shift A", "000110002a00000141001e00010141001e00010110002a00", true},
		{"empty", "", false},
		{"truncated", "01020a0014", false},
		{"held mouse", "01020a001400", false},
		{"unmatched release", "02020a001400", false},
		{"duplicate down", "01020a00140001020a00140002020a001400", false},
		{"held modifier", "000110002a00", false},
		{"key up without down", "010141001e00", false},
		{"unknown message", "03020a001400", false},
		{"x bound", "000280020000", false},
		{"y bound", "000200005e01", false},
		{"negative coordinate", "0002ffff0000", false},
		{"bad suffix after click", "01020a00140002020a001400ffff00000000", false},
		{"invalid vk", "000100011e00010100011e00", false},
		{"invalid scan", "000141000001010141000001", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if got := validInputEvents(data, 640, 350); got != tc.valid {
				t.Fatalf("valid=%v want %v", got, tc.valid)
			}
		})
	}
	move := []byte{0, 2, 1, 0, 1, 0}
	if !validInputEvents(bytes.Repeat(move, 40), 640, 350) {
		t.Fatal("40-event boundary rejected")
	}
	if validInputEvents(bytes.Repeat(move, 41), 640, 350) {
		t.Fatal("oversized gesture accepted")
	}
	// A rejected gesture must not poison subsequent validation.
	validInputEvents([]byte{1, 2, 1, 0, 1, 0}, 640, 350)
	if !validInputEvents(move, 640, 350) {
		t.Fatal("validation retained held-button state")
	}
}
