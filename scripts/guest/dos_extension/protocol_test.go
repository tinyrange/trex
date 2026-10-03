package main

import (
	"renvo.dev/device/dos"
	"strings"
	"testing"
)

func request(s string) bool {
	if len(s) > lineLimit {
		return false
	}
	copy(input[:], s)
	return parse(len(s))
}
func TestParserAndBounds(t *testing.T) {
	if !request("CALL\trename\tsC:\\\\OLD.TXT\tsC:\\\\NEW.TXT\r") || !equalField(2, "sC:\\OLD.TXT") || !stringArg(3, 127, false) {
		t.Fatal("escaped path")
	}
	for _, s := range []string{"CALL\tremove\tsbad\\q", "CALL\tremove\tsbad\\", "CALL\tremove\tsbad\x00", "CALL\tremove\tsé", strings.Repeat("x\t", 8)} {
		if request(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, s := range []string{"i8", "i9", "i32768", "i9999999999999999", "i-1", "i", "i+1"} {
		if !request("CALL\tclose_file\t" + s) {
			t.Fatal("framing")
		}
		if integerArg(2, 7) >= 0 {
			t.Fatalf("accepted handle %s", s)
		}
	}
	if !request("CALL\twrite_file\ti0\ts00aAfF") {
		t.Fatal("hex framing")
	}
	if n := hexArg(3); n != 3 || transfer[0] != 0 || transfer[1] != 170 || transfer[2] != 255 {
		t.Fatal("hex decoding")
	}
	for _, s := range []string{"s0", "s0g", "s" + strings.Repeat("aa", 257)} {
		request("CALL\twrite_file\ti0\t" + s)
		if hexArg(3) >= 0 {
			t.Fatal("accepted invalid hex")
		}
	}
	if !request(strings.Repeat("x", lineLimit)) {
		t.Fatal("exact limit")
	}
}
func TestInvalidCallsHaveNoDOSEffects(t *testing.T) {
	effects := 0
	dos.InterruptHook = func(vector byte, regs *dos.Registers) {
		if vector == 0x21 {
			effects++
		}
	}
	defer func() { dos.InterruptHook = nil }()
	used[0] = true
	defer func() { used[0] = false }()
	for _, s := range []string{
		"CALL\tremove\tsFILE\textra",
		"CALL\trename\tsFILE\ts",
		"CALL\topen_file\tsFILE\tsinvalid",
		"CALL\twrite_file\ti0\ts00zz",
		"CALL\tread_file\ti0\ti257",
		"CALL\tclose_file\ti8",
		"CALL\trun\tsAPP.COM\ts" + strings.Repeat("a", 127),
		"CALL\tmkdir\tsbad\\npath",
	} {
		if !request(s) {
			t.Fatalf("framing %q", s)
		}
		dispatch()
	}
	if effects != 0 {
		t.Fatalf("invalid calls produced %d DOS effects", effects)
	}
}
