package msdelta

import "testing"

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
