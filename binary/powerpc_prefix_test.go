package binary

import (
	"encoding/binary"
	"testing"
)

func TestPowerPCPrefixWidthAndTruncation(t *testing.T) {
	src := instructionSource(binary.BigEndian, 0x06000000, 0x38600001, 0x4e800020)
	got, err := PowerPCInstructions(src, 0, 12, 0x1000, "big", 2)
	if err != nil || len(got) != 2 || got[0].Length != 8 || got[0].Opcode != "paddi" || got[1].Address != 0x1008 {
		t.Fatal(got, err)
	}
	got, err = PowerPCInstructions(src, 0, 4, 0x1000, "big", 1)
	if err != nil || len(got) != 1 || got[0].Error == "" || got[0].Length != 4 {
		t.Fatal(got, err)
	}
}
