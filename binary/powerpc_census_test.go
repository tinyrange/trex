package binary

import (
	"encoding/binary"
	"testing"
)

func TestPowerPCCensusCountsAndGroupsUnknown(t *testing.T) {
	// mflr r0; mtspr 275,r3; 0; blr; two undecodable words in primary opcode 0;
	// then a range outside the selection that must not be counted.
	src := instructionSource(binary.BigEndian, 0x7c0802a6, 0x7c7343a6, 0, 0x4e800020, 0x00000001, 0x00000003, 0x4e800020)
	c, err := PowerPCCensusRanges(src, []PowerPCRange{{0, 8}, {8, 16}}, "big", 1, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Words != 6 || c.Zero != 1 || c.Decoded != 3 || c.Mnemonic["bclr"] != 1 || c.SPR["mtspr 275"] != 1 {
		t.Fatalf("%+v", c)
	}
	if len(c.Absolute) != 0 {
		t.Fatalf("absolute %v", c.Absolute)
	}
	if len(c.Unknown) != 1 || c.Unknown[0].Key != "0/-" || c.Unknown[0].Count != 2 || len(c.Unknown[0].Words) != 1 || c.Unknown[0].Offsets[0] != 16 {
		t.Fatalf("%+v", c.Unknown)
	}
	for _, bad := range [][]PowerPCRange{{{2, 4}}, {{0, 6}}, {{0, 32}}} {
		if _, err := PowerPCCensusRanges(src, bad, "big", 1, 1<<20, false); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if _, err := PowerPCCensusRanges(src, []PowerPCRange{{0, 16}}, "big", 1, 8, false); err == nil {
		t.Fatal("ignored byte budget")
	}
}

func TestPowerPCCensusFlowSkipsUnreachableData(t *testing.T) {
	// beq +12 -> blr; li r3,1; blr; then an unreachable table; then the branch
	// target (an undecodable word reached by flow), and a trailing table word.
	src := instructionSource(binary.BigEndian, 0x4182000c, 0x38600001, 0x4e800020, 0x00000001, 0xffffffff)
	c, err := PowerPCCensusRanges(src, []PowerPCRange{{0, 20}}, "big", 2, 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Words != 4 || c.Decoded != 3 || c.Mnemonic["fnmadd."] != 0 || len(c.Unknown) != 1 || c.Unknown[0].Offsets[0] != 12 {
		t.Fatalf("%+v %+v", c, c.Unknown)
	}
}

func TestPowerPCCensusAbsoluteTargets(t *testing.T) {
	// bla 0xff019830 (sign-extended), ba 0x100
	src := instructionSource(binary.BigEndian, 0x4b019833, 0x48000102)
	c, err := PowerPCCensusRanges(src, []PowerPCRange{{0, 8}}, "big", 1, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Absolute["ffffffffff010000"] != 1 || c.Absolute["0000000000000000"] != 1 {
		t.Fatalf("%v", c.Absolute)
	}
}
