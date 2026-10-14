package binary

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"math"
	"testing"
)

func instructionSource(order binary.ByteOrder, words ...uint32) *starfile.Bytes {
	b := make([]byte, len(words)*4)
	for i, w := range words {
		order.PutUint32(b[i*4:], w)
	}
	return &starfile.Bytes{Data: b}
}
func TestPowerPCBranchesAndByteOrder(t *testing.T) {
	for _, order := range []struct {
		name string
		bo   binary.ByteOrder
	}{{"big", binary.BigEndian}, {"little", binary.LittleEndian}} {
		t.Run(order.name, func(t *testing.T) {
			src := instructionSource(order.bo, 0x7c0802a6, 0x4bfffffd, 0x4b7f68c2, 0x4e800020)
			got, err := PowerPCInstructions(src, 0, 16, 0xffffffffff100000, order.name, 4)
			if err != nil {
				t.Fatal(err)
			}
			if got[0].Text != "mflr r0" || got[1].Target == nil || *got[1].Target != 0xffffffffff100000 || got[2].Target == nil || *got[2].Target != 0xffffffffff7f68c0 || got[3].Text != "blr" {
				t.Fatalf("%+v", got)
			}
			if got[1].Arguments[0].Value != -4 || got[2].Arguments[0].Value != -8427328 {
				t.Fatal(got[1].Arguments, got[2].Arguments)
			}
		})
	}
}
func TestPowerPCInvalidInputAndBudget(t *testing.T) {
	src := instructionSource(binary.BigEndian, 0, 0x4e800020)
	got, err := PowerPCInstructions(src, 0, 8, 0, "big", 2)
	if err != nil || got[0].Error == "" || got[0].Length != 4 || got[1].Opcode != "bclr" {
		t.Fatal(got, err)
	}
	for _, tc := range []struct {
		off, size int64
		address   uint64
		order     string
		maximum   int
	}{
		{-1, 4, 0, "big", 2}, {0, 5, 0, "big", 2}, {4, 8, 0, "big", 2}, {0, 8, math.MaxUint64 - 4, "big", 2}, {0, 4, 0, "middle", 2}, {0, 8, 0, "big", 1},
	} {
		if _, err := PowerPCInstructions(src, tc.off, tc.size, tc.address, tc.order, tc.maximum); err == nil {
			t.Fatal("accepted invalid request", tc)
		}
	}
}
