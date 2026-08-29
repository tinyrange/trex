package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestMinidumpRegistersI386(t *testing.T) {
	context := make([]byte, 200)
	binary.LittleEndian.PutUint32(context[180:184], 0x11223344)
	binary.LittleEndian.PutUint32(context[184:188], 0x55667788)
	binary.LittleEndian.PutUint32(context[196:200], 0x99aabbcc)
	pc, sp, fp := minidumpRegisters(context, 0)
	if pc != 0x55667788 || sp != 0x99aabbcc || fp != 0x11223344 {
		t.Fatalf("registers = pc %#x sp %#x fp %#x", pc, sp, fp)
	}
}

func TestMinidumpString(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[8:12], 8)
	copy(data[12:], []byte{'g', 0, 'p', 0, 's', 0, 'v', 0})
	got, err := minidumpString(&starfile.Bytes{Name: "dump", Data: data}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got != "gpsv" {
		t.Fatalf("string = %q", got)
	}
}

func TestMinidumpFramesI386(t *testing.T) {
	stack := make([]byte, 0x80)
	start := uint64(0x1000)
	binary.LittleEndian.PutUint32(stack[0x20:0x24], 0x1040)
	binary.LittleEndian.PutUint32(stack[0x24:0x28], 0x401234)
	binary.LittleEndian.PutUint32(stack[0x40:0x44], 0x1060)
	binary.LittleEndian.PutUint32(stack[0x44:0x48], 0x402345)
	binary.LittleEndian.PutUint32(stack[0x60:0x64], 0)
	binary.LittleEndian.PutUint32(stack[0x64:0x68], 0x403456)

	frames := minidumpFrames(stack, start, 0x400123, 0x1010, 0x1020, 0)
	if len(frames) != 4 {
		t.Fatalf("frame count = %d, want 4", len(frames))
	}
	wantAddresses := []uint64{0x400123, 0x401234, 0x402345, 0x403456}
	wantStacks := []uint64{0x1010, 0x1024, 0x1044, 0x1064}
	for index := range frames {
		if frames[index].address != wantAddresses[index] || frames[index].stackAddress != wantStacks[index] {
			t.Fatalf("frame %d = %+v", index, frames[index])
		}
	}
}

func TestMinidumpFramesRejectsNonIncreasingChain(t *testing.T) {
	stack := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(stack[0x20:0x24], 0x1020)
	binary.LittleEndian.PutUint32(stack[0x24:0x28], 0x401234)
	frames := minidumpFrames(stack, 0x1000, 0x400123, 0x1010, 0x1020, 0)
	if len(frames) != 2 {
		t.Fatalf("frame count = %d, want 2", len(frames))
	}
}
