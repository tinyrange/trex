package windows

import (
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

func TestAMD64Version2BodyUnwind(t *testing.T) {
	// A 0x300-byte function with two 8-byte epilogs, one at the end and
	// one 0x110 bytes back. The prolog allocates 32 bytes and saves RBX.
	image := &pe.File{Sections: []*pe.Section{{SectionHeader: pe.SectionHeader{VirtualAddress: 0x1000, VirtualSize: 64, Size: 64}}}}
	data := make([]byte, 64)
	copy(data, []byte{2, 5, 4, 0, 8, 0x16, 0x10, 0x16, 5, 0x32, 1, 0x30})
	fn := amd64RuntimeFunction{begin: 0x2000, end: 0x2300, unwind: 0x1000}
	stack := make([]byte, 48)
	binary.LittleEndian.PutUint64(stack[32:], 0x12345678)
	binary.LittleEndian.PutUint64(stack[40:], 0x87654321)
	state := amd64UnwindState{stack: stack, stackBase: 0x8000, stackEnd: 0x8030, rsp: 0x8000}
	if err := amd64ApplyUnwind(image, data, fn, 0x80, &state, 0); err != nil {
		t.Fatal(err)
	}
	if state.rsp != 0x8028 || state.registers[3] != 0x12345678 {
		t.Fatalf("rsp=%x rbx=%x", state.rsp, state.registers[3])
	}
	ret, err := state.readUint64(state.rsp)
	if err != nil || ret != 0x87654321 {
		t.Fatalf("return=%x err=%v", ret, err)
	}
	for _, pc := range []uint32{0x1f0, 0x1f7, 0x2f8, 0x2ff} {
		if _, err := amd64BodyUnwindStart(2, data[4:12], fn, pc); err == nil || !strings.Contains(err.Error(), "epilog PC") {
			t.Fatalf("accepted epilog pc=%x: %v", pc, err)
		}
	}
	// Partial prolog: only RBX has been pushed, allocation not yet executed.
	state = amd64UnwindState{stack: stack[32:], stackBase: 0x8000, stackEnd: 0x8010, rsp: 0x8000}
	if err := amd64ApplyUnwind(image, data, fn, 1, &state, 0); err != nil || state.rsp != 0x8008 || state.registers[3] != 0x12345678 {
		t.Fatalf("partial prolog: %+v %v", state, err)
	}
}

func TestAMD64Version2EpilogDescriptors(t *testing.T) {
	fn := amd64RuntimeFunction{begin: 0x1000, end: 0x1300}
	for _, tt := range []struct {
		codes []byte
		want  int
	}{
		{[]byte{8, 0x16, 0, 6, 5, 0x32}, 2},          // at-end plus padding
		{[]byte{8, 6, 0x10, 0x16, 0, 6, 5, 0x32}, 3}, // explicit 0x110 distance
		{[]byte{5, 0x32}, 0},
	} {
		got, err := amd64BodyUnwindStart(2, tt.codes, fn, 0x80)
		if err != nil || got != tt.want {
			t.Fatalf("%x -> %d %v", tt.codes, got, err)
		}
	}
	for _, bad := range [][]byte{{8}, {0, 0x16}, {8, 0x26}, {8, 6}, {8, 6, 0, 6}, {8, 6, 4, 6}, {8, 6, 1, 0x46}} {
		if _, err := amd64BodyUnwindStart(2, bad, fn, 0x80); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
	if got, err := amd64BodyUnwindStart(1, []byte{8, 0x16}, fn, 0x80); err != nil || got != 0 {
		t.Fatal("version 1 reinterpreted")
	}
}
