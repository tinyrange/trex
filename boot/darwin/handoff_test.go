package darwin

import (
	"encoding/binary"
	"testing"
)

func TestBootArgsABI(t *testing.T) {
	b, err := (Arguments{CommandLine: "-v rd=md0", MemoryMap: 0x4000, MemoryMapSize: 80, DeviceTree: 0x5000, DeviceTreeSize: 96, KernelAddress: 0x100000, KernelSize: 0x800000, EFISystemTable: 0x6000, PhysicalMemorySize: 2 << 30, FSBFrequency: 100000000, Video: [6]uint32{0xe0001000, 1, 5120, 1280, 720, 32}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 4096 || binary.LittleEndian.Uint16(b[2:]) != 2 || b[4] != 64 || string(b[8:17]) != "-v rd=md0" || b[17] != 0 || binary.LittleEndian.Uint32(b[1072:]) != 0x5000 || binary.LittleEndian.Uint32(b[1104:]) != 0x6000 || binary.LittleEndian.Uint64(b[1144:]) != 2<<30 {
		t.Fatal("ABI offsets wrong")
	}
}
func TestDeviceTreeWirePadding(t *testing.T) {
	tree := Node{Properties: map[string][]byte{"name": CString("/")}, Children: []Node{{Properties: map[string][]byte{"name": CString("chosen"), "RAMDisk": Range(0x200000, 0x300000)}}}}
	b, err := tree.Encode()
	if err != nil {
		t.Fatal(err)
	}
	u := binary.LittleEndian.Uint32
	if u(b) != 1 || u(b[4:]) != 1 || string(b[8:12]) != "name" || u(b[40:]) != 2 || b[44] != '/' || b[45] != 0 || u(b[48:]) != 2 || u(b[52:]) != 0 || string(b[56:63]) != "RAMDisk" || u(b[88:]) != 8 || u(b[92:]) != 0x200000 {
		t.Fatalf("wrong flattened tree: %x", b)
	}
	if _, err = (Node{Properties: map[string][]byte{string(make([]byte, 32)): nil}}).Encode(); err == nil {
		t.Fatal("accepted invalid name")
	}
	if _, err = MemoryMap([]MemoryRange{{Type: 7, Physical: 4096, Pages: 2}, {Type: 7, Physical: 8192, Pages: 1}}); err == nil {
		t.Fatal("accepted overlap")
	}
}

func TestDeviceTreeAggregateBoundAndRuntimeAlignment(t *testing.T) {
	value := make([]byte, 1<<19)
	if _, err := (Node{Properties: map[string][]byte{"a": value, "b": value}}).Encode(); err == nil {
		t.Fatal("accepted excessive aggregate tree")
	}
	for _, r := range []MemoryRange{{Physical: 4096, Virtual: 1, Pages: 1}, {Physical: 4096, Virtual: 0xfffffffffffff000, Pages: 2}, {Physical: 0xfffffffffffff000, Pages: 2}} {
		if _, err := MemoryMap([]MemoryRange{r}); err == nil {
			t.Fatal("accepted wrapping/unaligned descriptor")
		}
	}
	a := Arguments{MemoryMap: 0xfffffff0, MemoryMapSize: 80, DeviceTree: 4096, DeviceTreeSize: 8, KernelAddress: 0x100000, KernelSize: 4096}
	if _, err := a.Encode(); err == nil {
		t.Fatal("accepted wrapping boot metadata")
	}
}
