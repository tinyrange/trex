package darwin

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Node is Apple's flattened device tree (not the Linux FDT format).
// Property names are NUL-terminated in 32 bytes; values are padded to 4 bytes.
type Node struct {
	Properties map[string][]byte
	Children   []Node
}

func (n Node) Encode() ([]byte, error) {
	var out []byte
	var visit func(Node, int) error
	visit = func(n Node, depth int) error {
		if depth > 32 || len(n.Properties) > 1024 || len(n.Children) > 1024 {
			return fmt.Errorf("darwin: device tree limit")
		}
		if len(out) > (1<<20)-8 {
			return fmt.Errorf("darwin: device tree too large")
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(n.Properties)))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(n.Children)))
		keys := make([]string, 0, len(n.Properties))
		for k := range n.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := n.Properties[k]
			if len(k) == 0 || len(k) > 31 || strings.ContainsRune(k, 0) || len(v) > 1<<20 {
				return fmt.Errorf("darwin: invalid device tree property")
			}
			if 36+(len(v)+3)&^3 > (1<<20)-len(out) {
				return fmt.Errorf("darwin: device tree too large")
			}
			var name [32]byte
			copy(name[:], k)
			out = append(out, name[:]...)
			out = binary.LittleEndian.AppendUint32(out, uint32(len(v)))
			out = append(out, v...)
			for len(out)%4 != 0 {
				out = append(out, 0)
			}
		}
		for _, c := range n.Children {
			if err := visit(c, depth+1); err != nil {
				return err
			}
		}
		if len(out) > 1<<20 {
			return fmt.Errorf("darwin: device tree too large")
		}
		return nil
	}
	if err := visit(n, 0); err != nil {
		return nil, err
	}
	return out, nil
}
func CString(s string) []byte           { return append([]byte(s), 0) }
func U32(v uint32) []byte               { return binary.LittleEndian.AppendUint32(nil, v) }
func U64(v uint64) []byte               { return binary.LittleEndian.AppendUint64(nil, v) }
func Range(address, size uint32) []byte { return append(U32(address), U32(size)...) }

// MemoryRange is a 40-byte EFI_MEMORY_DESCRIPTOR v1.
type MemoryRange struct {
	Type                                 uint32
	Physical, Virtual, Pages, Attributes uint64
}

func MemoryMap(ranges []MemoryRange) ([]byte, error) {
	var b []byte
	var end uint64
	for _, r := range ranges {
		if r.Physical%4096 != 0 || r.Virtual%4096 != 0 || r.Pages > (^uint64(0)-r.Virtual)/4096 || r.Pages == 0 || r.Physical < end || r.Pages > (^uint64(0)-r.Physical)/4096 {
			return nil, fmt.Errorf("darwin: invalid/overlapping EFI memory range")
		}
		end = r.Physical + r.Pages*4096
		b = binary.LittleEndian.AppendUint32(b, r.Type)
		b = binary.LittleEndian.AppendUint32(b, 0)
		for _, v := range []uint64{r.Physical, r.Virtual, r.Pages, r.Attributes} {
			b = binary.LittleEndian.AppendUint64(b, v)
		}
	}
	return b, nil
}

// Arguments encodes the 4096-byte XNU boot_args version 2, revision 0 ABI.
// All pointers except EFI runtime virtual addresses are physical and below 4GiB.
type Arguments struct {
	CommandLine                                                       string
	MemoryMap, MemoryMapSize, DeviceTree, DeviceTreeSize              uint32
	KernelAddress, KernelSize, EFISystemTable                         uint32
	RuntimePageStart, RuntimePageCount                                uint32
	RuntimeVirtualPage                                                uint64
	Video                                                             [6]uint32 // base, display, stride, width, height, depth
	BootMemoryStart, BootMemorySize, PhysicalMemorySize, FSBFrequency uint64
}

func (a Arguments) Encode() ([]byte, error) {
	if len(a.CommandLine) > 1023 || strings.ContainsRune(a.CommandLine, 0) {
		return nil, fmt.Errorf("darwin: command line must be NUL-free and shorter than 1024 bytes")
	}
	if a.MemoryMap == 0 || a.MemoryMapSize == 0 || a.MemoryMapSize%40 != 0 || a.DeviceTree == 0 || a.DeviceTreeSize == 0 || a.KernelAddress == 0 || a.KernelSize == 0 {
		return nil, fmt.Errorf("darwin: missing boot metadata")
	}
	for _, r := range [][2]uint32{{a.MemoryMap, a.MemoryMapSize}, {a.DeviceTree, a.DeviceTreeSize}, {a.KernelAddress, a.KernelSize}} {
		if uint64(r[0])+uint64(r[1]) > 1<<32 {
			return nil, fmt.Errorf("darwin: metadata range wraps 32-bit address space")
		}
	}
	if uint64(a.RuntimePageStart)+uint64(a.RuntimePageCount) > 1<<20 || a.RuntimeVirtualPage > (^uint64(0)>>12)-uint64(a.RuntimePageCount) {
		return nil, fmt.Errorf("darwin: invalid runtime page range")
	}
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint16(b[2:], 2)
	b[4] = 64
	copy(b[8:1032], a.CommandLine)
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	put(1032, a.MemoryMap)
	put(1036, a.MemoryMapSize)
	put(1040, 40)
	put(1044, 1)
	for i, v := range a.Video {
		put(1048+i*4, v)
	}
	put(1072, a.DeviceTree)
	put(1076, a.DeviceTreeSize)
	put(1080, a.KernelAddress)
	put(1084, a.KernelSize)
	put(1088, a.RuntimePageStart)
	put(1092, a.RuntimePageCount)
	binary.LittleEndian.PutUint64(b[1096:], a.RuntimeVirtualPage)
	put(1104, a.EFISystemTable)
	for i, v := range []uint64{a.BootMemoryStart, a.BootMemorySize, a.PhysicalMemorySize, a.FSBFrequency} {
		binary.LittleEndian.PutUint64(b[1128+i*8:], v)
	}
	return b, nil
}
