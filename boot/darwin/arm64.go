package darwin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tinyrange/trex/binary/macho"
	"github.com/tinyrange/trex/storage"
)

// ARM64Arguments is XNU's 64-bit boot_args revision 2/version 2 ABI.
// DeviceTree is a kernel virtual address; TopOfKernelData is physical.
type ARM64Arguments struct {
	VirtualBase, PhysicalBase, MemorySize, TopOfKernelData uint64
	DeviceTree                                             uint64
	DeviceTreeLength                                       uint32
	CommandLine                                            string
	BootFlags, MemorySizeActual                            uint64
}

func (a ARM64Arguments) Encode() ([]byte, error) {
	if len(a.CommandLine) >= 1024 || strings.ContainsRune(a.CommandLine, 0) {
		return nil, fmt.Errorf("darwin arm64: command line must fit 1024 bytes including NUL")
	}
	b := make([]byte, 1152)
	binary.LittleEndian.PutUint16(b, 2)
	binary.LittleEndian.PutUint16(b[2:], 2)
	for j, v := range []uint64{a.VirtualBase, a.PhysicalBase, a.MemorySize, a.TopOfKernelData} {
		binary.LittleEndian.PutUint64(b[8+j*8:], v)
	}
	binary.LittleEndian.PutUint64(b[96:], a.DeviceTree)
	binary.LittleEndian.PutUint32(b[104:], a.DeviceTreeLength)
	copy(b[108:1132], a.CommandLine)
	binary.LittleEndian.PutUint64(b[1136:], a.BootFlags)
	binary.LittleEndian.PutUint64(b[1144:], a.MemorySizeActual)
	return b, nil
}

type ARM64Handoff struct {
	Image                                 storage.Reader
	Address, Entry, Arguments, DeviceTree uint64
	ReadOnlyAddress, ReadOnlySize         uint64
	Payloads                              []ARM64Payload
	// NVRAM is the same single bank carried by /chosen/nvram-proxy-data.
	// The platform backend must use it to seed its physical NVRAM device.
	NVRAM []byte
}

// ARM64Payload reserves an immutable input in the physical boot handoff.
// Name identifies its /chosen/memory-map property. PrepareARM64 assigns Address.
type ARM64Payload struct {
	Name    string
	Data    storage.Reader
	Address uint64
}

// PrepareARM64 loads an unslid ARM64 executable/fileset and appends its flattened
// device tree and boot arguments. XNU itself rebases and signs fileset pointers;
// the loader leaves chained fixups and kernel instructions unchanged.
func PrepareARM64(kernel, tree storage.Reader, physicalBase, virtualBase, memory uint64, command string, entropy []byte, payloads ...ARM64Payload) (*ARM64Handoff, error) {
	return prepareARM64(kernel, tree, physicalBase, virtualBase, memory, command, entropy, nil, payloads...)
}

// PrepareARM64WithNVRAM prepares a handoff using the supplied single NVRAM bank
// in place of the tree's proxy. A nil bank preserves PrepareARM64's behavior.
func PrepareARM64WithNVRAM(kernel, tree storage.Reader, physicalBase, virtualBase, memory uint64, command string, entropy, nvram []byte, payloads ...ARM64Payload) (*ARM64Handoff, error) {
	return prepareARM64(kernel, tree, physicalBase, virtualBase, memory, command, entropy, nvram, payloads...)
}

func prepareARM64(kernel, tree storage.Reader, physicalBase, virtualBase, memory uint64, command string, entropy, nvram []byte, payloads ...ARM64Payload) (*ARM64Handoff, error) {
	if nvram != nil && (len(nvram) < 4096 || len(nvram) > 65536 || len(nvram)%32 != 0) {
		return nil, fmt.Errorf("darwin arm64: NVRAM requires one 4..64 KiB bank in 32-byte units")
	}
	// Earlier ARM64 XNU consumes 64 bytes; PCC 26.6 consumes 256 bytes.
	if (len(entropy) != 64 && len(entropy) != 256) || bytes.Equal(entropy, make([]byte, len(entropy))) {
		return nil, fmt.Errorf("darwin arm64: boot entropy requires 64 or 256 bytes with nonzero data")
	}
	if physicalBase&0x1ffffff != 0 || virtualBase&0x1ffffff != 0 || memory < 64<<20 || memory&0x1ffffff != 0 || memory > ^uint64(0)-physicalBase {
		return nil, fmt.Errorf("darwin arm64: RAM bases and size require 32 MiB alignment")
	}
	m, err := macho.Open(kernel, macho.ARM64)
	if err != nil {
		return nil, err
	}
	if m.Type != 2 && m.Type != 12 || m.Entry == 0 {
		return nil, fmt.Errorf("darwin arm64: expected executable/fileset with thread entry")
	}
	n, err := DecodeNode(tree)
	if err != nil {
		return nil, err
	}
	segments := append([]macho.Segment(nil), m.Segments...)
	sort.Slice(segments, func(i, j int) bool { return segments[i].Address < segments[j].Address })
	var start, end uint64
	for _, s := range segments {
		if s.Size == 0 {
			continue
		}
		if s.Address < virtualBase || s.Size > memory || s.Address-virtualBase > memory-s.Size || s.FileSize > s.Size || end != 0 && s.Address < end {
			return nil, fmt.Errorf("darwin arm64: overlapping/out-of-RAM segment %s", s.Name)
		}
		if start == 0 {
			start = s.Address
		}
		end = s.Address + s.Size
	}
	if start == 0 || end-start > MaxKernelSize || m.Entry < start || m.Entry >= end || m.Entry&3 != 0 {
		return nil, fmt.Errorf("darwin arm64: invalid kernel extent/entry")
	}
	if _, err := m.At(m.Entry, 4); err != nil {
		return nil, err
	}
	base := physicalBase + start - virtualBase
	dtAddress := (physicalBase + end - virtualBase + 0x3fff) &^ uint64(0x3fff)
	// Reserve the exact encoded tree, with range sizes fixed before encoding.
	chosen := arm64Child(&n, "chosen")
	// XNU distinguishes the full DRAM range from the kernel-managed bootargs
	// range and requires these 64-bit values even when the ranges coincide.
	chosen.Properties["dram-base"] = U64(physicalBase)
	chosen.Properties["dram-size"] = U64(memory)
	chosen.Properties["random-seed"] = append([]byte(nil), entropy...)
	if nvram != nil || len(chosen.Properties["nvram-proxy-data"]) == 0 {
		if nvram == nil {
			nvram, err = EmptyARM64NVRAM(8192)
			if err != nil {
				return nil, err
			}
		}
		chosen.Properties["nvram-proxy-data"] = append([]byte(nil), nvram...)
		chosen.Properties["nvram-bank-size"] = U32(uint32(len(nvram)))
		chosen.Properties["nvram-bank-count"] = U32(1)
		chosen.Properties["nvram-current-bank"] = U32(0)
		for _, key := range []string{"nvram-proxy-data", "nvram-bank-size", "nvram-bank-count", "nvram-current-bank"} {
			delete(chosen.PropertyFlags, key)
		}
	}
	nvram = chosen.Properties["nvram-proxy-data"]
	if len(nvram) < 4096 || len(nvram) > 65536 || len(nvram)%32 != 0 {
		return nil, fmt.Errorf("darwin arm64: NVRAM proxy must contain one 4..64 KiB bank in 32-byte units")
	}
	for _, property := range []struct {
		name  string
		value uint32
	}{{"nvram-bank-size", uint32(len(nvram))}, {"nvram-bank-count", 1}, {"nvram-current-bank", 0}} {
		data := chosen.Properties[property.name]
		if len(data) != 4 || binary.LittleEndian.Uint32(data) != property.value {
			return nil, fmt.Errorf("darwin arm64: %s does not match single NVRAM proxy bank", property.name)
		}
	}
	delete(chosen.PropertyFlags, "dram-base")
	delete(chosen.PropertyFlags, "dram-size")
	delete(chosen.PropertyFlags, "random-seed")
	mmap := arm64Child(chosen, "memory-map")
	for _, s := range segments {
		if s.Size != 0 {
			mmap.Properties["Kernel-"+s.Name] = arm64Range(physicalBase+s.Address-virtualBase, s.Size)
		}
	}
	mmap.Properties["DeviceTree"] = arm64Range(dtAddress, 0)
	mmap.Properties["BootArgs"] = arm64Range(0, 1152)
	if len(payloads) > 32 {
		return nil, fmt.Errorf("darwin arm64: too many handoff payloads")
	}
	seen := map[string]bool{}
	for _, p := range payloads {
		if p.Name == "" || len(p.Name) > 31 || strings.ContainsRune(p.Name, 0) || seen[p.Name] || mmap.Properties[p.Name] != nil || p.Data == nil || p.Data.Size() <= 0 {
			return nil, fmt.Errorf("darwin arm64: invalid or duplicate handoff payload %q", p.Name)
		}
		seen[p.Name] = true
		mmap.Properties[p.Name] = arm64Range(0, uint64(p.Data.Size()))
	}
	dt, err := n.Encode()
	if err != nil {
		return nil, err
	}
	argsAddress := (dtAddress + uint64(len(dt)) + 0x3fff) &^ uint64(0x3fff)
	top := (argsAddress + 1152 + 0x3fff) &^ uint64(0x3fff)
	imageTop := top
	if top-physicalBase > memory || top-base > MaxKernelSize {
		return nil, fmt.Errorf("darwin arm64: handoff exceeds RAM/image limit")
	}
	mmap.Properties["DeviceTree"] = arm64Range(dtAddress, uint64(len(dt)))
	mmap.Properties["BootArgs"] = arm64Range(argsAddress, 1152)
	loads := append([]ARM64Payload(nil), payloads...)
	low := base
	for i := range loads {
		p := &loads[i]
		size := uint64(p.Data.Size())
		// Modern XNU requires boot trust caches below the collection, where
		// they can join its CTRR-protected immutable prefix.
		if p.Name == "TrustCache" {
			if size > low-physicalBase {
				return nil, fmt.Errorf("darwin arm64: trust cache exceeds low RAM")
			}
			low = (low - size) &^ uint64(0x3fff)
			p.Address = low
			mmap.Properties[p.Name] = arm64Range(low, base-low)
			continue
		}
		if top < physicalBase || top-physicalBase > memory || size > memory-(top-physicalBase) {
			return nil, fmt.Errorf("darwin arm64: payload %q exceeds RAM", p.Name)
		}
		p.Address = top
		mmap.Properties[p.Name] = arm64Range(top, size)
		top = (top + size + 0x3fff) &^ uint64(0x3fff)
		if top < physicalBase || top-physicalBase > memory {
			return nil, fmt.Errorf("darwin arm64: payload alignment exceeds RAM")
		}
	}
	dt, err = n.Encode()
	if err != nil {
		return nil, err
	}
	args, err := (ARM64Arguments{VirtualBase: virtualBase, PhysicalBase: physicalBase, MemorySize: memory, TopOfKernelData: top, DeviceTree: virtualBase + dtAddress - physicalBase, DeviceTreeLength: uint32(len(dt)), CommandLine: command, MemorySizeActual: memory}).Encode()
	if err != nil {
		return nil, err
	}
	b := make([]byte, imageTop-base)
	for _, s := range segments {
		if s.Size != 0 && s.FileSize != 0 {
			off := s.Address - start
			if _, err := io.ReadFull(io.NewSectionReader(s.Data, 0, int64(s.FileSize)), b[off:off+s.FileSize]); err != nil {
				return nil, err
			}
		}
	}
	copy(b[dtAddress-base:], dt)
	copy(b[argsAddress-base:], args)
	h := &ARM64Handoff{Image: bytes.NewReader(b), Address: base, Entry: physicalBase + m.Entry - virtualBase, Arguments: argsAddress, DeviceTree: dtAddress, Payloads: loads, NVRAM: append([]byte(nil), nvram...)}
	// The fileset's immutable prefix ends at __TEXT_EXEC. __DATA_CONST is
	// included: XNU signs its pointers before requesting CTRR lockdown.
	for _, s := range segments {
		if s.Name == "__TEXT_EXEC" && s.Size != 0 {
			h.ReadOnlyAddress, h.ReadOnlySize = low, base-low+s.Address+s.Size-start
		}
	}
	return h, nil
}

func arm64Range(address, size uint64) []byte { return append(U64(address), U64(size)...) }
func arm64Child(n *Node, name string) *Node {
	for i := range n.Children {
		if strings.TrimRight(string(n.Children[i].Properties["name"]), "\x00") == name {
			return &n.Children[i]
		}
	}
	n.Children = append(n.Children, Node{Properties: map[string][]byte{"name": CString(name)}})
	return &n.Children[len(n.Children)-1]
}
