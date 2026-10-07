package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
)

// Read the firmware bytes as an XNU device-tree consumer, rather than
// checking a Go-side map or searching for an unscoped property name.
func chosenEntropy(t *testing.T, tree []byte) []byte {
	t.Helper()
	offset := 0
	var seed []byte
	var visit func(string)
	visit = func(parent string) {
		if offset+8 > len(tree) {
			t.Fatal("truncated device tree")
		}
		properties := int(binary.LittleEndian.Uint32(tree[offset:]))
		children := int(binary.LittleEndian.Uint32(tree[offset+4:]))
		offset += 8
		props := map[string][]byte{}
		for i := 0; i < properties; i++ {
			if offset+36 > len(tree) {
				t.Fatal("truncated property")
			}
			name := string(bytes.TrimRight(tree[offset:offset+32], "\x00"))
			size := int(binary.LittleEndian.Uint32(tree[offset+32:]))
			offset += 36
			if size > len(tree)-offset {
				t.Fatal("property extends outside tree")
			}
			props[name] = tree[offset : offset+size]
			offset += (size + 3) &^ 3
		}
		path := parent + "/" + string(bytes.TrimRight(props["name"], "\x00"))
		if string(bytes.TrimRight(props["name"], "\x00")) == "/" {
			path = ""
		}
		if path == "/chosen" {
			seed = props["random-seed"]
		}
		for i := 0; i < children; i++ {
			visit(path)
		}
	}
	visit("")
	if offset != len(tree) {
		t.Fatal("unexpected device tree tail")
	}
	return seed
}

func TestDarwinFirmwareEntropyConsumer(t *testing.T) {
	cpu := &darwinTestCPU{}
	pc := &pc{cpu: cpu, ram: make([]byte, 160<<20), framebuffer: make([]byte, ramfb.Size)}
	boot := &vmm.DarwinBoot{Kernel: darwinKernel(0x200000)}
	readSeed := func() []byte {
		t.Helper()
		if err := pc.installDarwin(boot); err != nil {
			t.Fatal(err)
		}
		args := pc.ram[cpu.regs.Rax : cpu.regs.Rax+4096]
		start := binary.LittleEndian.Uint32(args[1072:])
		size := binary.LittleEndian.Uint32(args[1076:])
		seed := chosenEntropy(t, pc.ram[start:start+size])
		// XNU2782 early_random needs all 64 bytes; PE_get_random_seed
		// rejects an all-zero seed and clears the consumed guest property.
		if len(seed) != 64 || bytes.Equal(seed, make([]byte, 64)) {
			t.Fatal("firmware entropy would be rejected by original XNU")
		}
		result := bytes.Clone(seed)
		clear(seed)
		return result
	}
	first, second := readSeed(), readSeed()
	if bytes.Equal(first, second) {
		t.Fatal("firmware reused entropy across boots")
	}
}
