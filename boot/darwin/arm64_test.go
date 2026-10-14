package darwin

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func arm64KernelFixture() []byte {
	b := make([]byte, 0x8000)
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	put(0, 0xfeedfacf)
	put(4, 0x100000c)
	put(8, 2)
	put(12, 12)
	put(16, 2)
	put(20, 72+288)
	put(32, 0x19)
	put(36, 72)
	copy(b[40:], "__TEXT")
	binary.LittleEndian.PutUint64(b[56:], 0xfffffe0007004000)
	binary.LittleEndian.PutUint64(b[64:], 0x10000)
	binary.LittleEndian.PutUint64(b[80:], uint64(len(b)))
	put(104, 5)
	put(108, 288)
	put(112, 6)
	put(116, 68)
	binary.LittleEndian.PutUint64(b[376:], 0xfffffe0007005000)
	copy(b[0x1000:], []byte{0x1f, 0x20, 0x03, 0xd5})
	return b
}

func TestARM64HandoffLayoutAndUnchangedKernel(t *testing.T) {
	k := arm64KernelFixture()
	tree, err := (Node{Properties: map[string][]byte{"name": CString("device-tree")}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0xab}, 256)
	h, err := PrepareARM64(bytes.NewReader(k), bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "-v", seed)
	if err != nil {
		t.Fatal(err)
	}
	if h.Address != 0x77004000 || h.Entry != 0x77005000 || h.Arguments&0x3fff != 0 {
		t.Fatalf("handoff %+v", h)
	}
	loaded := make([]byte, len(k))
	if _, err := h.Image.ReadAt(loaded, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, k) {
		t.Fatal("kernel modified")
	}
	bss := make([]byte, 0x8000)
	h.Image.ReadAt(bss, 0x8000)
	if !bytes.Equal(bss, make([]byte, len(bss))) {
		t.Fatal("BSS not zero")
	}
	a := make([]byte, 1152)
	h.Image.ReadAt(a, int64(h.Arguments-h.Address))
	if binary.LittleEndian.Uint16(a) != 2 || binary.LittleEndian.Uint64(a[96:]) != 0xfffffe0000000000+h.DeviceTree-0x70000000 || string(a[108:111]) != "-v\x00" || binary.LittleEndian.Uint64(a[1144:]) != 1536<<20 {
		t.Fatalf("bad ARM64 arguments")
	}
	dt := make([]byte, binary.LittleEndian.Uint32(a[104:]))
	h.Image.ReadAt(dt, int64(h.DeviceTree-h.Address))
	n, err := DecodeNode(bytes.NewReader(dt))
	if err != nil {
		t.Fatal(err)
	}
	chosen := arm64Child(&n, "chosen")
	if binary.LittleEndian.Uint64(chosen.Properties["dram-base"]) != 0x70000000 || binary.LittleEndian.Uint64(chosen.Properties["dram-size"]) != 1536<<20 {
		t.Fatal("missing full DRAM range")
	}
	if !bytes.Equal(chosen.Properties["random-seed"], seed) {
		t.Fatal("boot entropy lost")
	}
	defaultNVRAM, _ := EmptyARM64NVRAM(8192)
	if !bytes.Equal(h.NVRAM, defaultNVRAM) || !bytes.Equal(h.NVRAM, chosen.Properties["nvram-proxy-data"]) {
		t.Fatal("default NVRAM proxy and physical bank differ")
	}
	m := arm64Child(chosen, "memory-map").Properties
	if binary.LittleEndian.Uint64(m["Kernel-__TEXT"]) != h.Address || binary.LittleEndian.Uint64(m["DeviceTree"][8:]) != uint64(len(dt)) {
		t.Fatal("bad memory map")
	}
}

func TestARM64HandoffNVRAMProxyAndPhysicalBank(t *testing.T) {
	bank, err := ARM64NVRAM(8192, map[string]string{"fixture-config": `{"mode":"test"}`}, map[string]string{"system-name": "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []bool{false, true} {
		node := Node{Properties: map[string][]byte{"name": CString("device-tree")}}
		chosen := arm64Child(&node, "chosen")
		chosen.Properties["nvram-proxy-data"] = bank
		chosen.Properties["nvram-bank-size"] = U32(uint32(len(bank)))
		chosen.Properties["nvram-bank-count"] = U32(1)
		chosen.Properties["nvram-current-bank"] = U32(0)
		var override []byte
		if supplied {
			override = bank
			// Explicit bank bytes replace the original proxy and its metadata.
			chosen.Properties["nvram-proxy-data"] = []byte("stale")
			chosen.Properties["nvram-bank-size"] = U32(0)
			chosen.Properties["nvram-bank-count"] = U32(0)
			chosen.Properties["nvram-current-bank"] = U32(9)
			chosen.PropertyFlags = map[string]uint32{"nvram-bank-size": 0x80000000}
		}
		tree, err := node.Encode()
		if err != nil {
			t.Fatal(err)
		}
		h, err := PrepareARM64WithNVRAM(bytes.NewReader(arm64KernelFixture()), bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "-v", bytes.Repeat([]byte{1}, 256), override)
		if err != nil {
			t.Fatal(err)
		}
		args := make([]byte, 1152)
		h.Image.ReadAt(args, int64(h.Arguments-h.Address))
		dt := make([]byte, binary.LittleEndian.Uint32(args[104:]))
		h.Image.ReadAt(dt, int64(h.DeviceTree-h.Address))
		decoded, err := DecodeNode(bytes.NewReader(dt))
		if err != nil {
			t.Fatal(err)
		}
		actual := arm64Child(&decoded, "chosen")
		if !bytes.Equal(h.NVRAM, bank) || !bytes.Equal(actual.Properties["nvram-proxy-data"], h.NVRAM) || binary.LittleEndian.Uint32(actual.Properties["nvram-bank-size"]) != uint32(len(bank)) || binary.LittleEndian.Uint32(actual.Properties["nvram-bank-count"]) != 1 || binary.LittleEndian.Uint32(actual.Properties["nvram-current-bank"]) != 0 || actual.PropertyFlags["nvram-bank-size"] != 0 {
			t.Fatal("NVRAM proxy and physical backing contract differ")
		}
		h.NVRAM[100] ^= 0xff
		if !bytes.Equal(actual.Properties["nvram-proxy-data"], bank) {
			t.Fatal("physical seed aliases supplied bank or encoded proxy")
		}
	}
}

func TestARM64HandoffRejectsMismatchedNVRAM(t *testing.T) {
	bank, _ := EmptyARM64NVRAM(8192)
	for _, size := range []int{0, 4095, 4097, 65568} {
		if _, err := PrepareARM64WithNVRAM(nil, nil, 0, 0, 0, "", nil, make([]byte, size)); err == nil {
			t.Fatal("invalid explicit NVRAM bank accepted", size)
		}
	}
	for _, mutate := range []func(map[string][]byte){
		func(p map[string][]byte) { p["nvram-proxy-data"] = bank[:8191] },
		func(p map[string][]byte) { p["nvram-bank-size"] = U32(4096) },
		func(p map[string][]byte) { p["nvram-bank-count"] = U32(2) },
		func(p map[string][]byte) { p["nvram-current-bank"] = U32(1) },
		func(p map[string][]byte) { p["nvram-current-bank"] = []byte{0} },
		func(p map[string][]byte) { delete(p, "nvram-bank-count") },
	} {
		node := Node{Properties: map[string][]byte{"name": CString("device-tree")}}
		properties := arm64Child(&node, "chosen").Properties
		properties["nvram-proxy-data"], properties["nvram-bank-size"] = bank, U32(uint32(len(bank)))
		properties["nvram-bank-count"], properties["nvram-current-bank"] = U32(1), U32(0)
		mutate(properties)
		tree, _ := node.Encode()
		if _, err := PrepareARM64(bytes.NewReader(arm64KernelFixture()), bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "-v", bytes.Repeat([]byte{1}, 256)); err == nil {
			t.Fatal("inconsistent physical NVRAM bank metadata accepted")
		}
	}
}

func TestARM64HandoffRejectsBadLayout(t *testing.T) {
	tree, _ := (Node{Properties: map[string][]byte{"name": CString("device-tree")}}).Encode()
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint64(b[376:], 0) }, func(b []byte) { binary.LittleEndian.PutUint64(b[64:], 1<<32) }, func(b []byte) { binary.LittleEndian.PutUint32(b[116:], 67) }, func(b []byte) { binary.LittleEndian.PutUint64(b[56:], 0xfffffe0107004000) }} {
		b := arm64KernelFixture()
		mutate(b)
		if _, err := PrepareARM64(bytes.NewReader(b), bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "-v", bytes.Repeat([]byte{0xab}, 64)); err == nil {
			t.Fatal("accepted malformed kernel")
		}
	}
	for _, seed := range [][]byte{nil, make([]byte, 64), make([]byte, 256), bytes.Repeat([]byte{0xab}, 63), bytes.Repeat([]byte{0xab}, 255)} {
		if _, err := PrepareARM64(bytes.NewReader(arm64KernelFixture()), bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "-v", seed); err == nil {
			t.Fatal("accepted invalid boot entropy")
		}
	}
	if _, err := (ARM64Arguments{CommandLine: string(make([]byte, 1024))}).Encode(); err == nil {
		t.Fatal("accepted oversized args")
	}
}

func TestARM64PayloadReservations(t *testing.T) {
	tree, _ := (Node{Properties: map[string][]byte{"name": CString("device-tree")}}).Encode()
	kernel := bytes.NewReader(arm64KernelFixture())
	disk := bytes.NewReader(bytes.Repeat([]byte{0x73}, 0x5001))
	trust := bytes.NewReader(bytes.Repeat([]byte{0x41}, 8000))
	h, err := PrepareARM64(kernel, bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "rd=md0", bytes.Repeat([]byte{1}, 256), ARM64Payload{Name: "RAMDisk", Data: disk}, ARM64Payload{Name: "TrustCache", Data: trust})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Payloads) != 2 || h.Payloads[0].Data != disk || h.Payloads[1].Data != trust {
		t.Fatal("inputs copied or lost")
	}
	if h.Payloads[0].Address != h.Address+uint64(h.Image.Size()) || h.Payloads[1].Address != h.Address-0x4000 {
		t.Fatal("wrong separate placement")
	}
	args := make([]byte, 1152)
	h.Image.ReadAt(args, int64(h.Arguments-h.Address))
	top := binary.LittleEndian.Uint64(args[32:])
	if top != h.Payloads[0].Address+0x8000 {
		t.Fatal("payload not reserved")
	}
	dt := make([]byte, binary.LittleEndian.Uint32(args[104:]))
	h.Image.ReadAt(dt, int64(h.DeviceTree-h.Address))
	node, err := DecodeNode(bytes.NewReader(dt))
	if err != nil {
		t.Fatal(err)
	}
	m := arm64Child(arm64Child(&node, "chosen"), "memory-map").Properties
	for _, p := range h.Payloads {
		if binary.LittleEndian.Uint64(m[p.Name]) != p.Address {
			t.Fatal("memory-map address mismatch")
		}
	}
	if binary.LittleEndian.Uint64(m["RAMDisk"][8:]) != uint64(disk.Size()) || binary.LittleEndian.Uint64(m["TrustCache"][8:]) != 0x4000 {
		t.Fatal("memory-map extent mismatch")
	}
	for _, payloads := range [][]ARM64Payload{{{Name: "RAMDisk", Data: disk}, {Name: "RAMDisk", Data: trust}}, {{Name: "DeviceTree", Data: disk}}, {{Name: "empty", Data: bytes.NewReader(nil)}}, {{Name: "bad\x00", Data: disk}}} {
		if _, err := PrepareARM64(kernel, bytes.NewReader(tree), 0x70000000, 0xfffffe0000000000, 1536<<20, "", bytes.Repeat([]byte{1}, 256), payloads...); err == nil {
			t.Fatal("invalid payload accepted")
		}
	}
}
