package cc

import (
	"encoding/binary"
	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
	"testing"
)

// Exercise firmware/OS resource enumeration through configuration mechanism 1,
// including byte-lane writes, absent functions and fixed aperture readback.
func TestPCIDisplayEnumeration(t *testing.T) {
	p := &pc{pciDisplay: newPCIDisplay(), pciIDE: newPCIIDE()}
	config := func(address uint32, write bool, data []byte) {
		t.Helper()
		a := make([]byte, 4)
		binary.LittleEndian.PutUint32(a, address&^3)
		if err := p.pciIO(hypervisor.X86Exit{Port: 0xcf8, Size: 4, Count: 1, Write: true, Data: a}); err != nil {
			t.Fatal(err)
		}
		if err := p.pciIO(hypervisor.X86Exit{Port: 0xcfc + uint16(address&3), Size: uint8(len(data)), Count: 1, Write: write, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(address uint32) uint32 {
		b := make([]byte, 4)
		config(address, false, b)
		return binary.LittleEndian.Uint32(b)
	}
	if read(0x80001000) != 0xcc021234 || read(0x80001008) != 0x03000001 {
		t.Fatal("wrong synthetic display identity")
	}
	if read(0x80001100) != 0xffffffff || read(0x80001800) != 0xffffffff {
		t.Fatal("absent function/device decoded")
	}
	if read(0x80000800) != 0xcc011234 {
		t.Fatal("display collided with IDE")
	}
	for n := uint32(0); n < 4; n++ {
		config(0x80001010+n, true, []byte{0xff})
	}
	mask := read(0x80001010)
	if ^(mask&0xfffffff0)+1 != ramfb.Size {
		t.Fatalf("BAR size differs from actual mapping: %#x", mask)
	}
	config(0x80001010, true, []byte{0, 0, 0, 0xd0})
	if read(0x80001010) != ramfb.Address {
		t.Fatal("fixed BAR claimed unmapped relocation")
	}
	config(0x80001004, true, []byte{0, 0, 0xff, 0xff})
	if read(0x80001004) != 2 {
		t.Fatal("fixed decode or unsupported features advertised")
	}
	for offset := uint32(0x14); offset < 0x28; offset += 4 {
		config(0x80001000+offset, true, []byte{0xff, 0xff, 0xff, 0xff})
		if read(0x80001000+offset) != 0 {
			t.Fatal("unimplemented BAR claimed memory")
		}
	}
	if read(0x8000103c) != 0xff {
		t.Fatal("display claimed interrupt")
	}
}
