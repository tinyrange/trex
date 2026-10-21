package cc

import (
	"bytes"
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSCopyPreservesA20WrapAndPagingAtomicity(t *testing.T) {
	p := &pc{ram: make([]byte, 2<<20), a20Disabled: true}
	copy(p.ram[0xffffc:], []byte("left"))
	copy(p.ram, []byte("wrap"))
	copy(p.ram[0x100000:], []byte("high"))
	data := make([]byte, 8)
	if err := p.biosCopy(0xffffc, data, false, x86state.SystemRegisters{}); err != nil || string(data) != "leftwrap" {
		t.Fatalf("A20 read %q: %v", data, err)
	}
	if err := p.biosCopy(0xffffc, []byte("ABCD1234"), true, x86state.SystemRegisters{}); err != nil {
		t.Fatal(err)
	}
	if string(p.ram[:4]) != "1234" || string(p.ram[0xffffc:0x100000]) != "ABCD" || string(p.ram[0x100000:0x100004]) != "high" {
		t.Fatal("A20 write used unmasked backing")
	}
	p, s := pagedBIOSPC()
	binary.LittleEndian.PutUint32(p.ram[0x2010:], 0)
	before := bytes.Clone(p.ram)
	if err := p.biosCopy(0x3ffc, []byte("bad-tail"), true, s); err == nil {
		t.Fatal("unmapped tail accepted")
	}
	if !bytes.Equal(p.ram, before) {
		t.Fatal("rejected paged write partially changed RAM or A/D bits")
	}
}
