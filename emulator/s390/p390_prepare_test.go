package s390

import (
	"encoding/binary"
	"testing"
)

func TestP390PreparationPreservesArchitecturalStateAndInvalidatesCode(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	c := p.Machine.CPUs[0]
	program := []byte{0xa7, 0x18, 0, 17, 0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20}
	images := []Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: program}, {Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}
	if err := p.Machine.Load(images, false); err != nil {
		t.Fatal(err)
	}
	p.Advance(20)
	if binary.BigEndian.Uint32(c.S.Mem[0x900:]) != 17 {
		t.Fatal("precondition: code not executed")
	}
	c.Stopped = true
	c.GR[7], c.CR[7], c.AR[7], c.FPR[6] = 0x12345678, 0x76543000, 99, 0x1122334455667788
	c.S.Keys[8] = 0xa8
	c.S.Mem[0x8003] = 29 // direct memory edit deliberately bypasses host-write purge
	psw := c.PSW.Encode()
	p.Aperture[p390Combuf+0x33] = 0x22
	if err := p.manual(); err != nil {
		t.Fatal(err)
	}
	if c.PSW.Encode() != psw || !c.Stopped || c.GR[7] != 0x12345678 || c.CR[7] != 0x76543000 || c.AR[7] != 99 || c.FPR[6] != 0x1122334455667788 || c.S.Keys[8] != 0xa8 || c.S.Mem[0x8003] != 29 || p.IORequests != 0 || p.Aperture[p390Combuf+0x30] != 0xff {
		t.Fatal("preparation reset state, cleared data, started CPU, or manufactured I/O")
	}
	c.loadPSW(0x0008000080008000)
	c.Stopped = false
	p.Advance(20)
	if binary.BigEndian.Uint32(c.S.Mem[0x900:]) != 29 {
		t.Fatal("preparation retained stale translation")
	}
}

func TestP390PreparationRejectsUnsafeStateWithoutAck(t *testing.T) {
	for _, mode := range []string{"uninitialized", "operating", "host-io", "ipl"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := NewP390(1 << 20)
			p.Initialized = true
			p.Machine.CPUs[0].Stopped = true
			p.Aperture[p390Combuf+0x33] = 0x22
			switch mode {
			case "uninitialized":
				p.Initialized = false
			case "operating":
				p.Machine.CPUs[0].Stopped = false
			case "host-io":
				p.IOPending = true
			case "ipl":
				p.ipl = &p390IPL{}
			}
			if err := p.manual(); err == nil || p.Aperture[p390Combuf+0x30] != 0 {
				t.Fatal("unsafe preparation acknowledged")
			}
		})
	}
}
