package s390

import (
	"encoding/binary"
	"testing"
	"time"
)

func newP390370Test(t *testing.T) *P390 {
	t.Helper()
	p, err := NewP390WithConfig(Config{Memory: 1 << 20, S370: true, Start: time.Date(1985, 1, 1, 8, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	s := p.Aperture[p390Subchannels+128 : p390Subchannels+192]
	s[5] = 3
	be.PutUint16(s[6:], 9)
	return p
}

func TestP390S370RealSIOAndBCOrECInterruption(t *testing.T) {
	for _, bc := range []bool{true, false} {
		p := newP390370Test(t)
		c := p.Machine.CPUs[0]
		psw, wait, handler, done := uint64(0x8000), uint64(0x8002000000000000), uint64(0x8100), uint64(0x0002000000000000)
		if !bc {
			psw = 0x0008000000008000
			wait = 0x020a000000000000
			handler = 0x0008000000008100
			done = 0x000a000000000000
		}
		copy(c.S.Mem[0x8000:], []byte{0x9c, 0, 0, 9, 0x82, 0, 0x0f, 0x10})
		copy(c.S.Mem[0x8100:], []byte{0xa7, 0x28, 0, 17, 0x50, 0x20, 9, 0, 0x82, 0, 0x0f, 0x20})
		be.PutUint64(c.S.Mem[0xf10:], wait)
		be.PutUint64(c.S.Mem[0xf20:], done)
		be.PutUint64(c.S.Mem[pswIONew:], handler)
		be.PutUint32(c.S.Mem[0x48:], 0xa0003100)
		c.GR[1] = 0x12345678
		c.CR[2] = 0x80000000
		c.loadPSW(psw)
		c.Stopped = false
		p.Advance(50)
		if !p.IOPending || c.Instructions != 1 || p.IOInstruction != 0xb233 || c.GR[1] != 0x12345678 || binary.BigEndian.Uint32(p.Aperture[p390Combuf+0xc:]) != 0xa0003100 {
			t.Fatal("classic SIO did not hand CAW/device to original host")
		}
		p.AcknowledgeInterrupt()
		p.Aperture[p390Combuf+0x10] = 0xf0
		if err := p.WriteAperture(0x101, []byte{4}); err != nil {
			t.Fatal(err)
		}
		// Model only host status, not a native device implementation.
		packet := []byte{0, 1, 0, 2, 0, 0, 0, 7, 0, 0, 0x31, 8, 0x0c, 0, 0, 0}
		if err := p.WriteAperture(p390Combuf+0x20, packet); err != nil {
			t.Fatal(err)
		}
		if err := p.WriteAperture(0x101, []byte{4}); err != nil {
			t.Fatal(err)
		}
		p.Advance(50)
		if c.Check || p.Machine.Interrupts["io"] != 1 || be.Uint32(c.S.Mem[0x900:]) != 17 || be.Uint64(c.S.Mem[0x40:]) != 0xa00031080c000000 || p.interrupts[2].pending {
			t.Fatalf("S/370 host interrupt failed: %v %v", p.RunReason, p.Machine.Interrupts)
		}
		if bc {
			if be.Uint16(c.S.Mem[pswIOOld+2:]) != 9 || be.Uint16(c.S.Mem[0xba:]) != 0 {
				t.Fatal("BC interruption identity wrong")
			}
		} else if be.Uint16(c.S.Mem[0xba:]) != 9 {
			t.Fatal("EC interruption identity wrong")
		}
		if len(p.Machine.CSS.subs) != 0 {
			t.Fatal("native device bypass installed")
		}
	}
}

func TestP390S370IPLDeviceIdentityAndKeys(t *testing.T) {
	p := newP390370Test(t)
	c := p.Machine.CPUs[0]
	c.Stopped = true
	p.Aperture[p390Combuf+0x33] = 0x20
	be.PutUint32(p.Aperture[p390Combuf+0x34:], 9)
	if err := p.manual(); err != nil {
		t.Fatal(err)
	}
	p.Aperture[p390Combuf+0x10] = 0xf0
	if err := p.WriteAperture(0x101, []byte{4}); err != nil {
		t.Fatal(err)
	}
	be.PutUint64(c.S.Mem, 0x0002000000008000)
	packet := []byte{0, 1, 0, 2, 0, 0, 0, 7, 0, 0, 0, 16, 0x0c, 0, 0, 0}
	p.WriteAperture(p390Combuf+0x20, packet)
	if err := p.WriteAperture(0x101, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if !c.PSW.BC || c.PSW.IntCode != 9 || be.Uint16(c.S.Mem[2:]) != 9 || c.S.KeyShift != 11 || c.M.Time().Year() != 1985 {
		t.Fatal("S/370 boot identity, key size or initial clock lost")
	}
}

func TestP390S370TIOAndChannelQueriesUseHostCatalog(t *testing.T) {
	p := newP390370Test(t)
	c := p.Machine.CPUs[0]
	p.io370(c, []byte{0x9c}, 0x10)
	if c.PSW.CC != 3 || p.IORequests != 0 {
		t.Fatal("missing device accepted")
	}
	p.io370(c, []byte{0x9f}, 0)
	if c.PSW.CC != 0 {
		t.Fatal("installed channel missing")
	}
	c.stidc(0)
	if c.PSW.CC != 0 || c.lowWord(0xa8) != 0x10000000 {
		t.Fatal("STIDC ignored host catalog")
	}
	x := &p.interrupts[2]
	x.pending = true
	x.irq = true
	x.ccwaddr = 0x1234
	x.devStatus = 0x0c
	x.residual = 3
	p.io370(c, []byte{0x9d}, 9)
	if c.PSW.CC != 1 || c.lowDouble(0x40) != 0x000012340c000003 || x.pending {
		t.Fatal("TIO failed to consume original status")
	}
	p.io370(c, []byte{0x9d}, 9)
	if c.PSW.CC != 0 {
		t.Fatal("TIO status consumed twice")
	}
}
