package cc

import (
	"encoding/binary"
	"testing"
)

type nvmeMSICPU struct {
	nvmeTestCPU
	addr     uint64
	data     uint32
	messages int
}

func (c *nvmeMSICPU) SetMSI(addr uint64, data uint32) error {
	c.addr, c.data = addr, data
	c.messages++
	return nil
}

func TestPCINVMeMSI(t *testing.T) {
	p, _ := dmaTestPC(t)
	cpu := &nvmeMSICPU{nvmeTestCPU: nvmeTestCPU{levels: map[uint32]bool{}}}
	p.cpu = cpu
	d := newPCINVMe(p)
	if d.config[6]&0x10 == 0 || d.config[0x34] != 0x50 || d.config[0x50] != 5 {
		t.Fatal("MSI capability missing")
	}
	binary.LittleEndian.PutUint64(d.config[0x54:], 0xfee03000)
	binary.LittleEndian.PutUint16(d.config[0x5c:], 0x51)
	d.write(0x52, 0xff)
	if d.config[0x52] != 0x81 {
		t.Fatal("invalid MSI control writable bits")
	}
	if err := d.syncInterrupt(); err != nil {
		t.Fatal(err)
	}
	wr := func(off, value uint64) {
		t.Helper()
		if err := d.controller.WriteMMIO(off, 8, value); err != nil {
			t.Fatal(err)
		}
	}
	wr(0x24, 15|15<<16)
	wr(0x28, 0x1000)
	wr(0x30, 0x2000)
	wr(0x14, 1)
	cmd := p.ram[0x1000:0x1040]
	cmd[0] = 6
	binary.LittleEndian.PutUint64(cmd[24:], 0x5000)
	cmd[40] = 1
	wr(0x1000, 1)
	if cpu.messages != 1 || cpu.addr != 0xfee03000 || cpu.data != 0x51 || cpu.levels[16] {
		t.Fatalf("MSI delivery: %+v", cpu)
	}
	// A second command before CQ acknowledgement still requires a message.
	copy(p.ram[0x1040:0x1080], cmd)
	wr(0x1000, 2)
	if cpu.messages != 2 {
		t.Fatal("second completion lost")
	}
}
