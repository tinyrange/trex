package cc

import (
	"bytes"
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"testing"
)

func TestIdentifyNegotiatesImplementedMultiwordDMA(t *testing.T) {
	p, data := dmaTestPC(t)
	p.pciIDE = newICH7PATA()
	p.pciIDE.config[4] = 5
	if err := p.ide.command(0xec); err != nil {
		t.Fatal(err)
	}
	word := func(i int) uint16 { return binary.LittleEndian.Uint16(p.ide.buffer[i*2:]) }
	// Independent ATA client: validity gates supported modes and cycle times.
	if word(49)&0x100 == 0 || word(53)&2 == 0 || word(63)&7 != 7 || word(65) != 120 || word(66) != 120 {
		t.Fatal("incomplete DMA identify contract")
	}
	p.ide.task[1], p.ide.task[2] = 3, 0x22
	if err := p.ide.command(0xef); err != nil {
		t.Fatal(err)
	}
	if err := p.ide.command(0xec); err != nil {
		t.Fatal(err)
	}
	if word(63)&0x700 != 0x400 {
		t.Fatal("selected MWDMA2 not reported")
	}
	binary.LittleEndian.PutUint32(p.pciIDE.bm[4:], 0x1000)
	dmaPRD(p, 0, 0x20000, 512, true)
	dmaCommand(t, p, false, 1)
	if err := p.handleIO(hypervisor.X86Exit{Port: uint16(p.pciIDE.busMasterBase()), Size: 1, Count: 1, Write: true, Data: []byte{9}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ram[0x20000:0x20200], data[1024:1536]) {
		t.Fatal("negotiated DMA did not deliver original bytes")
	}
	p.ide.dmaEnabled = false
	if err := p.ide.command(0xec); err != nil {
		t.Fatal(err)
	}
	if word(49)&0x100 != 0 || word(63) != 0 || word(53)&2 != 0 {
		t.Fatal("PIO-only disk falsely advertises DMA")
	}
}
