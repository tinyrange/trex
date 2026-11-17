package s390

import (
	"encoding/binary"
	"testing"
)

func TestP390ChannelInstructionWaitsForOriginalHostReply(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	p.Aperture[p390Subchannels+5] = 0x83 // installed, valid and enabled by host/MSCH
	// L r1,940; SSCH 950; IPM r2; SRL r2,28; ST r2,900; LPSW 920.
	program := []byte{0x58, 0x10, 9, 0x40, 0xb2, 0x33, 9, 0x50, 0xb2, 0x22, 0, 0x20, 0x88, 0x20, 0, 0x1c, 0x50, 0x20, 9, 0, 0x82, 0, 9, 0x20}
	if err = p.Machine.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: program}, {Address: 0x940, Data: []byte{0, 1, 0, 0}}, {Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}, false); err != nil {
		t.Fatal(err)
	}
	p.Advance(100)
	c := p.Machine.CPUs[0]
	if !p.IOPending || p.RunReason.Kind != "host-io" || c.Instructions != 2 || !p.InterruptPending || binary.BigEndian.Uint16(p.Aperture[p390Combuf+0x12:]) != 0xb233 || binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x14:]) != 0x950 {
		t.Fatalf("instruction was not handed to host: %v, %d", p.RunReason, c.Instructions)
	}
	p.Advance(100)
	if c.Instructions != 2 {
		t.Fatal("CPU ran past an uncompleted host instruction")
	}
	p.AcknowledgeInterrupt()
	if err = p.WriteAperture(p390Combuf+0x10, []byte{0xf3}); err != nil {
		t.Fatal(err)
	}
	p.Advance(100)
	if !p.IOPending || c.Instructions != 2 {
		t.Fatal("reply applied before host completion strobe")
	}
	if err = p.WriteAperture(0x101, []byte{4}); err != nil {
		t.Fatal(err)
	}
	p.Advance(100)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 3 || p.IOCompletions != 1 || p.IOPending || p.RunReason.Kind != "disabled-wait" {
		t.Fatalf("host condition code not used: %v", p.RunReason)
	}
}

func TestP390CatalogRejectsMissingAndDisabledSubchannels(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.GR[1] = 0x10000
	c.PSW.CC = 0
	p.startSubchannel(c, 0x900, 0)
	if c.PSW.CC != 3 || p.IORequests != 0 || p.InterruptPending {
		t.Fatal("missing device was handed to host")
	}
	s := p.Aperture[p390Subchannels : p390Subchannels+64]
	s[5] = 3
	p.startSubchannel(c, 0x900, 0)
	if c.PSW.CC != 3 || p.IORequests != 0 {
		t.Fatal("disabled device was started")
	}
	s[5] = 0x83
	c.GR[1] = 0x10200
	p.startSubchannel(c, 0x900, 0)
	if c.PSW.CC != 3 || p.IORequests != 0 {
		t.Fatal("subchannel number wrapped onto private mailbox")
	}
}

func TestP390HostCompletionTakesArchitecturalInterruptAndTSCH(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	// Waiting CPU has I/O enabled. Its actual interruption handler stores the
	// subchannel's IRB and a result, then enters a disabled wait.
	handler := []byte{0xb2, 0x35, 0x0a, 0x00, 0xa7, 0x28, 0, 17, 0x50, 0x20, 9, 0, 0x82, 0, 9, 0x30}
	err = p.Machine.Load([]Image{
		{Address: 0, Data: []byte{2, 0x0a, 0, 0, 0, 0, 0, 0}},
		{Address: 0x78, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x81, 0}},
		{Address: 0x8100, Data: handler},
		{Address: 0x930, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.GR[1] = 0x10000
	c.CR[6] = 0x80000000
	s := p.Aperture[p390Subchannels : p390Subchannels+64]
	s[5] = 0x83
	binary.BigEndian.PutUint32(s, 0x12345678)
	packet := []byte{0, 1, 0, 0, 0, 0, 0, 7, 0, 0, 9, 0xb0, 0x0c, 0, 0, 0}
	if err = p.WriteAperture(p390Combuf+0x20, packet); err != nil {
		t.Fatal(err)
	}
	p.Advance(30)
	if p.IOStatusReports != 0 || c.Instructions != 0 {
		t.Fatal("unpublished status woke CPU")
	}
	if err = p.WriteAperture(0x101, []byte{4}); err != nil {
		t.Fatal(err)
	}
	// CR6 masking must retain the pending status and not manufacture acceptance.
	c.CR[6] = 0
	p.Advance(30)
	if p.Machine.Interrupts["io"] != 0 {
		t.Fatal("masked I/O interrupt accepted")
	}
	c.CR[6] = 0x80000000
	p.Advance(30)
	if p.Machine.Interrupts["io"] != 1 || binary.BigEndian.Uint32(p.Machine.S.Mem[0xb8:]) != 0x10000 || binary.BigEndian.Uint32(p.Machine.S.Mem[0xbc:]) != 0x12345678 || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 17 {
		t.Fatal("host completion did not take architectural I/O interruption")
	}
	if got := p.Machine.S.Mem[0xa00:0xa0c]; string(got) != string(packet[4:]) {
		t.Fatalf("IRB=%x, want %x", got, packet[4:])
	}
	if p.interrupts[0].pending || p.Aperture[p390Combuf+0x20] != 0xff || p.RunReason.Kind != "disabled-wait" || p.InterruptPending {
		t.Fatal("completion/TSCH did not release status or fabricated stop IRQ")
	}
	p.testSubchannel(c, 0xa40, 0)
	if c.PSW.CC != 1 {
		t.Fatal("TSCH consumed final status twice")
	}
}

func TestP390WindowLatchReadsPageAddressWithoutOperandOffset(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Machine.S.Mem[0x9a0] = 0x5a
	if err = p.WriteAperture(0x220, []byte{0xa0, 9, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var descriptor [4]byte
	if err = p.ReadAperture(0x220, descriptor[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(descriptor[:]) != 0 {
		t.Fatal("AWSCHAN's descriptor latch poll cannot finish")
	}
	var value [1]byte
	if err = p.ReadAperture(0x409a0, value[:]); err != nil || value[0] != 0x5a {
		t.Fatal("latched page plus consumer offset does not address actual storage")
	}
}
