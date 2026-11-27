package r3000

import (
	"bytes"
	"encoding/binary"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestR4400DoublewordLoadAndBranchDelay(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c := &m.cpu
	c.pc, c.next = mipsWord(0x88000000), mipsWord(0x88000004)
	c.gpr[3] = mipsWord(0x88000100)
	words := []uint32{
		0xdc610000, // ld $1, 0($3)
		0x64220001, // daddiu $2, $1, 1
		0x50220001, // beql $1, $2, 1 (not taken)
		0x0000000d, // annulled break
		0x10000001, // b 1
		0x64420001, // daddiu $2, $2, 1 (delay slot)
	}
	for i, word := range words {
		binary.BigEndian.PutUint32(m.ram[i*4:], word)
	}
	binary.BigEndian.PutUint64(m.ram[0x100:], 0x12345678ffffffff)
	for range 5 {
		if stop := c.step(m); stop.exception >= 0 {
			t.Fatalf("unexpected fault at %#x: %d", stop.pc, stop.exception)
		}
	}
	if c.gpr[2] != 0x1234567900000001 || c.pc != mipsWord(0x88000018) {
		t.Fatalf("value=%#x pc=%#x", c.gpr[2], c.pc)
	}
}

func TestR4400PairedLargeTLBPages(t *testing.T) {
	c := newR4400()
	c.cp0[status], c.cp0[10] = 0, 29
	c.tlb[0] = r4kTLB{
		hi: 0x40000 | 29, mask: 0x6000,
		even: (0x08008000 >> 6) | 6, odd: (0x08018000 >> 6) | 2,
	}
	for _, tt := range []struct {
		address, want uint64
		store         bool
		exception     int
	}{
		{0x410aa, 0x080090aa, true, -1},
		{0x470bb, 0x0801b0bb, false, -1},
		{0x470bb, 0, true, 1},
		{0x48000, 0, false, 2},
	} {
		x := r4kInstruction{code: -1}
		if got := c.translate(tt.address, tt.store, &x); got != tt.want || x.code != tt.exception {
			t.Errorf("address %#x translated to %#x with exception %d", tt.address, got, x.code)
		}
	}
}

func TestIP24RTCFreezesCurrentTimeWhenTransferDisabled(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.cycles = 5 * ip24Clock
	m.rtcAccess(11, 0, true)
	m.cycles += 60 * ip24Clock
	for register, want := range map[uint64]byte{1: 0x05, 2: 0, 8: 1, 9: 0x11, 10: 0x03} {
		if got := m.rtcAccess(register, 0, false); got != want {
			t.Errorf("RTC register %d = %#x, want %#x", register, got, want)
		}
	}
}

func TestIP24WD33C93LatchesInitiatorIDOnReset(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	disk, err := blockstar.NewFileBlockDevice(&starfile.Bytes{Data: make([]byte, 4096)}, blockstar.FileBlockDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AttachDisk(2, disk); err != nil {
		t.Fatal(err)
	}
	write := func(reg, value byte) {
		m.scsi.port(m, false, reg, true)
		m.scsi.port(m, true, value, true)
	}
	read := func(reg byte) byte {
		m.scsi.port(m, false, reg, true)
		return byte(m.scsi.port(m, true, 0, false))
	}

	write(0, 0x0f) // Own ID 7, advanced features enabled.
	write(wdCommand, 0)
	read(wdStatus)
	write(0, 10) // READ CAPACITY is a ten-byte CDB.
	write(3, 0x25)
	write(20, 8)
	write(21, 0x42)
	write(wdCommand, 8)
	var capacity [8]byte
	for i := range capacity {
		capacity[i] = read(wdData)
	}
	if got := read(wdStatus); got != 0x16 || binary.BigEndian.Uint32(capacity[:4]) != 7 || binary.BigEndian.Uint32(capacity[4:]) != 512 {
		t.Fatalf("target 2 READ CAPACITY returned %x with controller status %#x", capacity, got)
	}

	write(0, 0x0a) // Reconfigure the controller to arbitrate as ID 2.
	write(wdCommand, 0)
	read(wdStatus)
	write(0, 6)
	write(21, 2)
	write(wdCommand, 7)
	if got := read(wdStatus); got != 0x42 {
		t.Fatalf("selection of the latched initiator ID returned %#x, want timeout", got)
	}
}

func TestIP24WD33C93WriteDataPhaseThroughHPC3(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	base, err := blockstar.NewFileBlockDevice(&starfile.Bytes{Data: make([]byte, 4096)}, blockstar.FileBlockDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	disk, err := blockstar.NewOverlayDevice(base, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AttachDisk(1, disk); err != nil {
		t.Fatal(err)
	}
	write := func(reg, val byte) {
		m.scsi.port(m, false, reg, true)
		m.scsi.port(m, true, val, true)
	}
	readStatus := func() uint32 {
		m.scsi.port(m, false, wdStatus, true)
		return m.scsi.port(m, true, 0, false)
	}
	write(0, 7)
	write(21, 1)
	write(wdCommand, 7)
	if first, second := readStatus(), readStatus(); first != 0x11 || second != 0x8a {
		t.Fatalf("selection status %#x, %#x", first, second)
	}
	write(20, 10)
	write(wdCommand, 0x20)
	for _, b := range []byte{0x2a, 0, 0, 0, 0, 2, 0, 0, 1, 0} {
		write(wdData, b)
	}
	if got := readStatus(); got != 0x18 {
		t.Fatalf("expected data-out phase, got %#x", got)
	}
	data := bytes.Repeat([]byte{0x39, 0xa5}, 256)
	copy(m.ram[0x2000:], data)
	for i, word := range []uint32{ip24RAMBase + 0x2000, hpc3EOX | 512, 0} {
		binary.BigEndian.PutUint32(m.ram[0x1000+i*4:], word)
	}
	m.hpcSCSI(4, ip24RAMBase+0x1000, true)
	m.hpcSCSI(0x1004, hpc3Active|hpc3ToDevice, true)
	write(19, 2)
	write(20, 0)
	write(wdCommand, 0x20)
	var dest [512]byte
	if _, err := disk.ReadAt(dest[:], 1024); err != nil || !bytes.Equal(dest[:], data) {
		t.Fatalf("disk write did not commit, read error: %v", err)
	}
	if got := readStatus(); got != 0x1b || m.scsi.scsiStatus != 0 || m.dma.control&hpc3Active != 0 {
		t.Fatalf("write phase status %#x, SCSI status %#x, DMA %#x", got, m.scsi.scsiStatus, m.dma.control)
	}

	// A larger guest write can exhaust the WD transfer count before the
	// target has received the full CDB payload.
	write(wdCommand, 4)
	copy(m.ram[0x2200:], data)
	write(3, 0x2a)
	write(10, 0)
	write(11, 2)
	startBurst := func(buffer uint32) {
		binary.BigEndian.PutUint32(m.ram[0x1000:], buffer)
		m.hpcSCSI(4, ip24RAMBase+0x1000, true)
		m.hpcSCSI(0x1004, hpc3Active|hpc3ToDevice, true)
		write(19, 2)
		write(20, 0)
		write(wdCommand, 8)
	}
	startBurst(ip24RAMBase + 0x2000)
	if got := readStatus(); got != 0x48 || m.scsi.reg[16] != 0x46 {
		t.Fatalf("short combined transfer status %#x, phase %#x", got, m.scsi.reg[16])
	}
	if _, err := disk.ReadAt(dest[:], 0); err != nil || !bytes.Equal(dest[:], make([]byte, 512)) {
		t.Fatalf("short transfer changed the disk, read error: %v", err)
	}
	startBurst(ip24RAMBase + 0x2200)
	if got := readStatus(); got != 0x16 || m.scsi.scsiStatus != 0 {
		t.Fatalf("resumed transfer status %#x, SCSI status %#x", got, m.scsi.scsiStatus)
	}
	for offset := int64(0); offset < 1024; offset += 512 {
		if _, err := disk.ReadAt(dest[:], offset); err != nil || !bytes.Equal(dest[:], data) {
			t.Fatalf("resumed disk write at %d, read error: %v", offset, err)
		}
	}
}

func TestR4400UnalignedWordLoadsMergeLowRegisterBytes(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c := &m.cpu
	c.pc, c.next = mipsWord(0x88000000), mipsWord(0x88000004)
	c.gpr[3] = mipsWord(0x88000101)
	copy(m.ram[0x100:], []byte{0x11, 0xa2, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint32(m.ram, 0x88620000)     // lwl $2, 0($3)
	binary.BigEndian.PutUint32(m.ram[4:], 0x98620003) // lwr $2, 3($3)
	for range 2 {
		if stop := c.step(m); stop.exception >= 0 {
			t.Fatalf("unexpected fault at %#x: %d", stop.pc, stop.exception)
		}
	}
	if want := mipsWord(0xa2334455); c.gpr[2] != want {
		t.Fatalf("unaligned word = %#x, want %#x", c.gpr[2], want)
	}
}

func TestIP24TTYD1InterruptIsVisibleFromSCCChannelA(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	a, b := uint64(ip24IOC+0x3b), uint64(ip24IOC+0x33)
	m.write64(b, 1, 1)
	m.write64(b, 1, 2) // Enable channel B transmit interrupts.
	m.write64(a, 1, 3)
	if bits, ok := m.read64(a, 1); !ok || bits != 2 {
		t.Fatalf("SCC RR3 = %#x, mapped=%t", bits, ok)
	}
	m.write64(b, 1, 0x28) // Reset the channel B pending transmit interrupt.
	m.write64(a, 1, 3)
	if bits, ok := m.read64(a, 1); !ok || bits != 0 {
		t.Fatalf("SCC RR3 after acknowledge = %#x, mapped=%t", bits, ok)
	}
}

func TestIP24HPC3EthernetDescriptorPointers(t *testing.T) {
	m, err := NewIP24(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	addresses := []uint64{ip24HPC + 0x14004, ip24HPC + 0x16004, ip24HPC + 0x18000, ip24HPC + 0x1a000, ip24HPC + 0x1a004}
	for i, address := range addresses {
		value := uint64(ip24RAMBase + 16*i)
		if !m.write64(address, 4, value) {
			t.Fatalf("unmapped Ethernet descriptor register %#x", address)
		}
	}
	for i, address := range addresses {
		want := uint64(ip24RAMBase + 16*i)
		if got, mapped := m.read64(address, 4); !mapped || got != want {
			t.Errorf("Ethernet descriptor register %#x = %#x, want %#x", address, got, want)
		}
	}
}
