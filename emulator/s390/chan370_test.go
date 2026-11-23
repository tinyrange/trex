package s390

import (
	"bytes"
	"testing"
)

// testChannel370 returns a System/370 machine with a tape at 0x130 holding
// the given blocks, enabled for I/O interruptions in BC mode.
func testChannel370(t *testing.T, blocks ...string) (*Machine, *CPU, *Tape3420, *Subchannel) {
	t.Helper()
	m, c := newTest370(t, nil)
	tp := &Tape3420{}
	for _, b := range blocks {
		tp.blocks = append(tp.blocks, tapeBlock{data: []byte(b), n: len(b)})
	}
	if _, err := m.CSS.Attach(0x130, tp); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	return m, c, tp, m.CSS.bydev[0x130]
}

// ccw0 stores a format-0 CCW.
func ccw0(m *Machine, at uint32, cmd byte, addr uint32, flags byte, count uint16) {
	be.PutUint32(m.S.Mem[at:], uint32(cmd)<<24|addr)
	m.S.Mem[at+4] = flags
	m.S.Mem[at+5] = 0
	be.PutUint16(m.S.Mem[at+6:], count)
}

// ioInstr issues a channel instruction with CAW caw.
func ioInstr(c *CPU, op byte, dev uint16, caw uint32) byte {
	be.PutUint32(c.S.Mem[0x48:], caw)
	c.io370([]byte{op, 0}, uint32(dev))
	return c.PSW.CC
}

// advance runs the channel's timed transitions up to the next deadline.
func advance(m *Machine) bool {
	if m.CSS.next == 0 {
		return false
	}
	m.tod = m.CSS.next
	m.CSS.tick370()
	return true
}

// interrupt takes a pending I/O interruption and returns the stored CSW.
func interrupt(t *testing.T, c *CPU) uint64 {
	t.Helper()
	if !c.takeIO370() {
		t.Fatal("no I/O interruption pending")
	}
	c.loadPSW(0x00000000_00001000)
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	return be.Uint64(c.S.Mem[0x40:])
}

func TestS370TapeMotionIsImmediateWithDelayedDeviceEnd(t *testing.T) {
	m, c, tp, _ := testChannel370(t, "AAAA", "BBBB")
	ccw0(m, 0x1000, 0x37, 0x2000, ccwSLI, 80) // forward space block
	be.PutUint64(m.S.Mem[0x40:], 0x12345678_00000000)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 1 {
		t.Fatalf("SIO cc %d, want 1 (channel end in the initial status)", cc)
	}
	// Only the status portion of the CSW is stored.
	if csw := be.Uint64(m.S.Mem[0x40:]); csw>>32 != 0x12345678 || byte(csw>>24) != usCE {
		t.Fatalf("CSW %016X", csw)
	}
	if tp.pos != 1 {
		t.Fatalf("position %d", tp.pos)
	}
	// The drive works until device end: START I/O and TEST I/O see busy.
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 1 || m.S.Mem[0x44] != usBusy {
		t.Fatalf("busy SIO cc %d status %02X", cc, m.S.Mem[0x44])
	}
	if cc := ioInstr(c, 0x9d, 0x130, 0); cc != 1 || m.S.Mem[0x44] != usBusy {
		t.Fatalf("busy TIO cc %d status %02X", cc, m.S.Mem[0x44])
	}
	if c.takeIO370() {
		t.Fatal("interruption before device end")
	}
	if !advance(m) {
		t.Fatal("no device-end deadline")
	}
	// Device end alone, with zero key, address and count.
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("device-end CSW %016X", csw)
	}
	if cc := ioInstr(c, 0x9d, 0x130, 0); cc != 0 {
		t.Fatalf("TIO after device end: cc %d", cc)
	}
}

func TestS370TapeReadStoresDataAtChannelEnd(t *testing.T) {
	m, c, _, _ := testChannel370(t, "HELLO")
	ccw0(m, 0x1000, 0x02, 0x2000, 0, 5)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 0 {
		t.Fatalf("SIO cc %d", cc)
	}
	// The transfer is in progress: nothing is stored yet, and the
	// subchannel is working.
	if !bytes.Equal(m.S.Mem[0x2000:0x2005], make([]byte, 5)) {
		t.Fatal("data stored before channel end")
	}
	if cc := ioInstr(c, 0x9d, 0x130, 0); cc != 2 {
		t.Fatalf("TIO while working: cc %d", cc)
	}
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 2 {
		t.Fatalf("SIO while working: cc %d", cc)
	}
	advance(m)
	if string(m.S.Mem[0x2000:0x2005]) != "HELLO" {
		t.Fatalf("data %q", m.S.Mem[0x2000:0x2005])
	}
	// Status pending in the subchannel: START I/O is refused with cc 2.
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 2 {
		t.Fatalf("SIO with status pending: cc %d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001008_0C000000 {
		t.Fatalf("CSW %016X", csw)
	}
}

func Test9020ChannelChainsIntoMACHWithMaskedPCI(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const dev = 0x3f0
	const mach = machBase + 0x1000
	ccw0(m, 0x1100, 0x02, 0x2000, 0, 3)
	program := bytes.Clone(m.S.Mem[0x1100:0x1108])
	tape := &Tape2401{Tape3420: &Tape3420{blocks: []tapeBlock{
		{data: program, n: len(program)},
		{data: []byte("DDD"), n: 3},
	}}}
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0
	ccw0(m, 0x1000, 0x02, mach, ccwCC|ccwPCI, 8)
	ccw0(m, 0x1008, 0x08, mach, 0, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x50001000); cc != 0 {
		t.Fatalf("SIO with MACH target: cc %d", cc)
	}
	advance(m)
	if !m.CSS.tickPCI(false) || !advance(m) {
		t.Fatal("masked PCI stopped the channel program")
	}
	if got := string(m.S.Mem[0x2000:0x2003]); got != "DDD" {
		t.Fatalf("data from the MACH CCW: %q", got)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	if csw := interrupt(t, c); csw != 0x50C01008_0C800000 {
		t.Fatalf("merged completion CSW %016X", csw)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	clear(m.CSS.mach)
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if got := m.CSS.channelStorage(mach, 8); !bytes.Equal(got, program) {
		t.Fatalf("restored MACH CCW % X", got)
	}
	if got := m.CSS.channelStorage(machBase+0x1f000, 8); got != nil {
		t.Fatalf("reserved MACH storage is addressable: % X", got)
	}
}

func TestTape2401MotionStatusAndWriteLength(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x17, 0, 0, 1) // erase gap
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("erase gap: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("halt while control unit busy: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_24000000 {
		t.Fatalf("control-unit and device end: %016X", csw)
	}
	ccw0(m, 0x1010, 0x04, 0x2000, 0, 6)
	ioInstr(c, 0x9c, dev, 0x1010)
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001018_0C000000 {
		t.Fatalf("sense: %016X", csw)
	}
	if got := m.S.Mem[0x2000:0x2006]; !bytes.Equal(got, []byte{0, 0x40, 3, 0, 0, 0}) {
		t.Fatalf("sense after erase moves off load point: % X", got)
	}
	ccw0(m, 0x1010, 0x01, 0x2000, 0, 6)
	ioInstr(c, 0x9c, dev, 0x1010)
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001018_0C400000 {
		t.Fatalf("write ended under count control: %016X", csw)
	}
}

func TestTape2401SelectorHaltEndsChannelBeforeDevice(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 80)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
		t.Fatalf("write: cc=%d", cc)
	}
	// The buffered first byte precedes another 30 bytes after the gap.
	m.tod += 10500 * todMicro
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
		t.Fatalf("halt: cc=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_00000031 {
		t.Fatalf("selector termination: %016X", csw)
	}
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("test after halt: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_2C000000 {
		t.Fatalf("device termination: %016X", csw)
	}
	if len(tape.blocks) != 1 || tape.blocks[0].n != 31 {
		t.Fatalf("halted write did not leave a 31-byte record")
	}
}

func TestTape2401HaltBeforeFirstBytePreservesMedia(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{blocks: []tapeBlock{{data: []byte("OLD"), n: 3}, {mark: true}}}}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 80)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
		t.Fatalf("write: cc=%d", cc)
	}
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
		t.Fatalf("halt before first byte: cc=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_00000050 {
		t.Fatalf("selector termination: %016X", csw)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_0E000000 {
		t.Fatalf("device termination: %016X", csw)
	}
	if tape.pos != 0 || len(tape.blocks) != 2 || string(tape.blocks[0].data) != "OLD" || !tape.blocks[1].mark {
		t.Fatal("the canceled write changed the tape")
	}
	if out, _, _ := tape.Exec(0x04, nil, false); !bytes.Equal(out, []byte{2, 0x48, 3, 0, 0, 0}) {
		t.Fatalf("sense after canceled write: % X", out)
	}
}

func TestTape2401CheckpointKeepsPendingWrite(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 4)
	copy(m.S.Mem[0x2000:], "DATA")
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
		t.Fatalf("write: cc=%d", cc)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if !advance(m) || len(tape.blocks) != 1 || string(tape.blocks[0].data) != "DATA" {
		t.Fatal("restored write did not record its data")
	}
}

func TestS370CommandChainingWaitsForDeviceEnd(t *testing.T) {
	m, c, tp, x := testChannel370(t, "SKIP", "READ")
	ccw0(m, 0x1000, 0x37, 0x2000, ccwCC|ccwSLI, 1) // FSB, chained
	ccw0(m, 0x1008, 0x02, 0x2000, 0, 4)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 0 {
		t.Fatalf("SIO cc %d", cc)
	}
	if tp.pos != 1 || x.resumeAt == 0 {
		t.Fatalf("chain did not pause for device end: position %d", tp.pos)
	}
	advance(m) // device end of the FSB: the read starts
	if tp.pos != 2 || x.finishAt == 0 {
		t.Fatalf("read not started: position %d", tp.pos)
	}
	advance(m)
	if string(m.S.Mem[0x2000:0x2004]) != "READ" {
		t.Fatalf("data %q", m.S.Mem[0x2000:0x2004])
	}
	if csw := interrupt(t, c); csw != 0x00001010_0C000000 {
		t.Fatalf("CSW %016X", csw)
	}
}

func TestS370TimedOperationSurvivesCheckpoint(t *testing.T) {
	m, c, _, _ := testChannel370(t, "HELLO")
	ccw0(m, 0x1000, 0x02, 0x2000, 0, 5)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 0 {
		t.Fatalf("SIO cc %d", cc)
	}
	var b bytes.Buffer
	if err := m.Save(&b); err != nil {
		t.Fatal(err)
	}
	m2, c2, _, _ := testChannel370(t, "HELLO")
	if err := m2.Restore(&b, false); err != nil {
		t.Fatal(err)
	}
	c2.PSW.SysMask, c2.PSW.IO = 0xff, true
	if !advance(m2) || string(m2.S.Mem[0x2000:0x2005]) != "HELLO" {
		t.Fatalf("restored transfer did not complete: %q", m2.S.Mem[0x2000:0x2005])
	}
	if csw := interrupt(t, c2); csw != 0x00001008_0C000000 {
		t.Fatalf("CSW %016X", csw)
	}
	_ = c
}

func TestS370ChannelProgramErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(m *Machine)
		cc     byte
		status uint16 // unit and channel status from the CSW
		irq    bool
	}{
		// Errors in the first CCW are found before the device is selected:
		// START I/O stores the status portion with program check.
		{"tic_first", func(m *Machine) { ccw0(m, 0x1000, 0x08, 0x1100, 0, 0) }, 1, 0x0020, false},
		{"invalid_command", func(m *Machine) { ccw0(m, 0x1000, 0x10, 0x2000, 0, 1) }, 1, 0x0020, false},
		{"flag_bits_38_39", func(m *Machine) { ccw0(m, 0x1000, 0x02, 0x2000, 0x01, 1) }, 1, 0x0020, false},
		{"zero_count", func(m *Machine) { ccw0(m, 0x1000, 0x02, 0x2000, 0, 0) }, 1, 0x0020, false},
		// A TIC to a TIC when command chaining: the new operation is not
		// initiated and the interruption shows program check alone.
		{"tic_to_tic", func(m *Machine) {
			ccw0(m, 0x1000, 0x03, 0, ccwCC, 1)
			ccw0(m, 0x1008, 0x08, 0x1010, 0, 0)
			ccw0(m, 0x1010, 0x08, 0x1018, 0, 0)
		}, 0, 0x0020, true},
		// An invalid data address is found in the transfer: the device
		// presents its ending status with the program check.
		{"invalid_data_address", func(m *Machine) { ccw0(m, 0x1000, 0x02, 0x400000, 0, 4) }, 0, 0x0C20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c, _, _ := testChannel370(t, "DATA")
			tc.setup(m)
			cc := ioInstr(c, 0x9c, 0x130, 0x1000)
			if cc != tc.cc {
				t.Fatalf("SIO cc %d, want %d", cc, tc.cc)
			}
			status := be.Uint16(m.S.Mem[0x44:])
			if tc.irq {
				for advance(m) {
				}
				status = uint16(interrupt(t, c) >> 16)
			}
			if status != tc.status {
				t.Fatalf("status %04X, want %04X", status, tc.status)
			}
		})
	}
}

func TestS370ChannelStoreProtectionKeepsDeviceStatus(t *testing.T) {
	m, c, _, _ := testChannel370(t, "DATA")
	*m.S.key(0x2000) = 0x50 // key 5
	ccw0(m, 0x1000, 0x02, 0x2000, 0, 4)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1000|0x10000000); cc != 0 { // CAW key 1
		t.Fatalf("SIO cc %d", cc)
	}
	advance(m)
	if csw := interrupt(t, c); uint16(csw>>16) != 0x0C10 || !bytes.Equal(m.S.Mem[0x2000:0x2004], make([]byte, 4)) {
		t.Fatalf("CSW %016X data %X", csw, m.S.Mem[0x2000:0x2004])
	}
}

func TestPackOverlapIsByteAtATime(t *testing.T) {
	// PACK 0(2,12),1(3,12) with zoned F1 F2 C3 at 0x2001: the first result
	// byte (3C) overwrites the source byte later used for the high digit.
	m, c := newTest370(t, []byte{0xf2, 0x12, 0xc0, 0x00, 0xc0, 0x01})
	c.GR[12] = 0x2000
	copy(m.S.Mem[0x2000:], []byte{0x00, 0xf1, 0xf2, 0xc3})
	m.Run(1)
	if got := m.S.Mem[0x2000:0x2002]; !bytes.Equal(got, []byte{0xc2, 0x3c}) {
		t.Fatalf("PACK overlap %X, want C23C", got)
	}
}

func TestReader2540CommandSequence(t *testing.T) {
	u := &UnitRecord{Type: 0x2540}
	u.Load([]string{"ONE", "TWO", "THREE"})
	exec := func(cmd byte) byte { _, _, st := u.Exec(cmd, nil, false); return st }
	// A feed and select stacker may not be the first command after run-in.
	if st := exec(0x23); st != usUnitCheck || u.sense != senseCmdRej {
		t.Fatalf("first feed: status %02X sense %02X", st, u.sense)
	}
	u.sense = 0
	if exec(0xc2) != usCE|usDE { // read without feed
		t.Fatal("read without feed")
	}
	// A second read without feed: unit check, unusual command sequence.
	if st := exec(0xc2); st != usCE|usDE|usUnitCheck || u.sense != senseUnusual {
		t.Fatalf("second read without feed: status %02X sense %02X", st, u.sense)
	}
	u.sense = 0
	// Feed and select stacker follows a read without feed: channel end at
	// once, device end after the feed.
	if st := exec(0x23); st != usCE|usDE || u.chanT != 0 || u.devT == 0 {
		t.Fatalf("feed: status %02X timing %v %v", st, u.chanT, u.devT)
	}
	if out, _, st := u.Exec(0x02, nil, false); st != usCE|usDE || !bytes.HasPrefix(out, EncodeEBCDIC("TWO")) || u.devT == 0 {
		t.Fatalf("read feed: %q status %02X", EBCDICString(out), st)
	}
	exec(0x02)
	// End of file: unit exception alone, at initial selection, on the
	// read after the last card.
	if st := exec(0x02); st != usUnitExcept {
		t.Fatalf("end of file: status %02X", st)
	}
	if st := exec(0x0c); st != usUnitCheck { // read backward is invalid
		t.Fatalf("read backward: status %02X", st)
	}
}

func TestS360ReaderChannelEndAndPendingDeviceEnd(t *testing.T) {
	m, c := newTest360(t, true, nil)
	reader := &UnitRecord{Type: 0x2540}
	reader.Load([]string{"CARD"})
	const dev = 0x00c
	if err := m.CSS.AttachUnitRecord(dev, reader); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1000, 0x02, 0x2000, ccwSLI, 40)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("read: cc=%d", cc)
	}
	if delay := m.CSS.next - m.tod; delay != 410*todMicro {
		t.Fatalf("40-column transfer deadline is %d TOD units away", delay)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001008_08000000 {
		t.Fatalf("reader channel end: %016X", csw)
	}
	advance(m)
	if cc := ioInstr(c, 0x9f, dev, 0); cc != 1 {
		t.Fatalf("TCH with reader device end pending: cc=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("reader device end: %016X", csw)
	}
}

func TestS360ShortBlockDuringDataChainReportsIncorrectLength(t *testing.T) {
	m, c := newTest360(t, true, nil)
	reader := &UnitRecord{Type: 0x2540}
	reader.Load([]string{"CARD"})
	const dev = 0x00c
	if err := m.CSS.AttachUnitRecord(dev, reader); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1000, 0xc2, 0x2000, ccwCD|ccwSLI, 85)
	ccw0(m, 0x1008, 0, 0x2100, 0, 10)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("read: cc=%d", cc)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001008_0C400005 {
		t.Fatalf("short block in a data chain: %016X", csw)
	}
}

func TestPunch2540ReadyAndRawCard(t *testing.T) {
	m, c := newTest360(t, true, nil)
	punch := &UnitRecord{Type: 0x2541}
	const dev = 0x00d
	if err := m.CSS.AttachUnitRecord(dev, punch); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	punch.SetPunchReady(false)
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usUnitCheck {
		t.Fatalf("stopped: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	out, _, status := punch.Exec(0x04, nil, false)
	if status != usCE|usDE || !bytes.Equal(out, []byte{senseIntReq}) {
		t.Fatalf("stopped sense: %X, %02X", out, status)
	}
	punch.SetPunchReady(true)
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("start: %016X", csw)
	}
	if _, used, status := punch.Exec(0x41, []byte{0, 0xff}, false); used != 2 || status != usCE|usDE {
		t.Fatalf("punch: used=%d status=%02X", used, status)
	}
	want := append([]byte{0, 0xff}, bytes.Repeat([]byte{0x40}, 78)...)
	if len(punch.punched) != 1 || !bytes.Equal(punch.punched[0], want) {
		t.Fatalf("punch output % X", punch.punched)
	}
}

func TestPaired2821DiagnosticColumns(t *testing.T) {
	m, _ := newTest360(t, true, nil)
	reader := &UnitRecord{Type: 0x2540}
	punch := &UnitRecord{Type: 0x2541, cardPeer: reader}
	reader.cardPeer = punch
	reader.Load([]string{" AB", "SECOND"})
	if err := m.CSS.AttachUnitRecord(0x00c, reader); err != nil {
		t.Fatal(err)
	}
	if err := m.CSS.AttachUnitRecord(0x00d, punch); err != nil {
		t.Fatal(err)
	}
	// Column one receives row 12 and row 1, the punches for EBCDIC A.
	if _, used, status := punch.Exec(0x25, []byte{0x24, 0x00}, false); used != 2 || status != usCE|usDE {
		t.Fatalf("diagnostic write: %d bytes, status %02X", used, status)
	}
	out, _, status := reader.Exec(0xc2, nil, false)
	if status != usCE|usDE || !bytes.Equal(out[:3], EncodeEBCDIC("AAB")) {
		t.Fatalf("diagnostic read: % X, status %02X", out, status)
	}
	if _, _, status := reader.Exec(0x23, nil, false); status != usCE|usDE {
		t.Fatalf("stacker select: status %02X", status)
	}
	out, _, status = reader.Exec(0x02, nil, false)
	if status != usCE|usDE || !bytes.HasPrefix(out, EncodeEBCDIC("SECOND")) {
		t.Fatalf("read of next card: % X, status %02X", out, status)
	}
}

func Test2314NoOpAndHomeAddress(t *testing.T) {
	m, c := newTest360(t, true, nil)
	dev := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const addr = 0x340
	if _, err := m.CSS.Attach(addr, dev); err != nil {
		t.Fatal(err)
	}
	ccw0(m, 0x1000, 0x03, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, addr, 0x1000); cc != 1 || m.S.Mem[0x44] != usCE|usDE {
		t.Fatalf("2314 no-op: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if out, _, _ := dev.Exec(0x04, nil, false); !bytes.Equal(out, []byte{0, 0, 0, 0x40, 0, 0}) {
		t.Fatalf("2314 ready sense: % X", out)
	}
	ha := []byte{1, 0, 0, 0, 0}
	if _, _, status := dev.Exec(0x19, ha, false); status != usUnitCheck {
		t.Fatalf("write HA without format permission: status %02X", status)
	}
	dev.StartChain()
	dev.Exec(0x1f, []byte{0xc0}, true)
	if _, used, status := dev.Exec(0x19, ha, false); used != 5 || status != usCE|usDE {
		t.Fatalf("write HA with format permission: %d bytes, status %02X", used, status)
	}
	snap, err := dev.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	dev.home = nil
	if err := dev.restore(snap, false); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := dev.Exec(0x1a, nil, false); !bytes.Equal(out, ha) {
		t.Fatalf("read HA after restore: % X", out)
	}
}

func Test2314SearchAndFileMask(t *testing.T) {
	dev := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	dev.StartChain()
	if _, used, status := dev.Exec(0x31, []byte{0, 0, 0, 0}, true); used != 5 || status != usCE|usDE|usSM {
		t.Fatalf("short ID argument: used=%d status=%02X", used, status)
	}
	for _, key := range []string{"IPL1", "IPL2", "VOL1"} {
		if _, used, status := dev.Exec(0x29, EncodeEBCDIC(key), true); used != 4 || status != usCE|usDE|usSM {
			t.Fatalf("search for %s: used=%d status=%02X", key, used, status)
		}
	}
	dev.StartChain()
	if _, used, status := dev.Exec(0x1f, []byte{0x27}, false); used != 1 || status != usCE|usDE|usUnitCheck {
		t.Fatalf("invalid mask byte: used=%d status=%02X", used, status)
	}
	dev.StartChain()
	dev.Exec(0x1f, []byte{0x18}, true)
	if _, _, status := dev.Exec(0x1b, make([]byte, 6), false); status != usUnitCheck {
		t.Fatalf("seek head with seek inhibited: status %02X", status)
	}
	if sense, _, _ := dev.Exec(0x04, nil, false); sense[0] != 0 || sense[1] != senseFileProtect {
		t.Fatalf("seek rejection sense: % X", sense)
	}
	dev.EndChain()
	if _, _, status := dev.Exec(0x1b, make([]byte, 6), false); status != usCE|usDE {
		t.Fatalf("seek head on next selection: status %02X", status)
	}
}

func Test2314ControlUnitEndAfterFormatWrite(t *testing.T) {
	m, c := newTest360(t, true, nil)
	dev := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const addr = 0x340
	if _, err := m.CSS.Attach(addr, dev); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	m.S.Mem[0x2000] = 0xc0
	ccw0(m, 0x1000, 0x1f, 0x2000, ccwCC, 1)
	ccw0(m, 0x1008, 0x19, 0x2001, 0, 5)
	ccw0(m, 0x1010, 0x03, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, addr, 0x1000); cc != 0 {
		t.Fatalf("format write chain: cc=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001010_0C000000 {
		t.Fatalf("format write ending status: %016X", csw)
	}
	if cc := ioInstr(c, 0x9c, addr, 0x1010); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("SIO during erase: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if !advance(m) {
		t.Fatal("restore lost the erase deadline")
	}
	if csw := interrupt(t, c); csw != 0x00000000_20000000 {
		t.Fatalf("control-unit end: %016X", csw)
	}
	if cc := ioInstr(c, 0x9c, addr, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE|usDE {
		t.Fatalf("SIO after erase: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
}

func Test2314SelectorHalt(t *testing.T) {
	m, c := newTest360(t, true, nil)
	disk := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const dev = 0x340
	if _, err := m.CSS.Attach(dev, disk); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	disk.StartChain()
	disk.Exec(0x31, []byte{0, 0, 0, 0, 0}, true)
	record := append([]byte{0, 0, 0, 0, 1, 0, 0, 6}, "ABCDEF"...)
	if _, _, status := disk.Exec(0x1d, record, false); status != usCE|usDE {
		t.Fatalf("format: status %02X", status)
	}
	disk.Exec(0x07, make([]byte, 6), false)
	ccw0(m, 0x1000, 0x06, 0x2000, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("read SIO: cc %d", cc)
	}
	advance(m)
	if got := string(m.S.Mem[0x2000:0x2006]); got != "A\x00\x00\x00\x00\x00" {
		t.Fatalf("input after first byte: %q", got)
	}
	// The CPU may change a received byte without the channel storing it again.
	m.S.Mem[0x2000] = 'X'
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	advance(m)
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
		t.Fatalf("read HIO: cc %d", cc)
	}
	if got := string(m.S.Mem[0x2000:0x2006]); got != "XB\x00\x00\x00\x00" {
		t.Fatalf("input after halt: %q", got)
	}
	if csw := interrupt(t, c); csw != 0x00001008_00400004 {
		t.Fatalf("read halt CSW %016X", csw)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_0C000000 {
		t.Fatalf("read device status CSW %016X", csw)
	}

	disk.Exec(0x07, make([]byte, 6), false)
	m.S.Mem[0x2014] = 1
	copy(m.S.Mem[0x2020:], "GHIJKL")
	ccw0(m, 0x1000, 0x31, 0x2010, ccwCC, 5)
	ccw0(m, 0x1008, 0x08, 0x1000, 0, 1)
	ccw0(m, 0x1010, 0x05, 0x2020, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("write SIO: cc %d", cc)
	}
	checkRecord := func(want string) {
		t.Helper()
		records, err := disk.track(0)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(records[1].Data); got != want {
			t.Fatalf("disk record %q, want %q", got, want)
		}
	}
	checkRecord("ABCDEF")
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	m.tod += diskTransferTOD2314(3)
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
		t.Fatalf("write HIO: cc %d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_00400003 {
		t.Fatalf("write halt CSW %016X", csw)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_0C000000 {
		t.Fatalf("write device status CSW %016X", csw)
	}
	checkRecord("GHI\x00\x00\x00")
}

func Test2314ActuatorStopAndRecalibrate(t *testing.T) {
	m, c := newTest360(t, true, nil)
	disk := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const dev = 0x340
	if _, err := m.CSS.Attach(dev, disk); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	m.S.Mem[0x2003] = 0xff
	ccw0(m, 0x1000, 0x0b, 0x2000, 0, 6)
	ccw0(m, 0x1008, 0x13, 0, ccwSLI, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("seek SIO: cc %d", cc)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001008_08000000 {
		t.Fatalf("seek channel end: CSW %016X", csw)
	}
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usBusy {
		t.Fatalf("seek busy: cc %d status %02X", cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_06000000 {
		t.Fatalf("seek incomplete: CSW %016X", csw)
	}
	if sense, _, _ := disk.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0x01, 0, 0, 0x41, 0, 0}) {
		t.Fatalf("seek incomplete sense: % X", sense)
	}
	if cc := ioInstr(c, 0x9c, dev, 0x1008); cc != 0 {
		t.Fatalf("recalibrate SIO: cc %d", cc)
	}
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 2 {
		t.Fatalf("recalibrate before channel end: cc %d", cc)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001010_08000001 {
		t.Fatalf("recalibrate channel end: CSW %016X", csw)
	}
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usBusy {
		t.Fatalf("recalibrate busy: cc %d status %02X", cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("recalibrate device end: CSW %016X", csw)
	}
	if sense, _, _ := disk.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0, 0, 0, 0x40, 0, 0}) {
		t.Fatalf("sense after recovery: % X", sense)
	}
}

func Test2314OverflowAndFileProtection(t *testing.T) {
	dev := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const cyl = 1
	seek := func(head byte) {
		t.Helper()
		dev.StartChain()
		if _, _, status := dev.Exec(0x07, []byte{0, 0, 0, cyl, 0, head}, true); status != usCE|usDE {
			t.Fatalf("seek head %d: %02X", head, status)
		}
	}
	for head, part := range []struct {
		command byte
		data    string
	}{{0x01, "ABC"}, {0x1d, "DEF"}} {
		seek(byte(head))
		dev.Exec(0x31, []byte{0, cyl, 0, byte(head), 0}, true)
		record := append([]byte{0, cyl, 0, byte(head), 1, 0, 0, 3}, part.data...)
		if _, _, status := dev.Exec(part.command, record, false); status != usCE|usDE {
			t.Fatalf("format head %d: %02X", head, status)
		}
	}
	checkpoint, err := dev.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	dev.overflow = nil
	if err := dev.restore(checkpoint, false); err != nil {
		t.Fatal(err)
	}
	seek(0)
	if out, _, status := dev.Exec(0x06, nil, false); status != usCE|usDE || string(out) != "ABCDEF" {
		t.Fatalf("read both segments: %q, status %02X", out, status)
	}
	seek(0)
	dev.Exec(0x1f, []byte{0x18}, true)
	if out, _, status := dev.Exec(0x06, nil, false); status != usCE|usDE|usUnitCheck || string(out) != "ABC" {
		t.Fatalf("read with head switching inhibited: %q, status %02X", out, status)
	}
	if sense, _, _ := dev.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{0, 0x05, 0, 0x40, 0, 6}) {
		t.Fatalf("overflow incomplete sense: % X", sense)
	}
}

func Test2314SpaceCountRecoveryDataCheck(t *testing.T) {
	dev := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	dev.SetDeviceNumber(0x340)
	dev.StartChain()
	dev.Exec(0x31, []byte{0, 0, 0, 0, 0}, true)
	record := []byte{0, 0, 0, 0, 1, 2, 0, 5, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22}
	if _, _, status := dev.Exec(0x1d, record, false); status != usCE|usDE {
		t.Fatalf("format record: %02X", status)
	}
	dev.StartChain()
	dev.Exec(0x16, nil, true)
	dev.Exec(0x0f, []byte{2, 0, 13}, true)
	out, _, status := dev.Exec(0x0e, nil, false)
	want := append(append([]byte{}, record[8:]...), 0xff, 0xdd, 0x40, 0xeb, 0xff, 0xff, 0xff, 0xff)
	if status != usCE|usDE|usUnitCheck || !bytes.Equal(out, want) {
		t.Fatalf("read past the data field: % X, status %02X", out, status)
	}
	if sense, _, _ := dev.Exec(0x04, nil, false); sense[0] != senseDataCheck {
		t.Fatalf("recovery data-check sense: % X", sense)
	}
}

func TestPrinter1403Commands(t *testing.T) {
	u := &UnitRecord{Type: 0x1403}
	for _, tc := range []struct {
		cmd    byte
		status byte
	}{
		{0x09, usCE | usDE}, // write, space 1
		{0x89, usCE | usDE}, // write, skip to channel 1
		{0x0b, usCE | usDE}, // space 1 immediately
		{0xe3, usCE | usDE}, // skip to channel 12 immediately
		{0x37, usUnitCheck}, // invalid
		{0xf1, usUnitCheck}, // skip to channel 14: invalid
		{0x0c, usUnitCheck},
	} {
		if _, _, st := u.Exec(tc.cmd, []byte("LINE"), false); st != tc.status {
			t.Errorf("command %02X: status %02X, want %02X", tc.cmd, st, tc.status)
		}
	}
	// Diagnostic write and read of the print buffer.
	u.Exec(0x05, []byte("LOOP"), false)
	if out, _, _ := u.Exec(0x02, nil, false); len(out) != printBuffer || string(out[:4]) != "LOOP" {
		t.Fatalf("diagnostic read %q", out)
	}
	if len(u.Output) != 2 {
		t.Fatalf("printed %q", u.Output)
	}
}
