package s390

import (
	"bytes"
	"testing"
	"time"
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

func finishTransfer(t *testing.T, m *Machine, dev uint16) {
	t.Helper()
	x := m.CSS.byDevice(dev)
	for x.op != nil {
		if m.CSS.next <= m.tod || !advance(m) {
			t.Fatalf("device %04X transfer has no future deadline", dev)
		}
	}
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

func TestByteMuxSubchannelLayout(t *testing.T) {
	m := NewMachine(Config{S370: true, Memory: 128 << 10, ByteMuxSubchannels: 32})
	c := m.CPUs[0]
	if cc := ioInstr(c, 0x9f, 0, 0); cc != 0 {
		t.Fatalf("TCH of empty configured multiplexor: cc=%d", cc)
	}
	for _, address := range []uint16{0x01f, 0x082, 0x083, 0x120} {
		if err := m.CSS.AttachConsole1052(address, NewConsole1052()); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []uint16{0x000, 0x020, 0x07f} {
		if err := m.CSS.AttachConsole1052(address, NewConsole1052()); err == nil {
			t.Fatalf("attached console at unavailable address %03X", address)
		}
	}
	if err := m.CSS.AttachConsole1052(0x001, NewConsole1052()); err != nil {
		t.Fatal(err)
	}
	if err := m.CSS.AttachConsole1052(0x090, NewConsole1052()); err == nil {
		t.Fatal("attached shared control unit over an individual subchannel")
	}
	if cc := ioInstr(c, 0x9d, 0x020, 0); cc != 3 {
		t.Fatalf("TIO at address 020: cc=%d", cc)
	}
	ccw0(m, 0x1000, 0x0a, 0x2000, ccwSLI, 16) // 1052 keyboard read
	if cc := ioInstr(c, 0x9c, 0x082, 0x1000); cc != 0 || !m.CSS.bydev[0x082].working() {
		t.Fatalf("SIO to start the shared read: cc=%d", cc)
	}
	for _, op := range []byte{0x9c, 0x9d} {
		if cc := ioInstr(c, op, 0x083, 0x1000); cc != 2 {
			t.Fatalf("opcode %02X at sibling while read is active: cc=%d", op, cc)
		}
	}
	if cc := ioInstr(c, 0x9d, 0x01f, 0); cc != 0 {
		t.Fatalf("TIO at unrelated subchannel while read is active: cc=%d", cc)
	}
	owner := m.CSS.bydev[0x082]
	console := owner.dev.(*Console1052)
	console.Type("A")
	for owner.working() && advance(m) {
	}
	if !owner.pending {
		t.Fatal("read completion was not pending")
	}
	if cc := ioInstr(c, 0x9d, 0x083, 0); cc != 2 || !owner.pending {
		t.Fatalf("TIO at sibling while read completion is pending: cc=%d", cc)
	}
	if cc := ioInstr(c, 0x9d, 0x082, 0); cc != 1 || owner.pending {
		t.Fatalf("TIO at owner with read completion pending: cc=%d", cc)
	}
	if cc := ioInstr(c, 0x9d, 0x083, 0); cc != 0 {
		t.Fatalf("TIO at sibling after read completion accepted: cc=%d", cc)
	}
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

func TestTapeDeviceEndTimingAcrossRunSlices(t *testing.T) {
	for _, slice := range []uint64{4096, 4093} {
		m, c := newTest360(t, false, []byte{0x47, 0xf0, 0x10, 0x00}) // BC 15,0(R1)
		c.GR[1] = 0x1000
		tape := &Tape2401{Tape3420: &Tape3420{}}
		tape.writeRecord([]byte{0})
		tape.pos = 0
		const dev = 0x130
		if _, err := m.CSS.Attach(dev, tape); err != nil {
			t.Fatal(err)
		}
		ccw0(m, 0x1010, 0x37, 0, 0, 1)
		if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
			t.Fatalf("space block: cc=%d status=%02X", cc, m.S.Mem[0x44])
		}
		deadline := m.CSS.bydev[dev].deAt
		expected := m.tod + (deadline-m.tod+m.todStep-1)/m.todStep*m.todStep
		m.TraceIO = true
		for !m.CSS.bydev[dev].pending && m.tod < expected+slice*m.todStep {
			m.Run(slice)
		}
		var deviceEnd uint64
		for _, event := range m.Events {
			if event.Detail == "device end 0130 -> dev 04" {
				deviceEnd = event.TOD
				break
			}
		}
		if deviceEnd != expected {
			t.Fatalf("slice %d: Device End at %X, expected %X", slice, deviceEnd, expected)
		}
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

func Test9020StoppedSEInitialCCW(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const devno = 0x130
	tape := &Tape2401{Tape3420: &Tape3420{blocks: []tapeBlock{{data: []byte("ABC"), n: 3}}}}
	if _, err := m.CSS.Attach(devno, tape); err != nil {
		t.Fatal(err)
	}
	m.CSS.ioceATR[0] = channelATR9020{Mask: 0x2100000000, Active: true}
	ccw0(m, bytesPer9020SE+0x2000, 0x02, bytesPer9020SE+0x3000, 0, 3)
	const priorCSW = 0x5000fed8_7f80007b
	be.PutUint64(m.S.Mem[0x40:], priorCSW)
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if cc := ioInstr(c, 0x9c, devno, 0x2000); cc != 0 || !m.CSS.bydev[devno].working() {
		t.Fatalf("running SE2 did not accept the mapped CCW: CC=%d", cc)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	cc := ioInstr(c, 0x9c, devno, 0x2000)
	csw := be.Uint64(m.S.Mem[0x40:])
	if cc != 1 || csw != 0x5000fed8_0021007b || tape.pos != 0 || m.CSS.bydev[devno].working() {
		t.Fatalf("mapped CCW in stopped SE2: CC=%d CSW=%016X tape position=%d", cc, csw, tape.pos)
	}
}

func Test9020StoppedSEDataChainedCCW(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const devno = 0x130
	tape := &Tape2401{Tape3420: &Tape3420{blocks: []tapeBlock{{data: []byte("ABCDEF"), n: 6}}}}
	if _, err := m.CSS.Attach(devno, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	ccw0(m, bytesPer9020SE-8, 0x02, 0x2000, ccwCD|ccwSLI, 3)
	ccw0(m, bytesPer9020SE, 0x02, 0x2003, ccwSLI, 3)
	if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	if cc := ioInstr(c, 0x9c, devno, bytesPer9020SE-8); cc != 0 {
		t.Fatalf("first, accessible CCW did not start: CC=%d", cc)
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if !advance(m) || m.CSS.bydev[devno].pending || string(m.S.Mem[0x2000:0x2006]) != "ABC\x00\x00\x00" {
		t.Fatal("the selector did not store the first buffer before fetching the stopped-SE CCW")
	}
	if !advance(m) {
		t.Fatal("tape transfer never completed")
	}
	if csw := interrupt(t, c); csw != 0x00080008_0c210000 || string(m.S.Mem[0x2000:0x2006]) != "ABC\x00\x00\x00" {
		t.Fatalf("data chain into stopped SE2: CSW=%016X input=%q", csw, m.S.Mem[0x2000:0x2006])
	}
}

func Test9020StoppedSEPartialRead(t *testing.T) {
	const boundary = 2 * bytesPer9020SE
	for _, tc := range []struct {
		name    string
		command byte
		at      uint32
		pos     int
		stopped int
		want    string
	}{
		{"forward", 0x02, boundary - 3, 0, 3, "ABCxxx"},
		{"backward", 0x0c, boundary + 2, 1, 2, "xxxDEF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMachine(Config{Model9020: true, Memory: 3 * bytesPer9020SE, NoIntervalTimer: true})
			c := m.CPUs[0]
			c.loadPSW(0xff000000_00001000)
			const devno = 0x130
			tape := &Tape3420{pos: tc.pos, blocks: []tapeBlock{{data: []byte("ABCDEF"), n: 6}}}
			if _, err := m.CSS.Attach(devno, tape); err != nil {
				t.Fatal(err)
			}
			memory := m.S.Mem[boundary-3 : boundary+3]
			copy(memory, "xxxxxx")
			ccw0(m, 0x2000, tc.command, tc.at, 0, 6)
			if cc := ioInstr(c, 0x9c, devno, 0x2000); cc != 0 || string(memory) != "xxxxxx" {
				t.Fatalf("tape read did not start asynchronously: CC=%d storage=%q", cc, memory)
			}
			if err := m.ReplayStorageLogout9020(tc.stopped, make([]byte, seLogoutSize9020)); err != nil {
				t.Fatal(err)
			}
			if !advance(m) {
				t.Fatal("tape transfer never completed")
			}
			if csw := interrupt(t, c); csw != 0x00002008_0c210003 || string(memory) != tc.want {
				t.Fatalf("tape read into stopped SE: CSW=%016X storage=%q", csw, memory)
			}
		})
	}
}

func Test9020StoppedSEWrite(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr uint32
		data string
		csw  uint64
	}{
		{"first-byte", bytesPer9020SE, "", 0x00002008_00210006},
		{"after-prefix", bytesPer9020SE - 3, "ABC", 0x00002008_0c210003},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newTest360(t, true, nil)
			const devno = 0x130
			tape := &Tape2401{Tape3420: &Tape3420{}}
			if _, err := m.CSS.Attach(devno, tape); err != nil {
				t.Fatal(err)
			}
			c.PSW.SysMask, c.PSW.IO = 0xff, true
			copy(m.S.Mem[tc.addr:], "ABCDEF")
			ccw0(m, 0x2000, 0x01, tc.addr, 0, 6)
			if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
				t.Fatal(err)
			}
			if cc := ioInstr(c, 0x9c, devno, 0x2000); cc != 0 {
				t.Fatalf("write did not reach the data cycle: CC=%d", cc)
			}
			finishTransfer(t, m, devno)
			if csw := interrupt(t, c); csw != tc.csw {
				t.Fatalf("write from stopped SE: CSW=%016X want %016X", csw, tc.csw)
			}
			if tc.data == "" {
				if tape.pos != 0 || len(tape.blocks) != 0 {
					t.Fatal("a write with no available bytes must leave the reel unchanged")
				}
			} else if len(tape.blocks) != 1 || string(tape.blocks[0].data) != tc.data {
				t.Fatalf("write did not record the available prefix %q", tc.data)
			}
		})
	}
}

func Test9020StopSEDuringTapeWrite(t *testing.T) {
	for _, recover := range []bool{false, true} {
		m, c := newTest360(t, true, nil)
		const dev = 0x130
		tape := &Tape2401{Tape3420: &Tape3420{}}
		if _, err := m.CSS.Attach(dev, tape); err != nil {
			t.Fatal(err)
		}
		c.PSW.SysMask, c.PSW.IO = 0xff, true
		data := bytes.Repeat([]byte{'A'}, 1024)
		copy(m.S.Mem[bytesPer9020SE:], data)
		ccw0(m, 0x2000, 0x01, bytesPer9020SE, ccwSLI, uint16(len(data)))
		if cc := ioInstr(c, 0x9c, dev, 0x2000); cc != 0 || len(tape.blocks) != 0 {
			t.Fatalf("tape write did not start asynchronously: CC=%d", cc)
		}
		m.tod += todMicro
		if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
			t.Fatal(err)
		}
		x := m.CSS.byDevice(dev)
		faultAt := m.CSS.next
		if faultAt <= m.tod || faultAt >= x.finishAt {
			t.Fatal("channel did not schedule the next byte request after LOS")
		}
		var checkpoint bytes.Buffer
		if err := m.Save(&checkpoint); err != nil {
			t.Fatal(err)
		}
		if err := m.Restore(&checkpoint, false); err != nil {
			t.Fatal(err)
		}
		if m.CSS.next != faultAt {
			t.Fatal("restoring the in-flight write lost the original stop time")
		}
		wantCSW := uint64(0x00002008_0c2103ff)
		wantData := data[:1]
		if recover {
			// Release the SE one tick before the next output fetch.
			m.tod = faultAt - 1
			c.logoutStorage9020(0x280, 0, 2)
			if c.PSW.CC != 0 || m.CSS.next != faultAt {
				t.Fatal("FD0 did not release storage ahead of the next byte request")
			}
			wantCSW, wantData = 0x00002008_0c000000, data
		}
		finishTransfer(t, m, dev)
		if csw := interrupt(t, c); csw != wantCSW || len(tape.blocks) != 1 || !bytes.Equal(tape.blocks[0].data, wantData) {
			t.Fatalf("tape write after LOS, recovery %t: CSW=%016X want %016X, records=%d", recover, csw, wantCSW, len(tape.blocks))
		}
	}
}

func Test9020TapeWritePastStoppedSE(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const dev = 0x130
	tape := &Tape2401{Tape3420: &Tape3420{}}
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	m.S.Mem[bytesPer9020SE] = 'A'
	copy(m.S.Mem[0x4000:], "BCDEF")
	ccw0(m, 0x2000, 0x01, bytesPer9020SE, ccwCD, 1)
	ccw0(m, 0x2008, 0x01, 0x4000, ccwSLI, 5)
	if cc := ioInstr(c, 0x9c, dev, 0x2000); cc != 0 {
		t.Fatalf("data-chained write: CC=%d", cc)
	}
	// The 2803 requests the first byte before tape motion. The remaining
	// bytes come from SE1, so stopping SE2 now leaves no pending request.
	m.tod += todMicro
	if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	finishTransfer(t, m, dev)
	if csw := interrupt(t, c); csw != 0x00002010_0c000000 || len(tape.blocks) != 1 || string(tape.blocks[0].data) != "ABCDEF" {
		t.Fatalf("data-chained write beyond stopped SE2: CSW=%016X records=%d", csw, len(tape.blocks))
	}
}

func Test9020TapeWriteUntilFetchProtection(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}}
	const dev = 0x130
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	copy(m.S.Mem[0x47fe:], "ABCD")
	*m.S.key(0x4800) = 0x20 | keyFetch
	ccw0(m, 0x2000, 0x01, 0x47fe, ccwSLI, 4)
	if cc := ioInstr(c, 0x9c, dev, 0x50002000); cc != 0 {
		t.Fatalf("write SIO: CC=%d", cc)
	}
	finishTransfer(t, m, dev)
	if csw := interrupt(t, c); csw != 0x50002008_0c100002 {
		t.Fatalf("protected output CSW: %016X", csw)
	}
	if len(tape.blocks) != 1 || string(tape.blocks[0].data) != "AB" {
		t.Fatal("write did not record the two bytes accepted before protection check")
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
	finishTransfer(t, m, dev)
	if csw := interrupt(t, c); csw != 0x00001018_0C400000 {
		t.Fatalf("write ended under count control: %016X", csw)
	}
}

func TestTapeSelectorHaltEndsChannelBeforeDevice(t *testing.T) {
	for _, profile := range []struct {
		name    string
		model   uint8
		elapsed uint64 // microseconds after SIO
		written int
	}{
		{"2401", 0, 8500, 31},
		{"2420", 7, 45100, 33},
	} {
		t.Run(profile.name, func(t *testing.T) {
			m, c := newTest360(t, true, nil)
			tape := &Tape2401{Tape3420: &Tape3420{transportModel: profile.model, peOnly: profile.model == 7}}
			tape.Reset()
			const dev = 0x3f0
			if _, err := m.CSS.Attach(dev, tape); err != nil {
				t.Fatal(err)
			}
			c.PSW.SysMask = 0xff
			ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 80)
			if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
				t.Fatalf("write: cc=%d", cc)
			}
			m.tod += profile.elapsed * todMicro
			m.CSS.tick370()
			if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
				t.Fatalf("halt: cc=%d", cc)
			}
			if csw := interrupt(t, c); csw != 0x00001018_00000000|uint64(80-profile.written) {
				t.Fatalf("selector termination: %016X", csw)
			}
			if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
				t.Fatalf("test after halt: cc=%d status=%02X", cc, m.S.Mem[0x44])
			}
			advance(m)
			if csw := interrupt(t, c); csw != 0x00000000_2C000000 {
				t.Fatalf("device termination: %016X", csw)
			}
			if len(tape.blocks) != 1 || tape.blocks[0].n != profile.written {
				t.Fatalf("halted write did not leave a %d-byte record", profile.written)
			}
		})
	}
}

func TestTape2415HaltBeforeFirstBytePreservesMedia(t *testing.T) {
	m, c := newTest360(t, true, nil)
	tape := &Tape2401{Tape3420: &Tape3420{blocks: []tapeBlock{{data: []byte("OLD"), n: 3}, {mark: true}}}, model2415: true}
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
	if out, _, _ := tape.Exec(0x04, nil, false); !bytes.Equal(out, []byte{2, 0x4c, 3, 0, 0, 0}) {
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
	copy(m.S.Mem[0x2000:], "NEWS")
	finishTransfer(t, m, dev)
	if len(tape.blocks) != 1 || string(tape.blocks[0].data) != "DEWS" {
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
		// The count field is validated even for an immediate operation.
		{"zero_count_chained_nop", func(m *Machine) {
			ccw0(m, 0x1000, 0x03, 0, ccwCC, 1)
			ccw0(m, 0x1008, 0x03, 0, 0, 0)
		}, 0, 0x0020, true},
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

func TestS360InputStopsAtStorageBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, record, tail string
		chained            bool
		backward           bool
		csw                uint64
	}{
		{"crossing", "ABCDE", "ABC", false, false, 0x00001008_0C200002},
		{"short record", "ABC", "ABC", false, false, 0x00001008_0C000002},
		{"data chained", "ABCDEF", "BCD", true, false, 0x00001010_0C200002},
		{"backward", "ABCDE", "CDE", false, true, 0x00001008_0C200002},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMachine(Config{Memory: 64 << 10, S360: true})
			c := m.CPUs[0]
			c.PSW.SysMask = 0xff
			tape := &Tape3420{}
			tape.writeRecord([]byte(tc.record))
			command, address := byte(0x02), uint32(0xfffd)
			if tc.backward {
				command, address = 0x0c, 2
			} else {
				tape.pos = 0
			}
			if _, err := m.CSS.Attach(0x130, tape); err != nil {
				t.Fatal(err)
			}
			endCCW := uint32(0x1000)
			if tc.chained {
				ccw0(m, 0x1000, 0x02, 0x2000, ccwCD, 1)
				endCCW += 8
			}
			ccw0(m, endCCW, command, address, ccwSLI, 5)
			if cc := ioInstr(c, 0x9c, 0x130, 0x1000); cc != 0 {
				t.Fatalf("read start cc=%d", cc)
			}
			var checkpoint bytes.Buffer
			if err := m.Save(&checkpoint); err != nil {
				t.Fatal(err)
			}
			if err := m.Restore(&checkpoint, false); err != nil {
				t.Fatal(err)
			}
			advance(m)
			if csw := interrupt(t, c); csw != tc.csw {
				t.Fatalf("CSW %016X, want %016X", csw, tc.csw)
			}
			start := address
			if tc.backward {
				start -= 2
			}
			if got := string(m.S.Mem[start : start+3]); got != tc.tail {
				t.Fatalf("stored prefix %q, want %q", got, tc.tail)
			}
			if tc.chained && m.S.Mem[0x2000] != 'A' {
				t.Fatalf("earlier data segment lost its byte: %02X", m.S.Mem[0x2000])
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

func Test2821PunchBurstTiming(t *testing.T) {
	for _, tc := range []struct {
		name  string
		burst bool
		ceUS  uint64
		peer  byte
	}{
		{"multiplex", false, 810, 0},
		{"burst", true, 490, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newTest360(t, true, nil)
			reader, punch := &UnitRecord{Type: 0x2540}, &UnitRecord{Type: 0x2541}
			reader.cardPeer, punch.cardPeer = punch, reader
			reader.Load([]string{"DATA"})
			if err := m.CSS.AttachUnitRecord(0x00c, reader); err != nil {
				t.Fatal(err)
			}
			if err := m.CSS.AttachUnitRecord(0x00d, punch); err != nil {
				t.Fatal(err)
			}
			if err := m.CSS.Set2821Burst(0x00d, tc.burst); err != nil || reader.burst2821 != tc.burst {
				t.Fatalf("setting controller mode: %v", err)
			}
			ccw0(m, 0x1000, 0x01, 0x2000, ccwSLI, 80)
			if cc := ioInstr(c, 0x9c, 0x00d, 0x1000); cc != 0 {
				t.Fatalf("punch SIO condition code = %d", cc)
			}
			sub := m.CSS.bydev[0x00d]
			if got := (sub.finishAt - m.tod) / todMicro; got != tc.ceUS {
				t.Fatalf("first transfer delay = %d us, want %d", got, tc.ceUS)
			}
			if cc := ioInstr(c, 0x9d, 0x00c, 0); cc != tc.peer {
				t.Fatalf("reader TIO condition code = %d, want %d", cc, tc.peer)
			}
			if cc := ioInstr(c, 0x9f, 0x000, 0); cc != tc.peer {
				t.Fatalf("Test Channel condition code = %d, want %d", cc, tc.peer)
			}
			if !advance(m) || sub.deAt != m.tod+200000*todMicro {
				t.Fatalf("punch Device End deadline = %d, current TOD = %d", sub.deAt, m.tod)
			}
			if cc := ioInstr(c, 0x9d, 0x00c, 0); cc != 0 {
				t.Fatalf("reader TIO condition code after Channel End = %d", cc)
			}
		})
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
	endOfStorage := m.S.Size() - 3
	ccw0(m, 0x1000, 0x06, endOfStorage, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("boundary read SIO: cc %d, CSW %016X, sense %X", cc, be.Uint64(m.S.Mem[0x40:]), disk.sense[:6])
	}
	for range 3 {
		advance(m)
	}
	if got := string(m.S.Mem[endOfStorage:]); got != "ABC" || m.CSS.byDevice(dev).pending {
		t.Fatalf("data at the boundary: %q, pending interrupt %t", got, m.CSS.byDevice(dev).pending)
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001008_0C200003 {
		t.Fatalf("boundary read CSW %016X", csw)
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
	m.CSS.tick370()
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

func Test9020StopSEDuring2314Write(t *testing.T) {
	m, c := newTest360(t, true, nil)
	disk := NewDASD(FormattedVolume{Heads: 20}, 0x2314, 203, 20)
	const dev = 0x340
	if _, err := m.CSS.Attach(dev, disk); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask, c.PSW.IO = 0xff, true
	disk.StartChain()
	disk.Exec(0x31, []byte{0, 0, 0, 0, 0}, true)
	record := append([]byte{0, 0, 0, 0, 1, 0, 0, 6}, "ABCDEF"...)
	if _, _, status := disk.Exec(0x1d, record, false); status != usCE|usDE {
		t.Fatalf("format: status %02X", status)
	}
	disk.Exec(0x07, make([]byte, 6), false)
	m.S.Mem[0x2014] = 1
	copy(m.S.Mem[bytesPer9020SE:], "GHIJKL")
	ccw0(m, 0x1000, 0x31, 0x2010, ccwCC, 5)
	ccw0(m, 0x1008, 0x08, 0x1000, 0, 1)
	ccw0(m, 0x1010, 0x05, bytesPer9020SE, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 {
		t.Fatalf("write SIO: cc %d", cc)
	}
	start := m.tod
	if !advance(m) || m.tod != start+diskTransferTOD2314(1) {
		t.Fatal("2314 did not request the first byte at the disk byte rate")
	}
	copy(m.S.Mem[bytesPer9020SE:], "XYZ")
	m.tod = start + diskTransferTOD2314(3)
	m.CSS.tick370() // The second and third bytes now come from revised storage.
	c.logoutStorage9020(0x280, 0, 2)
	if c.PSW.CC != 0 || string(m.S.Mem[0x288:0x28e]) != "XYZJKL" ||
		m.storageLatches9020[1][0].Response != 0x04 {
		t.Fatal("FD0 did not capture the latest 2314 source word from IOCE 1")
	}
	if err := m.ReplayStorageLogout9020(2, make([]byte, seLogoutSize9020)); err != nil {
		t.Fatal(err)
	}
	if m.CSS.next != start+diskTransferTOD2314(4) || !advance(m) {
		t.Fatal("channel did not stop at the fourth byte request")
	}
	if csw := interrupt(t, c); csw != 0x00001018_0c210003 {
		t.Fatalf("stopped disk output CSW: %016X", csw)
	}
	records, err := disk.track(0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(records[1].Data); got != "GYZ\x00\x00\x00" {
		t.Fatalf("short disk write: %q", got)
	}
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

func Test1443PrintBarAndCarriageControl(t *testing.T) {
	printer := UnitRecord{Type: 0x1443}
	data := bytes.Repeat(EncodeEBCDIC("A"), 132)
	if _, n, status := printer.Exec(0x09, data, false); n != 120 || status != usCE|usDE {
		t.Fatalf("write and space: count %d, status %02X", n, status)
	}
	if len(printer.Output) != 1 || len(printer.Output[0]) != 120 || printer.pr.linesAdvanced != 1 {
		t.Fatalf("print width or carriage advance is incorrect")
	}
	transfer, printing := printer.CommandTiming(0x09, 120)
	if transfer <= 0 || printing <= 0 || transfer+printing != 250*time.Millisecond {
		t.Fatalf("1443 N1 standard-bar timing: channel end %s, device end %s", transfer, transfer+printing)
	}
	if _, _, status := printer.Exec(0xeb, nil, false); status != usCE|usDE|usUnitCheck {
		t.Fatalf("UCS command on a print-bar printer: status %02X", status)
	}
	if sense, _, _ := printer.Exec(0x04, nil, false); !bytes.Equal(sense, []byte{senseCmdRej}) {
		t.Fatalf("sense after invalid command: % X", sense)
	}
	wide := UnitRecord{Type: 0x1443, wide1443: true}
	data = bytes.Repeat(EncodeEBCDIC("A"), 145)
	data[143] = EncodeEBCDIC("Z")[0]
	if _, n, status := wide.Exec(0x09, data, false); n != 144 || status != usCE|usDE {
		t.Fatalf("wide write and space: count %d, status %02X", n, status)
	}
	if len(wide.Output) != 1 || len(wide.Output[0]) != 144 || wide.Output[0][143] != 'Z' {
		t.Fatal("wide printer must print through position 144")
	}
}

func Test1442TranslatedReadAndIntegratedPunch(t *testing.T) {
	reader := UnitRecord{Type: 0x1442}
	reader.Load([]string{"", "NEXT"})
	if card, _, status := reader.Exec(0x02, nil, false); len(card) != 80 || status != usCE|usDE {
		t.Fatalf("read card into punch station: length %d, status %02X", len(card), status)
	}
	if _, n, status := reader.Exec(0x01, EncodeEBCDIC("A"), false); n != 1 || status != usCE|usDE {
		t.Fatalf("punch first column: used %d, status %02X", n, status)
	}
	punched, sense := readCardColumns(reader.card1442, false)
	if punched[0] != EncodeEBCDIC("A")[0] || sense != 0 {
		t.Fatalf("punch contents: first column %02X, sense %02X", punched[0], sense)
	}
	card, _, status := reader.Exec(0x22, nil, false)
	if !bytes.HasPrefix(card, EncodeEBCDIC("NEXT")) || len(card) != 80 || status != usCE|usDE|usUnitExcept ||
		reader.readStackers != [3]uint64{0, 1, 0} {
		t.Fatalf("translated read and alternate stacker: length %d, status %02X, stackers %v", len(card), status, reader.readStackers)
	}
}

func TestReaderColumnBinaryCard(t *testing.T) {
	card := make([]byte, 160)
	card[0] = 0x08                // Row 0: EBCDIC zero.
	card[2], card[3] = 0x3f, 0x3f // Untranslatable punches.
	reader := UnitRecord{Type: 0x2540, cards: [][]byte{card, card}}
	data, _, status := reader.Exec(0x22, nil, false)
	if len(data) != 160 || data[0] != 0x08 || data[2] != 0x3f || data[3] != 0x3f || status != usCE|usDE {
		t.Fatalf("column-binary read: length %d, status %02x", len(data), status)
	}
	data, _, status = reader.Exec(0x02, nil, false)
	if len(data) != 80 || data[0] != 0xf0 || status != usCE|usDE|usUnitCheck || reader.sense != 0x08 {
		t.Fatalf("translated read: length %d, status %02x, sense %02x", len(data), status, reader.sense)
	}
}

func Test2401FileProtectRing(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{fileProtected: true}}
	for _, cmd := range []byte{0x01, 0x17, 0x1f} {
		_, used, status := tape.Exec(cmd, []byte{1}, false)
		if status != usUnitCheck || used != 0 || tape.pos != 0 || len(tape.blocks) != 0 {
			t.Fatalf("protected command %02X: status %02X, used %d, position %d", cmd, status, used, tape.pos)
		}
		sense, _, _ := tape.Exec(0x04, nil, false)
		if sense[0]&senseCmdReject == 0 || sense[1]&0x02 == 0 {
			t.Fatalf("protected command %02X: sense % X", cmd, sense)
		}
	}
	tape.pastLoadPoint, tape.unloaded, tape.tapeIndicate = true, true, true
	tape.reelPosition = 1200
	tape.remountWithRing(true)
	if tape.pos != 0 || tape.pastLoadPoint || tape.unloaded || tape.tapeIndicate || tape.reelPosition != 0 {
		t.Fatal("remount must leave the reel loaded at its load point")
	}
	sense, _, _ := tape.Exec(0x04, nil, false)
	if sense[1]&0x02 != 0 {
		t.Fatalf("ring inserted: sense % X", sense)
	}
	_, used, status := tape.Exec(0x01, []byte{1}, false)
	if status != usCE|usDE || used != 1 {
		t.Fatalf("ring inserted: status %02X, used %d", status, used)
	}
}

func Test2415SharedControlSelectionDuringTapeMotion(t *testing.T) {
	m, c := newTest360(t, false, nil)
	for _, addr := range []uint16{0x130, 0x131, 0x138} {
		tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
		tape.writeRecord(make([]byte, 1500))
		tape.pos = 0
		if _, err := m.CSS.Attach(addr, tape); err != nil {
			t.Fatal(err)
		}
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x37, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("spacing start: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	ccw0(m, 0x1018, 0x03, 0, 0, 1)
	for _, op := range []byte{0x9c, 0x9d} {
		if cc := ioInstr(c, op, 0x131, 0x1018); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
			t.Fatalf("select peer during spacing: op=%02X cc=%d status=%02X", op, cc, m.S.Mem[0x44])
		}
	}
	if cc := ioInstr(c, 0x9d, 0x138, 0); cc != 0 {
		t.Fatalf("separate control during spacing: cc=%d", cc)
	}
	advance(m)
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("select peer with held ending status: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if csw := interrupt(t, c); byte(csw>>24) != usCUE|usDE {
		t.Fatalf("spacing ending status: %016X", csw)
	}
	ccw0(m, 0x1010, 0x07, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("rewind start: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("select peer before rewind disconnect: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	rewindStart := m.tod
	if !advance(m) || m.tod-rewindStart != 30*todMicro {
		t.Fatal("rewind must disconnect after 30 microseconds")
	}
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 0 {
		t.Fatalf("select peer during rewind: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	ccw0(m, 0x1018, 0x04, 0x2000, 0, 6)
	if cc := ioInstr(c, 0x9c, 0x130, 0x1018); cc != 1 || m.S.Mem[0x44] != usBusy {
		t.Fatalf("sense on the rewinding drive: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if sense := m.S.Mem[0x2000:0x2006]; !bytes.Equal(sense, make([]byte, 6)) {
		t.Fatalf("busy selection transferred sense bytes: %X", sense)
	}
	advance(m)
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 0 {
		t.Fatalf("select peer with rewind Device End pending: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("rewind ending status: %016X", csw)
	}
	if cc := ioInstr(c, 0x9c, 0x130, 0x1018); cc != 0 {
		t.Fatalf("sense after rewind: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw, sense := interrupt(t, c), m.S.Mem[0x2000:0x2006]; byte(csw>>24) != usCE|usDE ||
		!bytes.Equal(sense, []byte{0x00, 0x48, 0x03, 0x00, 0x00, 0x00}) {
		t.Fatalf("sense after rewind: CSW %016X, data %X", csw, sense)
	}
	ioInstr(c, 0x9c, 0x130, 0x1010)
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 0 {
		t.Fatalf("rewind at load point must disconnect immediately: cc=%d", cc)
	}
}

func Test2415HaltAfterLoadPointEraseWithoutWriteData(t *testing.T) {
	m, c := newTest360(t, false, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.setReelEOT(3)
	const dev = 0x130
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 80)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
		t.Fatalf("write start: cc=%d", cc)
	}
	m.tod += 207000 * todMicro
	if cc := ioInstr(c, 0x9e, dev, 0); cc != 2 {
		t.Fatalf("halt: cc=%d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_00000050 {
		t.Fatalf("halt with full residual: %016X", csw)
	}
	advance(m)
	if csw := interrupt(t, c); byte(csw>>24) != usCE|usDE|usUnitCheck {
		t.Fatalf("write ending status: %016X", csw)
	}
	if len(tape.blocks) != 0 || !tape.pastLoadPoint || tape.reelPosition != 3000 || !tape.tapeIndicate {
		t.Fatalf("empty write: %d blocks, past load point %t, position %d, tape indicate %t",
			len(tape.blocks), tape.pastLoadPoint, tape.reelPosition, tape.tapeIndicate)
	}
	if sense, _, _ := tape.Exec(0x04, nil, false); sense[0] != 0x02 || sense[1]&0x08 != 0 {
		t.Fatalf("sense after erase without data: %x", sense)
	}
}

func Test2415RewindEndWaitsForSharedControl(t *testing.T) {
	m, c := newTest360(t, false, nil)
	for _, addr := range []uint16{0x130, 0x131} {
		tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
		tape.writeRecord(make([]byte, 1500))
		if addr == 0x131 {
			tape.pos = 0
		}
		if _, err := m.CSS.Attach(addr, tape); err != nil {
			t.Fatal(err)
		}
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x07, 0, 0, 1)
	ioInstr(c, 0x9c, 0x130, 0x1010)
	advance(m) // the controller disconnects before the reel stops
	ccw0(m, 0x1018, 0x37, 0, 0, 1)
	ioInstr(c, 0x9c, 0x131, 0x1018)
	rewind, spacing := m.CSS.bydev[0x130], m.CSS.bydev[0x131]
	if rewind.deAt == 0 || rewind.deAt >= spacing.deAt {
		t.Fatal("rewind must finish physically before spacing")
	}
	if !advance(m) || !spacing.pending || rewind.pending {
		t.Fatalf("first completion: rewind pending %t, spacing pending %t", rewind.pending, spacing.pending)
	}
	interrupt(t, c)
	acceptedAt := m.tod
	if !advance(m) || !rewind.pending || m.tod < acceptedAt {
		t.Fatal("rewind ending status must follow spacing without moving the clock backward")
	}
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("rewind ending status: %016X", csw)
	}
}

func Test2415ReloadWaitsForReelTravel(t *testing.T) {
	m, c := newTest360(t, false, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	const dev = 0x130
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	peer := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	peer.writeRecord(make([]byte, 20000))
	peer.pos = 0
	if _, err := m.CSS.Attach(0x131, peer); err != nil {
		t.Fatal(err)
	}
	tape.setReelEOT(240)
	tape.reelPosition = 120 * nrziFramesPerInch
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x0f, 0, 0, 1)
	start := m.tod
	ioInstr(c, 0x9c, dev, 0x1010)
	advance(m)
	if csw := interrupt(t, c); byte(csw>>24) != usCUE|usDE|usUnitCheck || m.tod-start != 30*todMicro {
		t.Fatalf("unload initiation: CSW %016X, time %d us", csw, (m.tod-start)/todMicro)
	}
	if cc := ioInstr(c, 0x9d, 0x131, 0); cc != 0 {
		t.Fatalf("sibling drive during reel travel: cc=%d", cc)
	}
	ccw0(m, 0x1018, 0x37, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, 0x131, 0x1018); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("sibling space block: cc=%d, status %02X", cc, m.S.Mem[0x44])
	}
	m.CSS.remountTape(m.CSS.bydev[dev], tape, false)
	if !tape.unloaded || m.CSS.bydev[dev].pending {
		t.Fatal("early operator reload must wait for reel travel")
	}
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if !advance(m) || m.tod-start != 1000000*todMicro || tape.unloaded || !tape.fileProtected {
		t.Fatalf("reload after reel travel: time %d us, unloaded %t, file protected %t",
			(m.tod-start)/todMicro, tape.unloaded, tape.fileProtected)
	}
	if m.CSS.bydev[dev].pending || !tape.readyEnd {
		t.Fatal("reloaded drive must wait for sibling spacing to end before interrupting")
	}
	if !advance(m) || m.CSS.bydev[dev].pending || !m.CSS.bydev[0x131].pending {
		t.Fatal("sibling spacing must present ending status first")
	}
	interrupt(t, c)
	if !advance(m) {
		t.Fatal("operator-ready status must become available after controller release")
	}
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("ready interruption: %016X", csw)
	}
}

func Test2415ReadyPreservesPendingUnloadStatus(t *testing.T) {
	m, c := newTest360(t, false, nil)
	tape := &Tape2401{Tape3420: &Tape3420{fileProtected: true}, model2415: true}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x0f, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("rewind-unload: cc=%d status=%02X", cc, m.S.Mem[0x44])
	}
	if delay := m.CSS.bydev[dev].deAt - m.tod; delay != 30*todMicro {
		t.Fatalf("rewind-unload ending status is scheduled %d microseconds after channel end", delay/todMicro)
	}
	advance(m)
	m.CSS.remountTape(m.CSS.bydev[dev], tape, true)
	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	if csw := interrupt(t, c); byte(csw>>24) != usCUE|usDE|usUnitCheck {
		t.Fatalf("rewind-unload ending status: %016X", csw)
	}
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("manual ready status: %016X", csw)
	}
}

func Test2415ResetAndStartPreserveTapePosition(t *testing.T) {
	m, c := newTest360(t, false, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	tape.writeRecord([]byte("first record"))
	tape.writeRecord([]byte("second record"))
	tape.pos, tape.pastLoadPoint, tape.tapeIndicate = 1, true, true
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	x := m.CSS.bydev[dev]
	c.PSW.SysMask = 0xff
	m.CSS.setTapeManual(x, tape, true)
	m.CSS.setTapeManual(x, tape, false)
	if x.pending {
		t.Fatal("unselected drive must not signal device end on START")
	}
	m.CSS.setTapeManual(x, tape, true)
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usUnitCheck {
		t.Fatalf("TIO in manual control: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	sense, _, status := tape.Exec(0x04, nil, false)
	if status != usCE|usDE || sense[0] != senseIntervReq || sense[1] != 0x20 || tape.tapeIndicate || x.pending {
		t.Fatalf("manual sense % X, status %02X, tape indicate %t, pending %t", sense, status, tape.tapeIndicate, x.pending)
	}
	if _, _, status := tape.Exec(0x37, nil, false); status != usUnitCheck || tape.pos != 1 {
		t.Fatalf("spacing in manual control returned %02X at record %d", status, tape.pos)
	}
	m.CSS.setTapeManual(x, tape, false)
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("start interruption: %016X", csw)
	}
	out, _, status := tape.Exec(0x02, nil, false)
	if string(out) != "second record" || status != usCE|usDE {
		t.Fatalf("read after start returned %q, status %02X", out, status)
	}
}

func Test2415ResetDuringSenseUpdatesOnlyUnsentBytes(t *testing.T) {
	m, c := newTest360(t, false, nil)
	tape := &Tape2401{Tape3420: &Tape3420{}, model2415: true}
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, tape); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x04, 0x2000, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
		t.Fatalf("Sense start: cc %d", cc)
	}
	m.tod += 4 * todMicro // byte 0 transferred while Ready
	m.CSS.setTapeManual(m.CSS.bydev[dev], tape, true)
	advance(m)
	if csw := interrupt(t, c); csw != 0x00001018_0C000000 {
		t.Fatalf("Sense completion: %016X", csw)
	}
	if got := m.S.Mem[0x2000:0x2006]; !bytes.Equal(got, []byte{0x00, 0x20, 0x03, 0, 0, 0}) {
		t.Fatalf("Sense across RESET returned % X", got)
	}
}

func Test2420RewindAtLoadPointSeparatesEndingStatus(t *testing.T) {
	m, c := newTest360(t, false, nil)
	const dev = 0x3f0
	if _, err := m.CSS.Attach(dev, &Tape2401{Tape3420: &Tape3420{transportModel: 7, peOnly: true}}); err != nil {
		t.Fatal(err)
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x07, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("rewind at load point: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	if !advance(m) {
		t.Fatal("missing rewind ending status")
	}
	if csw := interrupt(t, c); byte(csw>>24) != usDE {
		t.Fatalf("rewind device end: %016X", csw)
	}
}

func Test2401RewindControllerDisconnectsBeforeReelStops(t *testing.T) {
	m, c := newTest360(t, false, nil)
	const dev, sibling = 0x3f0, 0x3f1
	tape := &Tape2401{Tape3420: &Tape3420{transportModel: 5, peOnly: true}}
	peer := &Tape2401{Tape3420: &Tape3420{transportModel: 2, modeCompatible: true}}
	for address, device := range map[uint16]*Tape2401{dev: tape, sibling: peer} {
		if _, err := m.CSS.Attach(address, device); err != nil {
			t.Fatal(err)
		}
	}
	tape.setReelEOT(600)
	tape.reelPosition, tape.pastLoadPoint = 288*nrziFramesPerInch, true // one percent of 2,400 feet
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x07, 0, 0, 1)
	start := m.tod
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("rewind start: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	if cc := ioInstr(c, 0x9d, sibling, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("peer before disconnect: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	if !advance(m) || m.tod-start != durationTOD(30*time.Millisecond) {
		t.Fatalf("rewind disconnect after %d us", (m.tod-start)/todMicro)
	}
	if cc := ioInstr(c, 0x9d, sibling, 0); cc != 0 {
		t.Fatalf("peer after disconnect: cc %d", cc)
	}
	if !advance(m) || m.tod-start != durationTOD(840*time.Millisecond) {
		t.Fatalf("rewind Device End after %d us", (m.tod-start)/todMicro)
	}
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("rewind Device End: %016X", csw)
	}
	ccw0(m, 0x1010, 0x0f, 0, 0, 1)
	start = m.tod
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("unload start: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	if !advance(m) || m.tod-start != durationTOD(45*time.Millisecond) {
		t.Fatalf("unload status after %d us", (m.tod-start)/todMicro)
	}
	if csw := interrupt(t, c); csw != 0x00000000_26000000 {
		t.Fatalf("unload status: %016X", csw)
	}
	if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != usUnitCheck {
		t.Fatalf("test of unloaded transport: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	ccw0(m, 0x1010, 0x03, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 1 || m.S.Mem[0x44] != usUnitCheck {
		t.Fatalf("No Operation on unloaded transport: cc %d, status %02X", cc, m.S.Mem[0x44])
	}
	ccw0(m, 0x1010, 0x04, 0x2000, 0, 6)
	if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 || !advance(m) {
		t.Fatalf("Sense of unloaded transport: cc %d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_0C000000 {
		t.Fatalf("Sense of unloaded transport: CSW %016X", csw)
	}
	if m.S.Mem[0x2000] != senseIntervReq || m.S.Mem[0x2001] != 0x20 {
		t.Fatalf("Sense of unloaded transport: % X", m.S.Mem[0x2000:0x2006])
	}
}

func Test2401DualDensityModeIsSharedAtLoadPoint(t *testing.T) {
	m, c := newTest360(t, false, nil)
	const selector, sibling, separate = 0x3f0, 0x3f1, 0x3f8
	drives := map[uint16]*Tape2401{}
	for _, address := range []uint16{selector, sibling, separate} {
		drive := &Tape2401{Tape3420: &Tape3420{transportModel: 5, dualDensity: true}}
		drive.Reset()
		if _, err := m.CSS.Attach(address, drive); err != nil {
			t.Fatal(err)
		}
		drives[address] = drive
	}
	c.PSW.SysMask = 0xff
	write := func(address uint16, density int) {
		t.Helper()
		ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 80)
		if cc := ioInstr(c, 0x9c, address, 0x1010); cc != 0 || !advance(m) {
			t.Fatalf("write to %03X: cc %d", address, cc)
		}
		if csw := interrupt(t, c); csw != 0x00001018_0C000000 {
			t.Fatalf("write to %03X: CSW %016X", address, csw)
		}
		drive := drives[address]
		if got := drive.blocks[drive.pos-1].density; got != density {
			t.Fatalf("write to %03X: density %d, want %d", address, got, density)
		}
	}
	write(sibling, 1600)
	ccw0(m, 0x1010, 0xcb, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, selector, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE|usDE {
		t.Fatalf("set NRZI on %03X: cc %d, status %02X", selector, cc, m.S.Mem[0x44])
	}
	write(sibling, 1600)
	ccw0(m, 0x1010, 0x07, 0, 0, 1)
	if cc := ioInstr(c, 0x9c, sibling, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
		t.Fatalf("rewind %03X: cc %d, status %02X", sibling, cc, m.S.Mem[0x44])
	}
	advance(m)
	if csw := interrupt(t, c); csw != 0x00000000_04000000 {
		t.Fatalf("rewind %03X: CSW %016X", sibling, csw)
	}
	write(sibling, 800)
	write(separate, 1600)
}

func Test2401RejectedConverterModeStillSetsController(t *testing.T) {
	m, c := newTest360(t, false, nil)
	const selector, sibling = 0x3f0, 0x3f1
	first := &Tape2401{Tape3420: &Tape3420{transportModel: 2, sevenTrack: true, noConverter: true}}
	second := &Tape2401{Tape3420: &Tape3420{transportModel: 2, sevenTrack: true, noConverter: true}}
	for address, drive := range map[uint16]*Tape2401{selector: first, sibling: second} {
		drive.Reset()
		if _, err := m.CSS.Attach(address, drive); err != nil {
			t.Fatal(err)
		}
	}
	c.PSW.SysMask = 0xff
	ccw0(m, 0x1010, 0x2b, 0, 0, 1) // 200 bpi, even parity, translator on
	if cc := ioInstr(c, 0x9c, selector, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE|usDE || second.sevenMode != tapeEvenTranslate {
		t.Fatalf("set even mode: cc %d, status %02X, sibling mode %02X", cc, m.S.Mem[0x44], second.sevenMode)
	}
	ccw0(m, 0x1010, 0x53, 0, 0, 1) // 556 bpi with unavailable converter
	if cc := ioInstr(c, 0x9c, selector, 0x1010); cc != 1 || m.S.Mem[0x44] != usUnitCheck || first.sense[0] != senseCmdReject {
		t.Fatalf("request converter: cc %d, status %02X, sense %02X", cc, m.S.Mem[0x44], first.sense[0])
	}
	ccw0(m, 0x1010, 0x01, 0x2000, ccwSLI, 3)
	if cc := ioInstr(c, 0x9c, sibling, 0x1010); cc != 0 || !advance(m) {
		t.Fatalf("write to sibling: cc %d", cc)
	}
	if csw := interrupt(t, c); csw != 0x00001018_0C000000 {
		t.Fatalf("write to sibling: CSW %016X", csw)
	}
	block := second.blocks[0]
	if block.density != 556 || !bytes.Equal(block.data, []byte{0x40, 0x40, 0x40}) {
		t.Fatalf("sibling wrote %X at %d bpi", block.data, block.density)
	}
}

func Test2401InhibitGoDelaysOnlyEarlyReinstruction(t *testing.T) {
	for _, profile := range []struct {
		model      uint8
		compatible bool
		hold       time.Duration
	}{
		{1, true, 4 * time.Millisecond}, {2, true, 1200 * time.Microsecond},
		{3, false, 0}, {4, false, 4 * time.Millisecond}, {5, false, 1200 * time.Microsecond},
	} {
		m, c := newTest360(t, false, nil)
		tape := &Tape2401{Tape3420: &Tape3420{transportModel: profile.model, modeCompatible: profile.compatible, peOnly: profile.model >= 4}}
		tape.Reset()
		for range 3 {
			tape.writeRecord(make([]byte, 1600))
		}
		tape.pos = 0
		tape.pastLoadPoint = true
		const dev = 0x3f0
		if _, err := m.CSS.Attach(dev, tape); err != nil {
			t.Fatal(err)
		}
		c.PSW.SysMask = 0xff
		ccw0(m, 0x1010, 0x02, 0x2000, 0, 1600)
		x := m.CSS.bydev[dev]
		var delays [3]uint64
		for i := range delays {
			if i == 2 {
				m.tod += durationTOD(profile.hold)
			}
			if cc := ioInstr(c, 0x9c, dev, 0x1010); cc != 0 {
				t.Fatalf("Model %d read %d: cc %d", profile.model, i+1, cc)
			}
			delays[i] = x.finishAt - m.tod
			advance(m)
			interrupt(t, c)
		}
		if delays[0] != delays[2] || delays[1] != delays[0]+durationTOD(profile.hold) {
			t.Fatalf("Model %d completion delays %v, want early read held for %s", profile.model, delays, profile.hold)
		}
	}
}

func Test2401SpacingDuringRunout(t *testing.T) {
	for _, tc := range []struct {
		name          string
		model         uint8
		first, second byte
		pos           int
		backward      bool
		recordSize    uint16
		restart       time.Duration
	}{
		{"Model 3 read then forward space", 3, 0x02, 0x3f, 1, false, 8000, 291 * time.Microsecond},
		{"Model 6 read then forward space", 6, 0x02, 0x3f, 1, false, 8000, 291 * time.Microsecond},
		{"forward space then forward space", 3, 0x37, 0x3f, 1, false, 8000, 291 * time.Microsecond},
		{"backspace then backspace", 3, 0x27, 0x2f, 2, true, 8000, 291 * time.Microsecond},
		{"reverse after a read", 3, 0x02, 0x27, 1, false, 8000, 0},
		{"short read after turnaround", 3, 0x02, 0x3f, 1, true, 1, 0},
		{"clocked write tape mark after a read", 3, 0x02, 0x1f, 1, false, 8000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delay := func(wait time.Duration) uint64 {
				m, c := newTest360(t, false, nil)
				tape := &Tape2401{Tape3420: &Tape3420{
					transportModel: tc.model, peOnly: tc.model == 6,
					pos: tc.pos, pastLoadPoint: true, backward: tc.backward,
					blocks: []tapeBlock{
						{mark: true},
						{data: make([]byte, tc.recordSize), n: int(tc.recordSize)},
						{mark: true},
					},
				}}
				tape.Reset()
				const addr = 0x3f0
				if _, err := m.CSS.Attach(addr, tape); err != nil {
					t.Fatal(err)
				}
				c.PSW.SysMask = 0xff
				ccw0(m, 0x1010, tc.first, 0x2000, ccwSLI, tc.recordSize)
				cc := ioInstr(c, 0x9c, addr, 0x1010)
				if (tc.first == 0x02 && cc != 0) || (tc.first != 0x02 && cc != 1) || !advance(m) {
					t.Fatalf("first command %02X: cc %d", tc.first, cc)
				}
				if csw := interrupt(t, c); byte(csw>>24)&usDE == 0 {
					t.Fatalf("first command %02X: CSW %016X", tc.first, csw)
				}
				m.tod += durationTOD(wait)
				ccw0(m, 0x1010, tc.second, 0, 0, 1)
				if cc := ioInstr(c, 0x9c, addr, 0x1010); cc != 1 || m.S.Mem[0x44] != usCE {
					t.Fatalf("second command %02X: cc %d, status %02X", tc.second, cc, m.S.Mem[0x44])
				}
				start := m.tod
				if !advance(m) {
					t.Fatal("missing second command ending status")
				}
				if csw := interrupt(t, c); byte(csw>>24) != usDE {
					t.Fatalf("second command %02X: CSW %016X", tc.second, csw)
				}
				return m.tod - start
			}
			settled := delay(20 * time.Millisecond)
			early := delay(9 * time.Microsecond)
			if early != settled+durationTOD(tc.restart) {
				t.Fatalf("early delay %d TOD ticks, want settled delay %d plus %s", early, settled, tc.restart)
			}
			if tc.restart != 0 {
				// Halfway through braking, half the nominal speed
				// remains and the launch saves more than the runout.
				braking := delay(1800 * time.Microsecond)
				if braking+durationTOD(950*time.Microsecond) != settled {
					t.Fatalf("delay during braking %d TOD ticks, want %d", braking, settled-durationTOD(950*time.Microsecond))
				}
			}
		})
	}
}

func Test2401SenseAfterRewindUnload(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}}
	tape.Exec(0x0f, nil, false)
	sense, _, status := tape.Exec(0x04, nil, false)
	if status != usCE|usDE || len(sense) != 6 || sense[0]&senseIntervReq == 0 || sense[1]&0x40 != 0 {
		t.Fatalf("unloaded sense % X, status %02X", sense, status)
	}
}

func Test2401BackwardClearsTapeIndicateBeyondMarker(t *testing.T) {
	tape := &Tape2401{Tape3420: &Tape3420{}}
	tape.setReelEOT(1)
	// Cross the marker and write another block entirely past it.
	for _, n := range []int{800, 1} {
		if status := tape.finishWrite(make([]byte, n)); status != usUnitExcept {
			t.Fatalf("write of %d bytes: ending status %02X, want unit exception", n, status)
		}
	}
	tape.Exec(0x27, nil, false)
	if tape.reelPosition < tape.reelEOT || tape.tapeIndicate {
		t.Fatal("backspace past the marker must clear Tape Indicate")
	}
	_, _, status := tape.Exec(0x17, nil, false)
	sense, _, _ := tape.Exec(0x04, nil, false)
	if status != usCE|usDE || sense[1]&0x04 != 0 {
		t.Fatalf("erase entirely past the marker: status %02X, sense % X", status, sense)
	}
}

func Test1403Dualing(t *testing.T) {
	p := &UnitRecord{Type: 0x1403, pr: printer{dualing: true, ucsLoaded: true}}
	copy(p.pr.ucs[:], []byte{0x4d, 0x5d, 0x7e, 0x7d})
	_, _, status := p.Exec(0x01, []byte{0x4d, 0x5d, 0x7e, 0x7d}, false)
	if status != usCE|usDE {
		t.Fatalf("write status %02X, sense %02X", status, p.sense)
	}
	data, _, _ := p.Exec(0x02, nil, false)
	if got := be.Uint32(data[:4]); got != 0x6c4c7b7c {
		t.Fatalf("read back %08X, want 6C4C7B7C", got)
	}
}

func Test2540PunchStackerFeed(t *testing.T) {
	punch := &UnitRecord{Type: 0x2541}
	punch.Exec(0x41, []byte{0xf1}, false)
	if punch.punchStackers != [3]uint64{} {
		t.Fatal("the first card is still in the transport")
	}
	punch.Exec(0x81, []byte{0xf2}, false)
	if punch.punchStackers != [3]uint64{0, 1, 0} {
		t.Fatalf("second feed must stack the first card in P2: %v", punch.punchStackers)
	}
	punch.runOutPunch()
	if punch.punchPending || punch.punchStackers != [3]uint64{1, 1, 0} {
		t.Fatalf("nonprocess runout must stack the remaining card in P1: %v", punch.punchStackers)
	}
}
