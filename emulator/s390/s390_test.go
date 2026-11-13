package s390

import (
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/filesystem/ckd"
)

// newTest returns a machine with code placed at 0x1000 and a program new
// PSW that loads a disabled wait identifying the interruption code.
func newTest(t *testing.T, code []byte) (*Machine, *CPU) {
	t.Helper()
	m := NewMachine(Config{Memory: 4 << 20, Start: time.Date(2003, 11, 1, 12, 0, 0, 0, time.UTC)})
	c := m.CPUs[0]
	copy(m.S.Mem[0x1000:], code)
	// Program new PSW: disabled wait at 0xDEAD.
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x000A0000_0000DEAD)
	c.Stopped = false
	c.loadPSW(0x00080000_80001000)
	return m, c
}

// runTo executes until the CPU loads a disabled wait or the budget ends.
func runTo(t *testing.T, m *Machine) StopReason {
	t.Helper()
	r := m.Run(100000)
	return r
}

// stop is the halt sequence used by tests: IPM 15 (keeping the final
// condition code in GR15) then LPSW of a disabled wait.
func stop() []byte { return []byte{0xb2, 0x22, 0x00, 0xf0, 0x82, 0x00, 0x0f, 0x00} }

func cc(c *CPU) uint32 { return c.GR[15] >> 28 & 3 }

func setupStop(m *Machine) { be.PutUint64(m.S.Mem[0xf00:], 0x000A0000_00000000) }

func TestArithmeticConditionCodes(t *testing.T) {
	code := []byte{
		0x18, 0x12, // LR 1,2
		0x1a, 0x13, // AR 1,3  (overflow)
		0xb2, 0x22, 0x00, 0x40, // IPM 4
		0x18, 0x52, // LR 5,2
		0x1e, 0x56, // ALR 5,6 (carry, zero)
		0xb2, 0x22, 0x00, 0x70, // IPM 7
	}
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[2], c.GR[3], c.GR[6] = 0x7fffffff, 1, 0x80000001
	if r := runTo(t, m); r.Kind != "disabled-wait" {
		t.Fatal(r)
	}
	if c.GR[1] != 0x80000000 || c.GR[4]>>28 != 3 {
		t.Fatalf("AR overflow: r1=%08X cc=%d", c.GR[1], c.GR[4]>>28)
	}
	if c.GR[5] != 0 || c.GR[7]>>28 != 2 {
		t.Fatalf("ALR carry: r5=%08X cc=%d", c.GR[5], c.GR[7]>>28)
	}
}

func TestBranchRelativeLoop(t *testing.T) {
	code := []byte{
		0xa7, 0x18, 0x00, 0x00, // LHI 1,0
		0xa7, 0x28, 0x00, 0x0a, // LHI 2,10
		0x1a, 0x12, // loop: AR 1,2
		0xa7, 0x26, 0xff, 0xff, // BRCT 2,loop
	}
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	runTo(t, m)
	if c.GR[1] != 55 {
		t.Fatalf("sum = %d", c.GR[1])
	}
}

func TestMoveLongPadsAndReportsLengths(t *testing.T) {
	code := []byte{0x0e, 0x24} // MVCL 2,4
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	copy(m.S.Mem[0x3000:], "ABC")
	c.GR[2], c.GR[3] = 0x4000, 8
	c.GR[4], c.GR[5] = 0x3000, 0x40000003 // pad 0x40, length 3
	runTo(t, m)
	if got := string(m.S.Mem[0x4000:0x4008]); got != "ABC\x40\x40\x40\x40\x40" {
		t.Fatalf("dest = %q", got)
	}
	if c.GR[3]&0xffffff != 0 || c.GR[2] != 0x4008 || cc(c) != 2 {
		t.Fatalf("registers %08X %08X cc %d", c.GR[2], c.GR[3], cc(c))
	}
}

func TestEditPacked(t *testing.T) {
	// Pattern: fill, digit, digit, significance starter, '.', digit, digit.
	code := []byte{0xde, 0x06, 0x30, 0x00, 0x30, 0x10} // ED 0(7,3),16(3)
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[3] = 0x3000
	copy(m.S.Mem[0x3000:], []byte{0x40, 0x20, 0x20, 0x21, 0x4b, 0x20, 0x20})
	copy(m.S.Mem[0x3010:], []byte{0x01, 0x23, 0x4c})
	runTo(t, m)
	if got := EBCDICString(m.S.Mem[0x3000:0x3007]); got != "  12.34" {
		t.Fatalf("ED = %q", got)
	}
	if cc(c) != 2 {
		t.Fatalf("ED cc = %d", cc(c))
	}
}

func TestDecimalAddAndConvert(t *testing.T) {
	code := []byte{
		0xfa, 0x31, 0x30, 0x00, 0x30, 0x10, // AP 0(4,3),16(2,3)
		0xf8, 0x73, 0x30, 0x20, 0x30, 0x00, // ZAP 32(8,3),0(4,3)
		0x4f, 0x50, 0x30, 0x20, // CVB 5,32(,3)
		0x4e, 0x60, 0x30, 0x30, // CVD 6,48(,3)
	}
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[3] = 0x3000
	c.GR[6] = uint32(0xffffff85) // -123
	copy(m.S.Mem[0x3000:], []byte{0x00, 0x01, 0x99, 0x9c})
	copy(m.S.Mem[0x3010:], []byte{0x00, 0x1c})
	runTo(t, m)
	if c.GR[5] != 2000 {
		t.Fatalf("CVB = %d", c.GR[5])
	}
	if got := m.S.Mem[0x3030:0x3038]; got[6] != 0x12 || got[7] != 0x3d {
		t.Fatalf("CVD = %X", got)
	}
}

func TestHexFloatAdd(t *testing.T) {
	code := []byte{0x7a, 0x00, 0x30, 0x00} // AE 0,0(,3)
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[3] = 0x3000
	c.FPR[0] = 0x41100000_00000000 // 1.0
	be.PutUint32(m.S.Mem[0x3000:], 0x41100000)
	runTo(t, m)
	if c.FPR[0]>>32 != 0x41200000 || cc(c) != 2 {
		t.Fatalf("AE = %08X cc %d", c.FPR[0]>>32, cc(c))
	}
}

// TEST BLOCK must clear the block, not only test it.
func TestTestBlockClearsBlock(t *testing.T) {
	code := []byte{0xb2, 0x2c, 0x00, 0x02} // TB 0,2
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	c.GR[2] = 0x5000
	for i := 0x5000; i < 0x6000; i++ {
		m.S.Mem[i] = 0xaa
	}
	runTo(t, m)
	for i := 0x5000; i < 0x6000; i++ {
		if m.S.Mem[i] != 0 {
			t.Fatalf("byte %X not cleared", i)
		}
	}
	if cc(c) != 0 {
		t.Fatal("cc", cc(c))
	}
}

// A maximum positive CPU-timer value must not wrap into an immediate interruption.
func TestCPUTimerLargeValueDoesNotFire(t *testing.T) {
	m, c := newTest(t, nil)
	c.setCPUTimer(0x7fffffffffffffff)
	c.CR[0] |= 1 << 10
	c.PSW.Ext = true
	if c.pendingExternal()&extCPUTimer != 0 {
		t.Fatal("CPU timer interruption pending for a large positive value")
	}
	m.tod += 100
	c.setCPUTimer(10)
	m.tod += 11
	if c.pendingExternal()&extCPUTimer == 0 {
		t.Fatal("CPU timer did not become negative")
	}
}

func TestDATTranslationAndSegmentException(t *testing.T) {
	m, c := newTest(t, nil)
	// Segment table at 0x10000 (one 64-byte unit = 16 entries), page table at 0x11000.
	for i := 0; i < 16; i++ {
		be.PutUint32(m.S.Mem[0x10000+4*i:], 0x20) // invalid
	}
	be.PutUint32(m.S.Mem[0x10000:], 0x00011000|0x0f) // segment 0 -> page table, PTL 15
	for i := 0; i < 256; i++ {
		be.PutUint32(m.S.Mem[0x11000+4*i:], 0x400)
	}
	be.PutUint32(m.S.Mem[0x11000+4*3:], 0x00007000) // page 3 -> frame 0x7000
	c.CR[0] = 0x00b00000
	c.CR[1] = 0x00010000 // STL 0
	real, _ := c.translate(0x3abc, c.CR[1], accFetch)
	if real != 0x7abc {
		t.Fatalf("real = %X", real)
	}
	func() {
		defer func() {
			pc, ok := recover().(programCheck)
			if !ok || pc.code != pgmSegment || !pc.nullify {
				t.Fatalf("expected nullifying segment exception, got %v", pc)
			}
		}()
		c.translate(0x00100000, c.CR[1], accFetch)
	}()
}

// fakeDevice transfers fixed data for reads.
type fakeDevice struct{ data []byte }

func (f *fakeDevice) SenseID() []byte { return []byte{0xff, 0x12, 0x34, 0x01} }
func (f *fakeDevice) Reset()          {}
func (f *fakeDevice) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	if cmd == 0x02 {
		return f.data, 0, usCE | usDE
	}
	return nil, len(data), usCE | usDE
}

func TestStartAndTestSubchannel(t *testing.T) {
	code := []byte{
		0xb2, 0x32, 0x30, 0x00, // MSCH 0(3)   enable
		0xb2, 0x33, 0x30, 0x40, // SSCH 64(3)
		0xb2, 0x35, 0x30, 0x80, // TSCH 128(3)
		0xb2, 0x22, 0x00, 0x40, // IPM 4
		0xb2, 0x30, 0x00, 0x00, // CSCH
		0xb2, 0x35, 0x30, 0xc0, // TSCH 192(3) (clear status)
		0xb2, 0x33, 0x30, 0x40, // SSCH again: must not be busy
	}
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	if _, err := m.CSS.Attach(0x0190, &fakeDevice{data: []byte("HELLO")}); err != nil {
		t.Fatal(err)
	}
	c.GR[1] = 0x00010000
	c.GR[3] = 0x3000
	be.PutUint32(m.S.Mem[0x3004:], 1<<23)                                          // PMCW: enabled
	be.PutUint32(m.S.Mem[0x3048:], 0x3100)                                         // ORB: CCW address
	copy(m.S.Mem[0x3100:], []byte{0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x05}) // read 5 to 0x3200
	runTo(t, m)
	if string(m.S.Mem[0x3200:0x3205]) != "HELLO" {
		t.Fatalf("data %q", m.S.Mem[0x3200:0x3205])
	}
	if c.GR[4]>>28 != 0 {
		t.Fatalf("TSCH cc %d", c.GR[4]>>28)
	}
	if irb := be.Uint32(m.S.Mem[0x3080:]); irb&0x1f != scPrimary|scSecondary|1 {
		t.Fatalf("SCSW %08X", irb)
	}
	if cc(c) != 0 {
		t.Fatalf("SSCH after clear cc %d (clear function not cleared by TSCH)", cc(c))
	}
}

// tracks is a synthetic CKD volume.
type tracks map[uint32][]ckd.Record

func (t tracks) Track(n uint32) ([]ckd.Record, error) { return t[n], nil }

func volume() tracks {
	v := tracks{}
	for cyl := uint32(0); cyl < 3; cyl++ {
		for h := uint32(0); h < 15; h++ {
			recs := []ckd.Record{{Cylinder: uint16(cyl), Head: uint16(h), Number: 0, Data: make([]byte, 8)}}
			for r := 1; r <= 2; r++ {
				recs = append(recs, ckd.Record{Cylinder: uint16(cyl), Head: uint16(h), Number: byte(r),
					Data: []byte{byte(cyl), byte(h), byte(r)}})
			}
			v[cyl*15+h] = recs
		}
	}
	return v
}

func locate(op, count byte, cyl, head uint16, rec byte) []byte {
	b := make([]byte, 16)
	b[0], b[3] = op, count
	be.PutUint16(b[4:], cyl)
	be.PutUint16(b[6:], head)
	be.PutUint16(b[8:], cyl)
	be.PutUint16(b[10:], head)
	b[12] = rec
	return b
}

func extent(c0, h0, c1, h1 uint16) []byte {
	b := make([]byte, 16)
	be.PutUint16(b[8:], c0)
	be.PutUint16(b[10:], h0)
	be.PutUint16(b[12:], c1)
	be.PutUint16(b[14:], h1)
	return b
}

// Multi-record reads within a locate-record domain continue onto the next
// cylinder, and operation 0x16 orients on the search argument.
func TestDASDLocateRecordDomainCrossesCylinder(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	if _, _, st := d.Exec(0x63, extent(0, 0, 2, 14), true); st != usCE|usDE {
		t.Fatal("define extent", d.Stats.Errors)
	}
	if _, _, st := d.Exec(0x47, locate(0x16, 3, 0, 14, 2), true); st != usCE|usDE {
		t.Fatal("locate", d.Stats.Errors)
	}
	var got [][]byte
	for i := 0; i < 3; i++ {
		out, _, st := d.Exec(0x86, nil, true)
		if st != usCE|usDE {
			t.Fatal("read", i, d.Stats.Errors)
		}
		got = append(got, out)
	}
	want := [][]byte{{0, 14, 2}, {1, 0, 1}, {1, 0, 2}}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Fatalf("read %d = %v want %v", i, got[i], want[i])
		}
	}
}

func TestDASDWriteGoesToOverlay(t *testing.T) {
	base := volume()
	d := NewDASD3390(base, 3)
	d.StartChain()
	d.Exec(0x63, extent(0, 0, 2, 14), true)
	d.Exec(0x47, locate(0x01, 1, 1, 3, 1), true)
	if _, used, st := d.Exec(0x85, []byte{9, 9, 9}, false); st != usCE|usDE || used != 3 {
		t.Fatal("write", d.Stats.Errors)
	}
	if base[18][1].Data[0] != 1 {
		t.Fatal("base modified")
	}
	r, _ := d.ReadTrack(18)
	if string(r[1].Data) != "\x09\x09\x09" {
		t.Fatalf("overlay %v", r[1].Data)
	}
}

func TestConsole3270WriteAndReadModified(t *testing.T) {
	c := NewConsole3270(24, 80)
	// EW: WCC, SBA row 1 col 0, SF unprotected, IC.
	addr := c.encodeAddr(80)
	data := append([]byte{0xc3, 0x11}, addr...)
	data = append(data, 0x1d, 0x00, 0x13)
	if _, _, st := c.Exec(0x05, data, false); st != usCE|usDE {
		t.Fatal(st)
	}
	if err := c.Type("logon maint"); err != nil {
		t.Fatal(err)
	}
	c.aid = AIDEnter
	out, _, _ := c.Exec(0x06, nil, false)
	if out[0] != AIDEnter || out[3] != 0x11 {
		t.Fatalf("read modified %X", out)
	}
	if got := EBCDICString(out[6:]); got != "logon maint" {
		t.Fatalf("field %q", got)
	}
	if _, _, st := c.Exec(0x11, []byte{0, 5, 1, 0xff, 2}, false); st != usCE|usDE {
		t.Fatal("read partition query rejected")
	}
	if out, _, _ := c.Exec(0x06, nil, false); out[0] != 0x88 || out[3] != 0x81 || out[4] != 0x80 {
		t.Fatalf("query reply %X", out)
	}
}

// Guest storage accesses must keep the byte offset within a host page on
// the first (uncached) translation, and instruction interceptions leave the
// guest PSW at the next instruction.
func TestSIEGuestTranslationAndInterception(t *testing.T) {
	code := []byte{0xb2, 0x14, 0x40, 0x00} // SIE 0(4)
	m, c := newTest(t, append(code, stop()...))
	setupStop(m)
	// Host primary space: segment 0 maps pages 0-1 of guest to frames 0x20000-0x21000.
	be.PutUint32(m.S.Mem[0x10000:], 0x00011000|0x0f)
	for i := 1; i < 16; i++ {
		be.PutUint32(m.S.Mem[0x10000+4*i:], 0x20)
	}
	for i := 0; i < 256; i++ {
		be.PutUint32(m.S.Mem[0x11000+4*i:], 0x400)
	}
	be.PutUint32(m.S.Mem[0x11000:], 0x00020000)
	be.PutUint32(m.S.Mem[0x11004:], 0x00021000)
	c.CR[0] = 0x00b00000
	c.CR[1] = 0x00010000
	// Guest code at guest 0x1100: LR 1,1 ; DIAG (intercepted).
	copy(m.S.Mem[0x21100:], []byte{0x18, 0x11, 0x83, 0x00, 0x00, 0x08})
	sd := uint32(0x4000)
	c.GR[4] = sd
	m.S.Mem[sd+3] = 0x20                                 // XA mode
	be.PutUint16(m.S.Mem[sd+10:], 0)                     // extent 64K
	be.PutUint64(m.S.Mem[sd+0x18:], 0x00080000_80001100) // guest PSW
	be.PutUint32(m.S.Mem[sd+0x80:], 0x000000e0)          // guest CR0
	be.PutUint32(m.S.Mem[sd+0x80+14*4:], 0xc2000000)     // guest CR14
	runTo(t, m)
	if m.S.Mem[sd+0x50] != sieCodeInst {
		t.Fatalf("interception code %d", m.S.Mem[sd+0x50])
	}
	if ipa := be.Uint16(m.S.Mem[sd+0x56:]); ipa != 0x8300 {
		t.Fatalf("IPA %04X", ipa)
	}
	if psw := be.Uint64(m.S.Mem[sd+0x18:]); uint32(psw)&0x7fffffff != 0x1106 {
		t.Fatalf("guest PSW %016X", psw)
	}
	if c.PSW.IA != 0x0f00 && c.PSW.Wait == false {
		t.Fatalf("host did not resume after SIE: %s", c.PSW)
	}
}

func TestDisassemble(t *testing.T) {
	text, n := Disassemble([]byte{0x47, 0xf0, 0xc0, 0x0a, 0, 0}, 0x2000)
	if n != 4 || !strings.HasPrefix(text, "BC") || !strings.Contains(text, "X'00A'(0,12)") {
		t.Fatalf("%q %d", text, n)
	}
	text, _ = Disassemble([]byte{0xa7, 0xf4, 0xff, 0xfe, 0, 0}, 0x2000)
	if !strings.Contains(text, "00001FFC") {
		t.Fatalf("relative target %q", text)
	}
}

// dat builds a primary space identity-mapping the first megabyte (segment
// table 0x10000, page table 0x11000) and an empty secondary space (0x12000).
func dat(m *Machine, c *CPU) {
	for i := 0; i < 16; i++ {
		be.PutUint32(m.S.Mem[0x10000+4*i:], 0x20)
		be.PutUint32(m.S.Mem[0x12000+4*i:], 0x20)
	}
	be.PutUint32(m.S.Mem[0x10000:], 0x00011000|0x0f)
	for i := 0; i < 256; i++ {
		be.PutUint32(m.S.Mem[0x11000+4*i:], uint32(i)<<12)
	}
	c.CR[0] = 0x04b00000 // secondary-space control, 4K pages, 1M segments
	c.CR[1] = 0x00010000
	c.CR[7] = 0x00012000
}

func TestMVCSFaultKeepsPSWModeAndIdentifiesSecondarySpace(t *testing.T) {
	// MVCS 0(R2=2,B1=3),0(B2=4),R3=5
	m, c := newTest(t, []byte{0xdb, 0x25, 0x30, 0x00, 0x40, 0x00})
	dat(m, c)
	c.loadPSW(0x04080000_80001000)
	c.GR[2], c.GR[3], c.GR[4], c.GR[5] = 4, 0x00305000, 0x2000, 0
	if r := runTo(t, m); r.Kind != "disabled-wait" {
		t.Fatal(r)
	}
	if code := be.Uint16(m.S.Mem[0x8e:]); code != pgmSegment {
		t.Fatalf("code %04X", code)
	}
	if old := be.Uint32(m.S.Mem[pswPgmOld:]); old&0xc000 != 0 {
		t.Fatalf("old PSW %08X left the primary-space mode", old)
	}
	if teid := be.Uint32(m.S.Mem[0x90:]); teid != 0x00305000|2 {
		t.Fatalf("TEID %08X, want secondary-space 00305002", teid)
	}
}

func TestDATProtectionStoresTEID(t *testing.T) {
	m, c := newTest(t, []byte{0x50, 0x10, 0x50, 0x08}) // ST 1,8(0,5)
	dat(m, c)
	be.PutUint32(m.S.Mem[0x11000+4*6:], 0x6000|0x200) // page 6 protected
	c.loadPSW(0x04080000_80001000)
	c.GR[5] = 0x6000
	runTo(t, m)
	if code := be.Uint16(m.S.Mem[0x8e:]); code != pgmProtection {
		t.Fatalf("code %04X", code)
	}
	if teid := be.Uint32(m.S.Mem[0x90:]); teid != 0x6000|4 {
		t.Fatalf("TEID %08X, want 00006004", teid)
	}
}

func TestCompareAndSwapAndPurgeAddressInR2(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0x50, 0x00, 0x02}, stop()...)) // CSP 0,2
	setupStop(m)
	be.PutUint32(m.S.Mem[0x3000:], 7)
	c.GR[0], c.GR[1], c.GR[2], c.GR[3] = 7, 9, 0x3000|1, 0xdead
	runTo(t, m)
	if v := be.Uint32(m.S.Mem[0x3000:]); v != 9 || cc(c) != 0 {
		t.Fatalf("CSP stored %d cc%d", v, cc(c))
	}
}

func TestStoreFacilityListAndCHSC(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0xb1, 0x00, 0x00, 0xb2, 0x5f, 0x00, 0x20}, stop()...)) // STFL; CHSC 2
	setupStop(m)
	m.Facilities = 0x40000000
	be.PutUint16(m.S.Mem[0x4000:], 16)
	be.PutUint16(m.S.Mem[0x4002:], 0x0010)
	c.GR[2] = 0x4000
	if r := runTo(t, m); r.Kind != "disabled-wait" || be.Uint16(m.S.Mem[0x8e:]) != 0 {
		t.Fatalf("%v program %04X", r, be.Uint16(m.S.Mem[0x8e:]))
	}
	if be.Uint32(m.S.Mem[0xc8:]) != 0x40000000 {
		t.Fatalf("facility list %08X", be.Uint32(m.S.Mem[0xc8:]))
	}
	if be.Uint16(m.S.Mem[0x4012:]) != 0x0004 || cc(c) != 0 {
		t.Fatalf("CHSC response %04X cc%d", be.Uint16(m.S.Mem[0x4012:]), cc(c))
	}
}

func TestSCLPConsoleMessagesAndCommands(t *testing.T) {
	m, c := newTest(t, nil)
	sccb := uint32(0x5000)
	call := func(cmd uint32, b []byte) []byte {
		copy(m.S.Mem[sccb:], b)
		m.serviceSignal = false
		m.sclp.servc(c, cmd, sccb)
		return m.S.Mem[sccb : sccb+uint32(len(b))]
	}
	// Register for operator commands and messages (4-byte masks).
	mask := make([]byte, 28)
	be.PutUint16(mask, 28)
	be.PutUint16(mask[10:], 4)
	be.PutUint32(mask[12:], evMask(evOpCmd))
	be.PutUint32(mask[16:], evMask(evMsg))
	if r := call(sclpWriteEventMask, mask); be.Uint16(r[6:]) != 0x0020 || be.Uint32(r[20:])&evMask(evMsg) == 0 {
		t.Fatalf("event mask response %X", r)
	}
	// A message event: MDB header, then one message-text object.
	text := EncodeEBCDIC500("a[1]!")
	mto := append([]byte{0, byte(10 + len(text)), 0, 4, 0, 0, 0, 0, 0, 0}, text...)
	mdb := append([]byte{0, byte(12 + len(mto)), 0, 1, 0xd4, 0xc4, 0xc2, 0x40, 0, 0, 0, 1}, mto...)
	ev := append([]byte{0, byte(6 + len(mdb)), evMsg, 0, 0, 0}, mdb...)
	wr := append([]byte{0, byte(8 + len(ev)), 0, 0, 0, 0, 0, 0}, ev...)
	if r := call(sclpWriteEventData, wr); be.Uint16(r[6:]) != 0x0020 {
		t.Fatalf("write response %04X", be.Uint16(r[6:]))
	}
	if got := m.ConsoleLines(); len(got) != 1 || got[0] != "a[1]!" {
		t.Fatalf("lines %q", got)
	}
	m.serviceSignal = false
	m.Command("ls -l")
	if !m.serviceSignal || m.serviceParam != 1 {
		t.Fatalf("event-pending signal %v %08X", m.serviceSignal, m.serviceParam)
	}
	rd := make([]byte, 256)
	be.PutUint16(rd, 256)
	r := call(sclpReadEventData, rd)
	if be.Uint16(r[6:]) != 0x0020 || r[10] != evOpCmd {
		t.Fatalf("read response %04X type %02X", be.Uint16(r[6:]), r[10])
	}
	want := EncodeEBCDIC500("ls -l")
	if !strings.Contains(string(r), string(append([]byte{byte(2 + len(want)), 0x30}, want...))) {
		t.Fatalf("command text not in self-defining text message: % X", r[:64])
	}
}

func TestStorageLoadStartsFromPSWAtZero(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	psw := make([]byte, 8)
	be.PutUint64(psw, 0x00080000_80002000)
	code := append([]byte{0xa7, 0x18, 0x00, 0x2a}, stop()...) // LHI 1,42
	if err := m.Load([]Image{{0, psw}, {0x2000, code}}, true); err != nil {
		t.Fatal(err)
	}
	setupStop(m)
	if r := m.Run(1000); r.Kind != "disabled-wait" || m.CPUs[0].GR[1] != 42 {
		t.Fatalf("%v r1=%d", r, m.CPUs[0].GR[1])
	}
}

func TestESAPCIPresentsIntermediateStatus(t *testing.T) {
	code := []byte{
		0xb2, 0x32, 0x30, 0x00, // MSCH 0(3)   enable
		0xb2, 0x33, 0x30, 0x40, // SSCH 64(3)
		0x82, 0x00, 0x0f, 0x10, // LPSW enabled wait
	}
	m, c := newTest(t, code)
	be.PutUint64(m.S.Mem[0xf10:], 0x020A0000_80000000)
	// I/O handler: TSCH, patch the second CCW's data address, wait again.
	be.PutUint64(m.S.Mem[pswIONew:], 0x00080000_80002000)
	copy(m.S.Mem[0x2000:], []byte{
		0xb2, 0x35, 0x30, 0x80, // TSCH 128(3)
		0x92, 0x33, 0x31, 0x0e, // MVI X'310E',X'33': second CCW stores to 0x3300
		0x82, 0x00, 0x0f, 0x10, // LPSW enabled wait
	})
	m.CSS.Attach(0x0190, chainDevice{})
	c.CR[6] = 0x80000000
	c.GR[1] = 0x00010000
	c.GR[3] = 0x3000
	be.PutUint32(m.S.Mem[0x3004:], 1<<23)      // PMCW: enabled
	be.PutUint32(m.S.Mem[0x3044:], 0x00800000) // ORB: format-1 CCWs
	be.PutUint32(m.S.Mem[0x3048:], 0x3100)
	copy(m.S.Mem[0x3100:], []byte{
		0x02, 0x68, 0x00, 0x0a, 0x00, 0x00, 0x32, 0x00, // read 10, CC|SLI|PCI
		0x02, 0x20, 0x00, 0x0a, 0x00, 0x00, 0x34, 0x00, // read 10 to 0x3400 (patched)
	})
	r := m.Run(100000)
	if string(m.S.Mem[0x3300:0x330a]) != "0123456789" {
		t.Fatalf("second CCW ran before the PCI handler patched it (%q, %v, %v)", m.S.Mem[0x3300:0x330a], m.Interrupts, r)
	}
	if irb := be.Uint32(m.S.Mem[0x3080:]); irb&0x1f != scPrimary|scSecondary|1 || m.S.Mem[0x3089]&scsPCI != 0 {
		t.Fatalf("final SCSW %08X subchannel status %02X", irb, m.S.Mem[0x3089])
	}
	if m.Interrupts["io"] != 2 {
		t.Fatalf("interrupts %v: want an intermediate and a final", m.Interrupts)
	}
	// The ORB's format-1 bit stays in the SCSW after the intermediate
	// status is cleared.
	if irb := be.Uint32(m.S.Mem[0x3080:]); irb&0x00800000 == 0 {
		t.Fatalf("final SCSW %08X lost the CCW-format bit", irb)
	}
}

func TestSCLPReadChannelPathInformation(t *testing.T) {
	m, c := newTest(t, nil)
	m.CSS.Attach(0x0700, chainDevice{})
	m.CSS.Attach(0x0a80, chainDevice{})
	sccb := uint32(0x5000)
	be.PutUint16(m.S.Mem[sccb:], 4096)
	m.sclp.servc(c, sclpReadChpInfo, sccb)
	r := m.S.Mem[sccb:]
	if be.Uint16(r[6:]) != 0x0010 {
		t.Fatalf("response %04X", be.Uint16(r[6:]))
	}
	// Recognized at 8 and configured at 72; nothing in standby (40).
	for _, base := range []int{8, 72} {
		if r[base+0] != 0x01 || r[base+1] != 0x20 {
			t.Fatalf("map at %d: %X", base, r[base:base+2])
		}
	}
	if r[40] != 0 || r[41] != 0 {
		t.Fatalf("standby map %X", r[40:42])
	}
}

func TestDASDConfigurationDataIdentifiesDevice(t *testing.T) {
	m, _ := newTest(t, nil)
	a := NewDASD3390(tracks{}, 10)
	b := NewDASD3390(tracks{}, 10)
	m.CSS.Attach(0x0a80, a)
	m.CSS.Attach(0x0a82, b)
	ra, rb := a.rcd(), b.rcd()
	if be.Uint16(ra[30:]) != 0x0a80 || be.Uint16(rb[30:]) != 0x0a82 {
		t.Fatalf("device tags %X %X", ra[30:32], rb[30:32])
	}
	if ra[224] != 0x80 || ra[243] != 0x80 || rb[243] != 0x82 || be.Uint16(ra[232:]) != be.Uint16(rb[232:]) {
		t.Fatalf("NEQ %X / %X", ra[224:256], rb[224:256])
	}
}

// Outside a locate-record domain, a multitrack read under Define Extent
// continues past the last track of a cylinder.
func TestDASDMultitrackReadCrossesCylinderInExtent(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	if _, _, st := d.Exec(0x63, extent(0, 14, 0, 14), true); st != usCE|usDE {
		t.Fatal("define extent", d.Stats.Errors)
	}
	seek := []byte{0, 0, 0, 0, 0, 14}
	if _, _, st := d.Exec(0x07, seek, true); st != usCE|usDE {
		t.Fatal("seek", d.Stats.Errors)
	}
	var got [][]byte
	for i := 0; i < 3; i++ {
		out, _, st := d.Exec(0x86, nil, true)
		if st != usCE|usDE {
			t.Fatal("read", i, d.Stats.Errors)
		}
		got = append(got, out)
	}
	want := [][]byte{{0, 14, 1}, {0, 14, 2}, {1, 0, 1}}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Fatalf("read %d = %v want %v", i, got[i], want[i])
		}
	}
	// Without Define Extent the device reports end of cylinder.
	d = NewDASD3390(volume(), 3)
	d.StartChain()
	d.Exec(0x07, seek, true)
	d.Exec(0x86, nil, true)
	d.Exec(0x86, nil, true)
	if _, _, st := d.Exec(0x86, nil, true); st&usUnitCheck == 0 || d.sense[1]&senseEndOfCyl == 0 {
		t.Fatalf("status %02X sense %X, want end of cylinder", st, d.sense[:2])
	}
}

// The CSP operand is a logical address: with DAT on it is translated.
func TestCompareAndSwapAndPurgeTranslatesOperand(t *testing.T) {
	m, c := newTest(t, nil)
	dat(m, c)
	copy(m.S.Mem[0x1000:], []byte{0xb2, 0x50, 0x00, 0x02}) // CSP 0,2
	copy(m.S.Mem[0x1004:], stop())
	setupStop(m)
	be.PutUint32(m.S.Mem[0x11000+4*5:], 0x7000) // virtual page 5 -> real 7000
	be.PutUint32(m.S.Mem[0x7010:], 7)
	c.loadPSW(0x04080000_80001000)
	c.GR[0], c.GR[1], c.GR[2] = 7, 9, 0x5010|1
	runTo(t, m)
	if v := be.Uint32(m.S.Mem[0x7010:]); v != 9 || cc(c) != 0 {
		t.Fatalf("CSP stored %d at real 7010, cc%d", v, cc(c))
	}
	if v := be.Uint32(m.S.Mem[0x5010:]); v != 0 {
		t.Fatalf("CSP stored %d at real 5010", v)
	}
}

// pcTables builds a primary ASTE (CR5) whose linkage table has LX 0 with
// an entry table of one 32-byte entry at EX 0.
func pcTables(m *Machine, c *CPU, ete [8]uint32) {
	c.CR[0] |= 0x00010000                                // ASF
	c.CR[5] = 0x8000                                     // primary ASTE
	be.PutUint32(m.S.Mem[0x8000+12:], 0x80000000|0x8100) // LTD: V, LTO 8100, LTL 0
	be.PutUint32(m.S.Mem[0x8100:], 0x8200)               // LTE: ETO 8200, ETL 0
	for i, w := range ete {
		be.PutUint32(m.S.Mem[0x8200+4*uint32(i):], w)
	}
}

func TestBasicProgramCallToCurrentPrimary(t *testing.T) {
	m, c := newTest(t, nil)
	dat(m, c)
	copy(m.S.Mem[0x1000:], []byte{0xb2, 0x18, 0x00, 0x00}) // PC 0
	copy(m.S.Mem[0x2000:], stop())
	setupStop(m)
	pcTables(m, c, [8]uint32{0xffff0000, 0x80002000, 0x12345678, 0x40000000})
	c.CR[3] = 0x80000000 | 5 // PKM key 0, SASN 5
	c.CR[4] = 7              // PASN 7
	c.loadPSW(0x04080000_80001000)
	runTo(t, m)
	if c.GR[4] != 0x12345678 || c.GR[14] != 0x80001004 || c.GR[3] != 0x80000007 {
		t.Fatalf("GR3 %08X GR4 %08X GR14 %08X", c.GR[3], c.GR[4], c.GR[14])
	}
	if c.CR[3] != 0xc0000007 || c.CR[7] != c.CR[1] {
		t.Fatalf("CR3 %08X (want EKM ORed, SASN = PASN) CR7 %08X", c.CR[3], c.CR[7])
	}
}

func TestStackingProgramCallAndProgramReturn(t *testing.T) {
	m, c := newTest(t, nil)
	dat(m, c)
	copy(m.S.Mem[0x1000:], []byte{0xb2, 0x18, 0x00, 0x00}) // PC 0
	copy(m.S.Mem[0x1004:], stop())
	copy(m.S.Mem[0x2000:], []byte{0x01, 0x01}) // PR
	setupStop(m)
	// T (stacking), key control with entry key 3.
	pcTables(m, c, [8]uint32{0xffff0000, 0x80002000, 0x55, 0, 0x90300000})
	c.CR[13] = c.CR[1]
	c.CR[3], c.CR[4] = 7, 7 // SASN = PASN: PR needs no ASN translation
	// Linkage stack: header at 0x9000 with room for one state entry, then
	// a trailer.
	be.PutUint32(m.S.Mem[0x9008:], 0x01000000|lsStateSize)
	c.CR[15] = 0x9008
	c.GR[2], c.GR[4] = 0x22, 0x44
	c.loadPSW(0x04080000_80001000)
	runTo(t, m)
	if c.CR[15] != 0x9008 || c.GR[2] != 0x22 || c.GR[4] != 0x44 || c.PSW.Key != 0 {
		t.Fatalf("after PR: CR15 %08X GR2 %X GR4 %X key %d pgm %04X", c.CR[15], c.GR[2], c.GR[4], c.PSW.Key, be.Uint16(m.S.Mem[0x8e:]))
	}
	if typ := m.S.Mem[0x9008+8+160]; typ != lsPCState {
		t.Fatalf("state entry type %02X", typ)
	}
	if num := be.Uint32(m.S.Mem[0x9010+148:]); num != 0 {
		t.Fatalf("stacked PC number %X", num)
	}
}

func TestProgramTransferToCurrentPrimary(t *testing.T) {
	m, c := newTest(t, nil)
	dat(m, c)
	copy(m.S.Mem[0x1000:], []byte{0xb2, 0x28, 0x00, 0x23}) // PT 2,3
	copy(m.S.Mem[0x3000:], stop())
	setupStop(m)
	pcTables(m, c, [8]uint32{})
	c.CR[3] = 0xc0000005
	c.CR[4] = 7
	c.loadPSW(0x04080000_80001000)
	c.GR[2], c.GR[3] = 0x80000007, 0x80003000
	runTo(t, m)
	if c.CR[3] != 0x80000007 || c.CR[7] != c.CR[1] {
		t.Fatalf("CR3 %08X (want PKM ANDed, SASN 7) CR7 %08X", c.CR[3], c.CR[7])
	}
	if be.Uint16(m.S.Mem[0x8e:]) != 0 && c.PSW.IA != 0 {
		t.Fatalf("program check %04X", be.Uint16(m.S.Mem[0x8e:]))
	}
}

// WRITE CKD NEXT TRACK (format write within a locate-record domain) puts
// the record after R0 of the following track: JES2 formats spool tracks
// this way and later orients on that record.
func TestDASDWriteCKDNextTrack(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	d.Exec(0x63, append([]byte{0xc0}, extent(0, 0, 2, 14)[1:]...), true)
	if _, _, st := d.Exec(0x47, locate(0x03, 2, 0, 3, 0), true); st != usCE|usDE {
		t.Fatal("locate", d.Stats.Errors)
	}
	rec := func(h uint16, r byte) []byte {
		b := []byte{0, 0, 0, byte(h), r, 0, 0, 1, 0xee}
		return b
	}
	if _, _, st := d.Exec(0x1d, rec(3, 1), true); st != usCE|usDE {
		t.Fatal("write", d.Stats.Errors)
	}
	if _, _, st := d.Exec(0x9d, rec(4, 1), false); st != usCE|usDE {
		t.Fatal("write next track", d.Stats.Errors)
	}
	t3, _ := d.writable(3)
	t4, _ := d.writable(4)
	if len(t3) != 2 || len(t4) != 2 || t4[1].Head != 4 || t4[1].Number != 1 || t4[0].Number != 0 {
		t.Fatalf("track 3 %d records, track 4 %v", len(t3), t4)
	}
}

// READ COUNT in a locate-record domain skips record zero of the next track.
func TestDASDLocateReadCountSkipsRecordZeroOnNextTrack(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	d.Exec(0x63, extent(0, 0, 2, 14), true)
	if _, _, st := d.Exec(0x47, locate(0x06, 4, 0, 3, 1), true); st != usCE|usDE {
		t.Fatal("locate", d.Stats.Errors)
	}
	d.Exec(0x86, nil, true) // record 1
	var got []byte
	for i := 0; i < 2; i++ {
		c, _, st := d.Exec(0x92, nil, true)
		if st != usCE|usDE {
			t.Fatal("read count", i, d.Stats.Errors)
		}
		got = append(got, c[3], c[4])
		d.Exec(0x86, nil, true)
	}
	if string(got) != string([]byte{3, 2, 4, 1}) {
		t.Fatalf("counts read %v, want 3/2 then 4/1", got)
	}
}

// LAM translates its operand with the access registers it started with,
// even when the base register's AR is among those loaded.
func TestLoadAccessMultipleUsesOriginalBaseAR(t *testing.T) {
	m, c := newTest(t, nil)
	dat(m, c)
	c.CR[0] |= 0x00010000
	copy(m.S.Mem[0x1000:], []byte{0x9a, 0xe1, 0xf0, 0x00}) // LAM 14,1,0(15)
	copy(m.S.Mem[0x1004:], stop())
	setupStop(m)
	for i, v := range []uint32{0x14, 0x7f000000, 0x10, 0x11} { // AR15 gets an invalid ALET
		be.PutUint32(m.S.Mem[0x3000+4*i:], v)
	}
	c.loadPSW(0x04084000_80001000) // AR mode
	c.GR[15] = 0x3000
	runTo(t, m)
	if code := be.Uint16(m.S.Mem[0x8e:]); code != 0 {
		t.Fatalf("program check %04X", code)
	}
	if c.AR[14] != 0x14 || c.AR[15] != 0x7f000000 || c.AR[0] != 0x10 || c.AR[1] != 0x11 {
		t.Fatalf("ARs %X %X %X %X", c.AR[14], c.AR[15], c.AR[0], c.AR[1])
	}
}

// Locate operation WRITE TRACK (0x0B) orients on record zero: WRITE DATA
// rewrites R0 and the following WRITE CKD replaces the rest of the track.
func TestDASDLocateWriteTrack(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	d.Exec(0x63, append([]byte{0xc0}, extent(0, 0, 2, 14)[1:]...), true)
	if _, _, st := d.Exec(0x47, locate(0x0b, 2, 0, 5, 0), true); st != usCE|usDE {
		t.Fatal("locate", d.Stats.Errors)
	}
	if _, used, st := d.Exec(0x05, make([]byte, 8), true); st != usCE|usDE || used != 8 {
		t.Fatal("write R0 data", used, d.Stats.Errors)
	}
	if _, _, st := d.Exec(0x1d, []byte{0, 0, 0, 5, 1, 0, 0, 2, 0xab, 0xcd}, false); st != usCE|usDE {
		t.Fatal("write CKD", d.Stats.Errors)
	}
	r, _ := d.writable(5)
	if len(r) != 2 || r[0].Number != 0 || r[1].Number != 1 || len(r[1].Data) != 2 {
		t.Fatalf("track 5: %v", r)
	}
}

type eofDevice struct{}

func (eofDevice) SenseID() []byte { return nil }
func (eofDevice) Reset()          {}
func (eofDevice) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	return nil, 0, usCE | usDE | usUnitExcept
}

// A unit exception on a PCI-flagged CCW ends the program with alert status,
// the PCI condition merged into the subchannel status, and the last path
// used named in the extended-status word.
func TestUnitExceptionStatusIsAlertWithPCIAndPath(t *testing.T) {
	m, c := newTest(t, nil)
	m.CSS.Attach(0x0190, eofDevice{})
	x := m.CSS.bydev[0x0190]
	x.enabled = true
	copy(m.S.Mem[0x3100:], []byte{0x06, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00}) // read, PCI|SLI, count 0
	x.fc = fcStart
	m.CSS.start(x, 0x3100, 0x00800000)
	c.GR[1] = 0x00010000 | uint32(x.num)
	c.tsch(0x4000, 0)
	irb := m.S.Mem[0x4000:]
	if irb[3]&scAlert == 0 || irb[9]&scsPCI == 0 || irb[8]&usUnitExcept == 0 {
		t.Fatalf("SCSW % X", irb[:12])
	}
	if irb[13] != 0x80 {
		t.Fatalf("ESW LPUM %02X", irb[13])
	}
}

// SET SECONDARY ASN to another space takes the SSTD from that space's ASTE.
func TestSetSecondaryASNSpaceSwitching(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0x25, 0x00, 0x30}, stop()...)) // SSAR 3
	setupStop(m)
	c.loadPSW(0x04080000_80001000)
	dat(m, c)
	c.loadPSW(0x04080000_80001000)
	c.CR[14] = 0x00080000 | 0x5                // ASN translation, AFT at 0x5000
	be.PutUint32(m.S.Mem[0x5000:], 0x6000)     // AFTE for ASN 0-63 -> AST at 0x6000
	aste := uint32(0x6000 + 2*64)              // ASN 2
	be.PutUint32(m.S.Mem[aste:], 0x7000)       // ATO 0x7000
	be.PutUint32(m.S.Mem[aste+4:], 0x00000010) // ATL covers AX 0-15
	be.PutUint32(m.S.Mem[aste+8:], 0x00042000) // STD of ASN 2
	m.S.Mem[0x7000] = 0x40                     // AX 0 secondary-authorized
	c.CR[4] = 1                                // PASN 1, AX 0
	c.GR[3] = 2
	runTo(t, m)
	if code := be.Uint16(m.S.Mem[0x8e:]); code != 0 {
		t.Fatalf("program check %04X", code)
	}
	if uint16(c.CR[3]) != 2 || c.CR[7] != 0x00042000 {
		t.Fatalf("CR3 %08X CR7 %08X", c.CR[3], c.CR[7])
	}
}

// IVSK is allowed in the problem state under the extraction-authority
// control; additional floating-point registers with the AFP-register
// control off give a data exception with DXC 1.
func TestExtractionAuthorityAndAFPDataException(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0x23, 0x00, 0x23, 0x60, 0x80, 0x30, 0x00}, stop()...)) // IVSK 2,3; STD 8,0(3)
	setupStop(m)
	dat(m, c)
	c.CR[0] |= 0x08000000          // extraction authority
	c.CR[3] = 0x80000000           // PKM allows key 0
	c.loadPSW(0x04090000_80001000) // problem state
	c.GR[3] = 0x3000
	runTo(t, m)
	if code := be.Uint16(m.S.Mem[0x8e:]); code != pgmData || m.S.Mem[0x93] != 1 {
		t.Fatalf("program check %04X DXC %02X, want data exception DXC 1 at STD 8", code, m.S.Mem[0x93])
	}
	if old := be.Uint32(m.S.Mem[pswPgmOld+4:]) & 0x7fffffff; old != 0x1008 {
		t.Fatalf("old PSW at %X, want past the suppressed STD", old)
	}
}

// A locate-record read domain may not leave the defined extent: reading
// past the last record of a one-track extent ends with a file-protect
// check (the end of the extent), not a record from the next track.
func TestDASDLocateDomainStopsAtExtentEnd(t *testing.T) {
	d := NewDASD3390(volume(), 3)
	d.StartChain()
	d.Exec(0x63, extent(1, 4, 1, 4), true)
	d.Exec(0x47, locate(0x06, 3, 1, 4, 1), true)
	for i := 1; i <= 2; i++ {
		out, _, st := d.Exec(0x06, make([]byte, 8), true)
		if st != usCE|usDE || out[2] != byte(i) {
			t.Fatalf("read %d: status %X data %X", i, st, out)
		}
	}
	if _, _, st := d.Exec(0x06, make([]byte, 8), false); st&usUnitCheck == 0 {
		t.Fatalf("read past the extent: status %X", st)
	}
	if sense, _, _ := d.Exec(0x04, make([]byte, 32), false); sense[1]&senseFileProtect == 0 || sense[27]&0x80 == 0 {
		t.Fatalf("sense %X", sense[:4])
	}
}
