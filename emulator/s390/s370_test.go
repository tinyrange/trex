package s390

import (
	"testing"
	"time"
)

// newTest370 returns a System/370 machine running BC-mode code at 0x1000
// whose new PSWs at 0x58-0x78 are disabled waits.
func newTest370(t *testing.T, code []byte) (*Machine, *CPU) {
	t.Helper()
	m := NewMachine(Config{Memory: 1 << 20, S370: true, Start: time.Date(1985, 8, 30, 12, 0, 0, 0, time.UTC)})
	c := m.CPUs[0]
	copy(m.S.Mem[0x1000:], code)
	for _, a := range []int{pswExtNew, pswSVCNew, pswPgmNew, pswIONew} {
		be.PutUint64(m.S.Mem[a:], 0x00020000_0000DEAD) // BC disabled wait
	}
	be.PutUint64(m.S.Mem[0xf00:], 0x00020000_00000000)
	c.Stopped = false
	c.loadPSW(0x00000000_00001000)
	return m, c
}

func TestS370BCModeKeepsInterruptionCodeInPSW(t *testing.T) {
	m, c := newTest370(t, []byte{0x0a, 0x2a}) // SVC 42
	if r := m.Run(100); r.Kind != "disabled-wait" {
		t.Fatal(r)
	}
	old := m.S.Mem[pswSVCOld : pswSVCOld+8]
	if be.Uint16(old[2:]) != 42 || old[4]>>6 != 1 || be.Uint32(old[4:])&0xffffff != 0x1002 {
		t.Fatalf("SVC old PSW % X", old)
	}
	if be.Uint32(m.S.Mem[0x88:]) != 0 {
		t.Fatalf("BC mode stored the SVC code at 0x88: % X", m.S.Mem[0x88:0x8c])
	}
	_ = c
}

func TestS370TranslationTwoBytePageTable(t *testing.T) {
	m, c := newTest370(t, nil)
	c.CR[0] = 0x00800000 // 4K pages, 64K segments
	c.CR[1] = 0x00010000 // STL 0 (16 segments), STO 0x10000
	for i := 0; i < 16; i++ {
		be.PutUint32(m.S.Mem[0x10000+4*i:], 1) // invalid
	}
	be.PutUint32(m.S.Mem[0x10000:], 0xf0000000|0x11000)
	for i := 0; i < 16; i++ {
		be.PutUint16(m.S.Mem[0x11000+2*i:], 0x0008) // invalid
	}
	be.PutUint16(m.S.Mem[0x11006:], 0x7<<4) // page 3 -> frame 0x7000
	if real, _ := c.translate(0x3abc, c.CR[1], accFetch); real != 0x7abc {
		t.Fatalf("real %X", real)
	}
	for _, tc := range []struct {
		v    uint32
		code uint16
	}{{0x4000, pgmPage}, {0x10000, pgmSegment}} {
		func() {
			defer func() {
				if pc, ok := recover().(programCheck); !ok || pc.code != tc.code {
					t.Fatalf("%X: got %v, want code %X", tc.v, pc, tc.code)
				}
			}()
			c.translate(tc.v, c.CR[1], accFetch)
		}()
	}
}

func TestS370StartIOAndInterruption(t *testing.T) {
	code := []byte{
		0x9c, 0x00, 0x00, 0x0e, // SIO 00E
		0x82, 0x00, 0x0f, 0x10, // LPSW enabled wait (channel 0)
	}
	m, _ := newTest370(t, code)
	be.PutUint64(m.S.Mem[0xf10:], 0x80020000_00000000)
	if _, err := m.CSS.Attach(0x000e, &fakeDevice{data: []byte("HELLO")}); err != nil {
		t.Fatal(err)
	}
	be.PutUint32(m.S.Mem[0x48:], 0x3100)                                           // CAW
	copy(m.S.Mem[0x3100:], []byte{0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x05}) // read 5 to 0x3200
	if r := m.Run(1000); r.Kind != "disabled-wait" {
		t.Fatal(r)
	}
	if string(m.S.Mem[0x3200:0x3205]) != "HELLO" {
		t.Fatalf("data %q", m.S.Mem[0x3200:0x3205])
	}
	if be.Uint16(m.S.Mem[pswIOOld+2:]) != 0x000e {
		t.Fatalf("I/O old PSW % X", m.S.Mem[pswIOOld:pswIOOld+8])
	}
	if csw := be.Uint64(m.S.Mem[0x40:]); csw != 0x00003108_0C000000 {
		t.Fatalf("CSW %016X", csw)
	}
	if be.Uint16(m.S.Mem[0xba:]) != 0 {
		t.Fatal("BC mode stored the I/O address at 186")
	}
}

func TestS370IntervalTimerInterrupts(t *testing.T) {
	m, _ := newTest370(t, []byte{0x82, 0x00, 0x0f, 0x10}) // LPSW enabled wait (external)
	be.PutUint64(m.S.Mem[0xf10:], 0x01020000_00000000)
	be.PutUint32(m.S.Mem[0x50:], 0x100) // 256 units of 1/76800 s
	if r := m.Run(10000000); r.Kind != "disabled-wait" {
		t.Fatal(r)
	}
	if code := be.Uint16(m.S.Mem[pswExtOld+2:]); code != 0x0080 {
		t.Fatalf("external code %04X", code)
	}
	if v := int32(be.Uint32(m.S.Mem[0x50:])); v >= 0 {
		t.Fatalf("timer %d not negative", v)
	}
}

func TestS370ConsoleReadWaitsForOperator(t *testing.T) {
	code := []byte{
		0x9c, 0x00, 0x00, 0x1f, // SIO 01F
		0x9d, 0x00, 0x00, 0x1f, // TIO 01F
		0xb2, 0x22, 0x00, 0x40, // IPM 4
	}
	m, c := newTest370(t, append(code, stop()...))
	lc := NewConsole3215()
	lc.css, lc.devno = m.CSS, 0x1f
	if _, err := m.CSS.Attach(0x1f, lc); err != nil {
		t.Fatal(err)
	}
	be.PutUint32(m.S.Mem[0x48:], 0x3100)
	copy(m.S.Mem[0x3100:], []byte{0x0a, 0x00, 0x32, 0x00, 0x20, 0x00, 0x00, 0x10}) // read inquiry, SLI
	m.Run(1000)
	if c.GR[4]>>28 != 2 {
		t.Fatalf("TIO during a waiting read: cc %d, want busy", c.GR[4]>>28)
	}
	lc.Type("hi")
	if string(EBCDICString(m.S.Mem[0x3200:0x3202])) != "hi" {
		t.Fatalf("read data % X", m.S.Mem[0x3200:0x3202])
	}
	if x := m.CSS.bydev[0x1f]; !x.pending || x.devStatus != usCE|usDE {
		t.Fatalf("completion not pending: %v %02X", x.pending, x.devStatus)
	}
}

func TestDASDSearchesRecordZeroAndEndsKeySearch(t *testing.T) {
	d := NewDASD(FormattedVolume{Heads: 19, Volser: "TEST01"}, 0x3330, 10, 19)
	if _, _, st := d.Exec(0x07, []byte{0, 0, 0, 1, 0, 0}, true); st != usCE|usDE {
		t.Fatalf("seek %02X", st)
	}
	if _, _, st := d.Exec(0x31, []byte{0, 1, 0, 0, 0}, true); st&usSM == 0 {
		t.Fatalf("search ID equal for record zero: %02X", st)
	}
	// A key search on a track holding only record zero ends with no record
	// found instead of looping.
	d.Exec(0x07, []byte{0, 0, 0, 1, 0, 0}, true)
	for i := 0; i < 8; i++ {
		_, _, st := d.Exec(0x29, []byte("VOL1"), true)
		if st&usUnitCheck != 0 {
			if d.sense[1]&senseNoRecord == 0 {
				t.Fatalf("sense % X", d.sense[:4])
			}
			return
		}
		if st&usSM != 0 {
			t.Fatal("search key matched a keyless record")
		}
	}
	t.Fatal("search key never reached the index point twice")
}

type memReader []byte

func (b memReader) Size() int64 { return int64(len(b)) }
func (b memReader) ReadAt(p []byte, off int64) (int, error) {
	return copy(p, b[off:]), nil
}

func TestAWSTapeBlocksAndMarks(t *testing.T) {
	img := []byte{3, 0, 0, 0, 0xa0, 0, 'A', 'B', 'C', 0, 0, 3, 0, 0x40, 0, 2, 0, 0, 0, 0xa0, 0, 'D', 'E'}
	tp, err := MountAWS(memReader(img))
	if err != nil {
		t.Fatal(err)
	}
	if out, _, st := tp.Exec(0x02, nil, false); string(out) != "ABC" || st != usCE|usDE {
		t.Fatalf("block 1 %q %02X", out, st)
	}
	if _, _, st := tp.Exec(0x02, nil, false); st&usUnitExcept == 0 {
		t.Fatalf("tape mark status %02X", st)
	}
	if out, _, _ := tp.Exec(0x02, nil, false); string(out) != "DE" {
		t.Fatalf("block 2 %q", out)
	}
	tp.Exec(0x07, nil, false) // rewind
	tp.Exec(0x3f, nil, false) // forward space file
	if out, _, _ := tp.Exec(0x02, nil, false); string(out) != "DE" {
		t.Fatalf("after FSF %q", out)
	}
}

func TestDASDFileMaskInhibitsMultitrack(t *testing.T) {
	d := NewDASD(FormattedVolume{Heads: 30, Volser: "MVSRES"}, 0x3350, 10, 30)
	d.StartChain()
	d.Exec(0x07, []byte{0, 0, 0, 1, 0, 0}, true)
	d.Exec(0x1f, []byte{0x18}, true) // seek and multitrack inhibited
	for i := 0; i < 4; i++ {
		_, _, st := d.Exec(0x92, nil, true) // read count, multitrack
		if st&usUnitCheck != 0 {
			if d.sense[1]&senseFileProtect == 0 {
				t.Fatalf("sense % X, want file protected", d.sense[:2])
			}
			return
		}
	}
	t.Fatal("multitrack read crossed the track despite the file mask")
}

// chainDevice returns 10 bytes for reads.
type chainDevice struct{}

func (chainDevice) SenseID() []byte { return nil }
func (chainDevice) Reset()          {}
func (chainDevice) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	return []byte("0123456789"), 0, usCE | usDE
}

func TestDataChainSkipAndResidualPerCCW(t *testing.T) {
	m, _ := newTest370(t, []byte{0x9c, 0x00, 0x00, 0x0e, 0x9d, 0x00, 0x00, 0x0e})
	m.CSS.Attach(0x000e, chainDevice{})
	be.PutUint32(m.S.Mem[0x48:], 0x3100)
	// Read: 3 bytes skipped (CD|skip), then 20 bytes to 0x3200 (SLI).
	copy(m.S.Mem[0x3100:], []byte{0x02, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x03,
		0x02, 0x00, 0x32, 0x00, 0x20, 0x00, 0x00, 0x14})
	m.Run(10)
	if got := string(m.S.Mem[0x3200:0x3207]); got != "3456789" {
		t.Fatalf("stored %q: skip applied to the wrong CCW", got)
	}
	csw := be.Uint64(m.S.Mem[0x40:])
	if addr, resid := uint32(csw>>32)&0xffffff, uint16(csw); addr != 0x3110 || resid != 13 {
		t.Fatalf("CSW %016X: want CCW 3110 residual 13", csw)
	}
}

func TestConsole3270ReadBufferFromBufferAddress(t *testing.T) {
	c := NewConsole3270(24, 80)
	// Erase/write: protected text, an unprotected field at row 1, then
	// erase-all-unprotected and a write that ends at row 1.
	c.Exec(0x05, append([]byte{0xc3, 0x1d, 0x20}, append(EncodeEBCDIC("HI"), 0x11, 0xc1, 0x50, 0x1d, 0x40)...), false)
	c.Exec(0x0f, nil, false)
	if c.cursor != 81 {
		t.Fatalf("EAU cursor %d, want the first unprotected position 81", c.cursor)
	}
	c.Type("GO")
	c.Exec(0x01, []byte{0xc3, 0x11, 0xc1, 0x50}, false) // SBA row 1 col 0
	out, _, _ := c.Exec(0x02, nil, false)
	if len(out) < 6 || out[3] != 0x1d || EBCDICString(out[5:7]) != "GO" {
		t.Fatalf("read buffer % X", out[:min(len(out), 8)])
	}
}

func TestS370PCIPausesChannelProgram(t *testing.T) {
	code := []byte{
		0x9c, 0x00, 0x00, 0x0e, // SIO 00E
		0x82, 0x00, 0x0f, 0x10, // LPSW enabled wait (channel 0)
	}
	m, c := newTest370(t, code)
	be.PutUint64(m.S.Mem[0xf10:], 0x80020000_00000000)
	// I/O new PSW: the handler patches the second CCW's address, then
	// waits again.
	be.PutUint64(m.S.Mem[pswIONew:], 0x00000000_00002000)
	copy(m.S.Mem[0x2000:], []byte{
		0x92, 0x33, 0x08, 0x0a, // MVI 0x80A,X'33': second CCW reads to 0x3300
		0x82, 0x00, 0x0f, 0x10, // LPSW enabled wait
	})
	m.CSS.Attach(0x000e, chainDevice{})
	be.PutUint32(m.S.Mem[0x48:], 0x800)
	copy(m.S.Mem[0x800:], []byte{
		0x02, 0x00, 0x32, 0x00, 0x68, 0x00, 0x00, 0x0a, // read 10, CC|SLI|PCI
		0x02, 0x00, 0x34, 0x00, 0x20, 0x00, 0x00, 0x0a, // read 10 to 0x3400 (patched)
	})
	m.Run(100000)
	if string(m.S.Mem[0x3300:0x330a]) != "0123456789" {
		t.Fatalf("second CCW ran before the PCI handler patched it (%q)", m.S.Mem[0x3300:0x330a])
	}
	if m.Interrupts["io-pci"] != 1 || m.Interrupts["io"] != 1 {
		t.Fatalf("interrupts %v", m.Interrupts)
	}
	_ = c
}

func TestLDLVolumeLayout(t *testing.T) {
	part := make([]byte, 20*4096)
	copy(part[4096:], "block-1")
	v := LDLVolume{Data: memReader(part), Volser: "LNX001"}
	recs, _ := v.Track(0)
	if len(recs) != 13 || recs[0].Number != 0 || len(recs[1].Data) != 4096 || len(recs[1].Key) != 0 {
		t.Fatalf("track 0: %d records", len(recs))
	}
	if EBCDICString(recs[3].Data[:10]) != "LNX1LNX001" {
		t.Fatalf("label %q", EBCDICString(recs[3].Data[:10]))
	}
	// Partition block 1 is volume block 4: track 0, record 5.
	if string(recs[5].Data[:7]) != "block-1" {
		t.Fatalf("partition block 1 at %q", recs[5].Data[:7])
	}
	if LDLBlocks(100) != 100*15*12-3 {
		t.Fatal(LDLBlocks(100))
	}
}

func TestPerformLockedOperation(t *testing.T) {
	// PLO 2,0(4),6,0(5) with function code in GR0.
	code := append([]byte{0xee, 0x26, 0x40, 0x00, 0x50, 0x00}, stop()...)
	run := func(fc uint32, setup func(m *Machine, c *CPU)) (*Machine, *CPU) {
		m, c := newTest(t, code)
		setupStop(m)
		c.GR[0] = fc
		c.GR[4], c.GR[5] = 0x3000, 0x3100
		setup(m, c)
		if r := runTo(t, m); r.Kind != "disabled-wait" || be.Uint16(m.S.Mem[0x8e:]) != 0 {
			t.Fatalf("fc %d: %v program %04X", fc, r, be.Uint16(m.S.Mem[0x8e:]))
		}
		return m, c
	}
	// Double compare and swap: both equal.
	m, c := run(8, func(m *Machine, c *CPU) {
		be.PutUint32(m.S.Mem[0x3000:], 1)
		be.PutUint32(m.S.Mem[0x3100:], 2)
		c.GR[2], c.GR[3], c.GR[6], c.GR[7] = 1, 10, 2, 20
	})
	if be.Uint32(m.S.Mem[0x3000:]) != 10 || be.Uint32(m.S.Mem[0x3100:]) != 20 || cc(c) != 0 {
		t.Fatalf("DCS stored %d %d cc%d", be.Uint32(m.S.Mem[0x3000:]), be.Uint32(m.S.Mem[0x3100:]), cc(c))
	}
	// Second comparison unequal: cc2, the fourth operand is loaded.
	m, c = run(8, func(m *Machine, c *CPU) {
		be.PutUint32(m.S.Mem[0x3000:], 1)
		be.PutUint32(m.S.Mem[0x3100:], 99)
		c.GR[2], c.GR[3], c.GR[6], c.GR[7] = 1, 10, 2, 20
	})
	if cc(c) != 2 || c.GR[6] != 99 || be.Uint32(m.S.Mem[0x3000:]) != 1 {
		t.Fatalf("DCS mismatch cc%d r6=%d", cc(c), c.GR[6])
	}
	// Compare and swap and double store through the parameter list.
	m, c = run(16, func(m *Machine, c *CPU) {
		be.PutUint32(m.S.Mem[0x3000:], 5)
		c.GR[2], c.GR[3] = 5, 6
		pl := m.S.Mem[0x3100:]
		be.PutUint32(pl[60:], 0xaaaa)
		be.PutUint32(pl[76:], 0x3400)
		be.PutUint32(pl[92:], 0xbbbb)
		be.PutUint32(pl[108:], 0x3404)
	})
	if be.Uint32(m.S.Mem[0x3000:]) != 6 || be.Uint32(m.S.Mem[0x3400:]) != 0xaaaa || be.Uint32(m.S.Mem[0x3404:]) != 0xbbbb || cc(c) != 0 {
		t.Fatalf("CSDST cc%d", cc(c))
	}
	// Test bit: a 64-bit-register function code is not installed.
	_, c = run(0x100|6, func(m *Machine, c *CPU) {})
	if cc(c) != 3 {
		t.Fatalf("test of function 6: cc%d", cc(c))
	}
}

func TestCompareUntilSubstringEqual(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0x57, 0x00, 0x24}, stop()...)) // CUSE 2,4
	setupStop(m)
	copy(m.S.Mem[0x3000:], "abcXYZde")
	copy(m.S.Mem[0x3100:], "qqqXYZzz")
	c.GR[0], c.GR[1] = 3, ' '
	c.GR[2], c.GR[3], c.GR[4], c.GR[5] = 0x3000, 8, 0x3100, 8
	runTo(t, m)
	if cc(c) != 0 || c.GR[2] != 0x3003 || c.GR[3] != 5 || c.GR[4] != 0x3103 {
		t.Fatalf("cc%d r2=%X r3=%d r4=%X", cc(c), c.GR[2], c.GR[3], c.GR[4])
	}
}

func TestUnicodeUTF8Conversions(t *testing.T) {
	m, c := newTest(t, append([]byte{0xb2, 0xa6, 0x00, 0x24}, stop()...)) // CUUTF 2,4
	setupStop(m)
	src := []byte{0x00, 'A', 0x00, 0xe9, 0x20, 0xac, 0xd8, 0x3d, 0xde, 0x00} // A é € U+1F600
	copy(m.S.Mem[0x3000:], src)
	c.GR[2], c.GR[3], c.GR[4], c.GR[5] = 0x3100, 64, 0x3000, uint32(len(src))
	c.GR[6], c.GR[7] = 0x3200, 64
	runTo(t, m)
	want := "A\u00e9\u20ac\U0001F600"
	if got := string(m.S.Mem[0x3100 : 0x3100+len(want)]); got != want || c.GR[2] != 0x3100+uint32(len(want)) {
		t.Fatalf("UTF-8 %q", got)
	}
	m2, c2 := newTest(t, append([]byte{0xb2, 0xa7, 0x00, 0x64}, stop()...))
	setupStop(m2)
	copy(m2.S.Mem[0x3100:], want)
	c2.GR[6], c2.GR[7], c2.GR[4], c2.GR[5] = 0x3200, 64, 0x3100, uint32(len(want))
	runTo(t, m2)
	if got := m2.S.Mem[0x3200 : 0x3200+len(src)]; string(got) != string(src) || cc(c2) != 0 {
		t.Fatalf("UTF-16 % X cc%d", got, cc(c2))
	}
}

func TestLinkageStackBranchAndReturn(t *testing.T) {
	code := append([]byte{0xb2, 0x40, 0x00, 0x0f}, stop()...) // BAKR 0,15; stop
	m, c := newTest(t, code)
	setupStop(m)
	dat(m, c)
	c.CR[0] |= 0x00010000 // address-space-function control
	c.CR[13] = c.CR[1]    // home space = primary
	// Header entry at 0x5000 (descriptor at 0x5008): 0x1000 bytes free.
	be.PutUint32(m.S.Mem[0x5008:], uint32(lsHeader)<<24|0x00420000|0x1000)
	c.CR[15] = 0x5008
	copy(m.S.Mem[0x1100:], []byte{0xa7, 0x28, 0x00, 0x63, 0xb2, 0x4a, 0x00, 0x46, 0x01, 0x01}) // LHI 2,99; ESTA 4,6; PR
	c.loadPSW(0x04080000_80001000)
	c.GR[2], c.GR[6], c.GR[15] = 7, 1, 0x80001100
	if r := runTo(t, m); r.Kind != "disabled-wait" || be.Uint16(m.S.Mem[0x8e:]) != 0 {
		t.Fatalf("%v program %04X", r, be.Uint16(m.S.Mem[0x8e:]))
	}
	if c.GR[2] != 7 {
		t.Fatalf("PR did not restore GR2: %d", c.GR[2])
	}
	if c.CR[15] != 0x5008 || be.Uint16(m.S.Mem[0x500c:]) != 0 {
		t.Fatalf("CR15 %08X, header next-entry size %d", c.CR[15], be.Uint16(m.S.Mem[0x500c:]))
	}
	// The state entry was formed after the header; its PSW addresses the
	// instruction after BAKR.
	if d := be.Uint32(m.S.Mem[0x5010+160:]); d>>24 != lsBranchState || d&0xffff != 0x1000-lsStateSize || d>>16&0xff != 0x42 {
		t.Fatalf("state descriptor %08X", d)
	}
	if w0, w1 := be.Uint32(m.S.Mem[0x5010+136:]), be.Uint32(m.S.Mem[0x5010+140:]); w1 != 0x80001004 || w0>>16 != 0x0408 {
		t.Fatalf("stacked PSW %08X %08X", w0, w1)
	}
}
