package power

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func dForm(po, rt, ra uint32, imm int32) uint32 {
	return po<<26 | rt<<21 | ra<<16 | uint32(imm)&0xffff
}
func xForm(rt, ra, rb, xo uint32, rc bool) uint32 {
	w := 31<<26 | rt<<21 | ra<<16 | rb<<11 | xo<<1
	if rc {
		w |= 1
	}
	return w
}
func xoForm(rt, ra, rb, xo uint32, oe, rc bool) uint32 {
	w := xForm(rt, ra, rb, xo, rc)
	if oe {
		w |= 1 << 10
	}
	return w
}
func mdForm(rs, ra, sh, mb, xo uint32, rc bool) uint32 {
	w := 30<<26 | rs<<21 | ra<<16 | (sh&31)<<11 | ((mb&31)<<1|mb>>5)<<5 | xo<<2 | (sh>>5)<<1
	if rc {
		w |= 1
	}
	return w
}
func mForm(po, rs, ra, sh, mb, me uint32) uint32 {
	return po<<26 | rs<<21 | ra<<16 | sh<<11 | mb<<6 | me<<1
}
func bc(bo, bi uint32, bd int32, lk bool) uint32 {
	w := 16<<26 | bo<<21 | bi<<16 | uint32(bd)&0xfffc
	if lk {
		w |= 1
	}
	return w
}
func branch(li int32, lk bool) uint32 {
	w := 18<<26 | uint32(li)&0x03fffffc
	if lk {
		w |= 1
	}
	return w
}

const (
	blr  = 0x4e800020
	sc0  = 0x44000002
	sc1  = 0x44000022
	rfid = 0x4c000024
)

func machineWith(t *testing.T, code ...uint32) *Machine {
	t.Helper()
	m := NewMachine(Config{Memory: 1 << 20})
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	m.CPUs[0].PC = 0x1000
	return m
}

func runUntilStop(t *testing.T, m *Machine, n uint64) StopReason {
	t.Helper()
	r, err := m.Run(n)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestArithmeticCarriesAndOverflow(t *testing.T) {
	m := machineWith(t,
		dForm(14, 3, 0, -1),                // li r3,-1
		dForm(14, 4, 0, 1),                 // li r4,1
		xoForm(5, 3, 4, 10, false, false),  // addc r5,r3,r4 -> 0, CA
		xoForm(6, 4, 4, 138, false, false), // adde r6,r4,r4 -> 3
		dForm(15, 7, 0, -32768),            // lis r7,0x7fff
		mdForm(7, 7, 32, 0, 1, false),      // rldicr r7,r7,32,0 -> 0x8000000000000000 (rotated hi bit)
		xoForm(8, 7, 7, 266, true, true),   // addo. r8,r7,r7 -> overflow
		xoForm(9, 3, 4, 233, false, false), // mulld r9,r3,r4 -> -1
		dForm(14, 10, 0, -7),
		dForm(14, 11, 0, 2),
		xoForm(12, 10, 11, 489, false, false), // divd r12,r10,r11 -> -3
		xoForm(13, 10, 0, 104, false, false),  // neg r13,r10 -> 7
		dForm(8, 14, 4, 5),                    // subfic r14,r4,5 -> 4, CA
	)
	runUntilStop(t, m, 13)
	c := m.CPUs[0]
	if c.GPR[5] != 0 || c.GPR[6] != 3 || c.GPR[9] != ^uint64(0) || int64(c.GPR[12]) != -3 || c.GPR[13] != 7 || c.GPR[14] != 4 {
		t.Fatalf("results %x", c.GPR[:15])
	}
	if c.GPR[7] != 0x8000000000000000 || c.GPR[8] != 0 || c.XER&(XEROV|XERSO) != XEROV|XERSO || c.CR>>28 != 0x3 {
		t.Fatalf("overflow r7=%x r8=%x xer=%x cr=%x", c.GPR[7], c.GPR[8], c.XER, c.CR)
	}
	if c.XER&XERCA == 0 {
		t.Fatal("subfic did not set CA")
	}
}

func TestRotatesAndShifts(t *testing.T) {
	m := machineWith(t,
		dForm(14, 3, 0, 0x1234),
		mForm(21, 3, 4, 8, 16, 23),    // rlwinm r4,r3,8,16,23 -> 0x3400
		mdForm(3, 5, 60, 0, 0, false), // rldicl r5,r3,60,0 -> rotr 4
		dForm(14, 6, 0, -1),
		mdForm(3, 6, 16, 32, 3, false), // rldimi r6,r3,16,32 -> insert 0x1234<<16 into low half
		dForm(14, 7, 0, -16),
		xForm(7, 8, 2, 413<<1>>1, false), // placeholder replaced below
	)
	// sradi r8,r7,2 (XS-form)
	binary.BigEndian.PutUint32(m.Mem[0x1018:], 31<<26|7<<21|8<<16|2<<11|413<<2)
	runUntilStop(t, m, 7)
	c := m.CPUs[0]
	if c.GPR[4] != 0x3400 || c.GPR[5] != 0x4000000000000123 || c.GPR[6] != 0xffffffff1234ffff || int64(c.GPR[8]) != -4 || c.XER&XERCA != 0 {
		t.Fatalf("r4=%x r5=%x r6=%x r8=%x xer=%x", c.GPR[4], c.GPR[5], c.GPR[6], c.GPR[8], c.XER)
	}
}

func TestBranchesCountAndLink(t *testing.T) {
	m := machineWith(t,
		dForm(14, 3, 0, 0),         // li r3,0
		dForm(14, 4, 0, 10),        // li r4,10
		xForm(4, 9, 9, 467, false), // mtctr r4 (spr 9)
		dForm(14, 3, 3, 3),         // loop: addi r3,r3,3
		bc(16, 0, -4, false),       // bdnz loop
		branch(8, true),            // bl +8
		dForm(14, 5, 0, 99),        // (skipped on return path) li r5,99
		dForm(14, 6, 0, 1),         // target: li r6,1
		dForm(11, 0, 6, 1),         // cmpwi r6,1
		bc(12, 2, 8, false),        // beq +8
		dForm(14, 7, 0, 1),         // not taken
		dForm(14, 8, 0, 2),
	)
	// mtctr encoding: spr field is split, 9 -> ra=9, rb=0.
	binary.BigEndian.PutUint32(m.Mem[0x1008:], 31<<26|4<<21|9<<16|467<<1)
	runUntilStop(t, m, 3+20+1+3+1)
	c := m.CPUs[0]
	if c.GPR[3] != 30 || c.CTR != 0 || c.LR != 0x1018 || c.GPR[5] != 0 || c.GPR[6] != 1 || c.GPR[7] != 0 || c.GPR[8] != 2 {
		t.Fatalf("r3=%d ctr=%d lr=%x r5=%d r6=%d r7=%d r8=%d", c.GPR[3], c.CTR, c.LR, c.GPR[5], c.GPR[6], c.GPR[7], c.GPR[8])
	}
}

func TestLoadsStoresQuadwordAndReservation(t *testing.T) {
	m := machineWith(t,
		dForm(14, 3, 0, 0x2000),
		dForm(14, 4, 0, -2),
		dForm(62, 4, 3, 8),         // std r4,8(r3)
		dForm(58, 5, 3, 8),         // ld r5,8(r3)
		dForm(42, 6, 3, 14),        // lha r6,14(r3) -> -2
		dForm(37, 4, 3, 16),        // stwu r4,16(r3)
		56<<26|8<<21|0<<16|0x2000,  // lq r8,0x2000(0)
		62<<26|8<<21|3<<16|0x10|2,  // stq r8,16(r3) -> 0x2020
		xForm(10, 0, 3, 20, false), // lwarx r10,0,r3
		xForm(4, 0, 3, 150, true),  // stwcx. r4,0,r3 -> success
		xForm(4, 0, 3, 150, true),  // stwcx. again -> fail (no reservation)
	)
	c := m.CPUs[0]
	runUntilStop(t, m, 10)
	if c.GPR[5] != ^uint64(1) || int64(c.GPR[6]) != -2 || c.GPR[3] != 0x2010 || c.CR>>28 != 2 {
		t.Fatalf("r5=%x r6=%x r3=%x cr=%x", c.GPR[5], c.GPR[6], c.GPR[3], c.CR)
	}
	runUntilStop(t, m, 1)
	if c.CR>>28 != 0 {
		t.Fatalf("second stwcx. succeeded: cr=%x", c.CR)
	}
	if c.GPR[8] != 0 || c.GPR[9] != ^uint64(1) || binary.BigEndian.Uint64(m.Mem[0x2028:]) != ^uint64(1) {
		t.Fatalf("lq/stq r8=%x r9=%x", c.GPR[8], c.GPR[9])
	}
}

func TestTranslationFaultsAndHypercall(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	// Code at effective 0xc000000000001000 in a 256MB segment with VSID 0x55.
	if err := c.SLBMTE(0x55<<12, 0xc000000000000000|1<<27|0); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(0x55, 0, 0x1000, 12, PTE{Real: 0x3000, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(0x55, 0, 0x2000, 12, PTE{Real: 0x4000}); err != nil { // read-only data
		t.Fatal(err)
	}
	code := []uint32{
		dForm(15, 4, 0, -16384),        // lis r4,0xc000
		mdForm(4, 4, 32, 31, 1, false), // rldicr r4,r4,32,31 -> 0xc000000000000000
		dForm(24, 4, 4, 0x2000),        // ori r4,r4,0x2000
		dForm(32, 5, 4, 0),             // lwz r5,0(r4)
		dForm(14, 3, 0, 0x77),          // li r3,0x77
		sc1,                            // hypercall
		dForm(36, 5, 4, 0),             // stw r5,0(r4) -> protection DSI
	}
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x3000+4*i:], w)
	}
	binary.BigEndian.PutUint32(m.Mem[0x4000:], 0xdeadbeef)
	c.PC = 0xc000000000001000
	c.MSR |= MSRIR | MSRDR
	var seen uint64
	m.Hypercall = func(c *CPU) error { seen = c.GPR[3]; c.GPR[3] = 0; return nil }
	r := runUntilStop(t, m, 100)
	if c.GPR[4] != 0xc000000000002000 || c.GPR[5] != 0xdeadbeef || seen != 0x77 || c.GPR[3] != 0 {
		t.Fatalf("r4=%x r5=%x hcall=%x", c.GPR[4], c.GPR[5], seen)
	}
	if r.Kind != "interrupt" || c.PC != VecDataStorage || c.DAR != 0xc000000000002000 || c.DSISR != 0x0a000000 || c.SRR0 != 0xc000000000001018 || c.SRR1&MSRIR == 0 || c.MSR&MSRIR != 0 {
		t.Fatalf("stop %v pc=%x dar=%x dsisr=%x srr0=%x srr1=%x", r, c.PC, c.DAR, c.DSISR, c.SRR0, c.SRR1)
	}
	// An unmapped segment raises a data segment interrupt.
	c.MSR, c.PC = MSRSF|MSRIR|MSRDR, 0xc000000000001000+12
	c.GPR[4] = 0xd000000000000000
	r = runUntilStop(t, m, 1)
	if r.Kind != "interrupt" || c.PC != VecDataSegment || c.DAR != 0xd000000000000000 {
		t.Fatalf("segment stop %v pc=%x", r, c.PC)
	}
}

func TestCallbackStorageInterrupt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		word    uint32
		handled bool
	}{{"extension", 0x7c0103e6, true}, {"declined", 0x7c0103e6, false}, {"hypercall", sc1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			m := machineWith(t, tc.word)
			c := m.CPUs[0]
			c.MSR = MSRSF | MSRDR
			c.setSLB(0, SLBEntry{Valid: true})
			m.StopAllInterrupts = true
			m.Hypercall = func(c *CPU) error {
				c.Load(0x3000, 1)
				return nil
			}
			m.Extension = func(c *CPU, word uint32) (bool, error) {
				c.Load(0x3000, 1)
				return tc.handled, nil
			}
			r := runUntilStop(t, m, 1)
			if r.Kind != "interrupt" || c.PC != VecDataStorage || c.SRR0 != 0x1000 || c.SRR1&MSRDR == 0 || c.DAR != 0x3000 {
				t.Fatalf("lost callback interrupt: %v pc=%x srr0=%x srr1=%x dar=%x", r, c.PC, c.SRR0, c.SRR1, c.DAR)
			}
		})
	}
}

func TestSystemCallRfidAndExtension(t *testing.T) {
	m := machineWith(t,
		sc0,        // system call -> 0xc00
		0x7c0103e6, // extension word
		0x78290218, // unhandled word -> program interrupt
	)
	binary.BigEndian.PutUint32(m.Mem[0xc00:], dForm(14, 9, 0, 5))
	binary.BigEndian.PutUint32(m.Mem[0xc04:], rfid)
	m.StopAllInterrupts = false
	m.StopInterrupts[VecProgram] = true
	var ext []uint32
	m.Extension = func(c *CPU, w uint32) (bool, error) {
		ext = append(ext, w)
		if w == 0x7c0103e6 {
			c.GPR[10] = 42
			return true, nil
		}
		return false, nil
	}
	c := m.CPUs[0]
	r := runUntilStop(t, m, 100)
	if c.GPR[9] != 5 || c.GPR[10] != 42 || len(ext) != 2 || r.Kind != "interrupt" || c.SRR0 != 0x1008 || c.SRR1&ProgIllegal == 0 || c.PC != VecProgram {
		t.Fatalf("r9=%d r10=%d ext=%x stop=%v srr0=%x srr1=%x", c.GPR[9], c.GPR[10], ext, r, c.SRR0, c.SRR1)
	}
	if m.Interrupts[VecSystemCall] != 1 {
		t.Fatal("system call not counted")
	}
}

func TestDecrementerAndCheckpoint(t *testing.T) {
	m := machineWith(t, branch(0, false)) // b . (spin)
	c := m.CPUs[0]
	c.MSR |= MSREE
	c.SetDEC(100)
	cp := m.Checkpoint()
	r := runUntilStop(t, m, 10000)
	if r.Kind != "interrupt" || c.PC != VecDecrementer || c.SRR0 != 0x1000 || c.MSR&MSREE != 0 {
		t.Fatalf("stop %v pc=%x srr0=%x", r, c.PC, c.SRR0)
	}
	if err := m.Restore(cp); err != nil {
		t.Fatal(err)
	}
	if c.PC != 0x1000 || c.MSR&MSREE == 0 || m.Instructions() != 0 {
		t.Fatalf("restore pc=%x msr=%x", c.PC, c.MSR)
	}
}

func TestCheckpointRequiresCompatibleProcessor(t *testing.T) {
	cfg := Config{Memory: 4096, MIPS: 10, PVR: 0x004e1202, Extensions: []string{"as"}}
	src := NewMachine(cfg)
	src.Mem[0] = 0x80
	src.tags[0] = 1
	src.instructions = 100
	cp := src.Checkpoint()
	same := NewMachine(cfg)
	if err := same.Restore(cp); err != nil || !same.Tag(0) || same.TB() != src.TB() {
		t.Fatalf("compatible checkpoint: tag %t time %d, err %v", same.Tag(0), same.TB(), err)
	}
	plain, clock, revision := cfg, cfg, cfg
	plain.Extensions = nil
	clock.MIPS++
	revision.PVR++
	for _, other := range []Config{plain, clock, revision} {
		dst := NewMachine(other)
		if err := dst.Restore(cp); err == nil || dst.Mem[0] != 0 {
			t.Fatalf("incompatible checkpoint changed partition: config %+v, byte %x, err %v", other, dst.Mem[0], err)
		}
	}
}

func TestCheckpointSparseMemory(t *testing.T) {
	// Exercise a zero block, a compressible block and a partial final block.
	m := NewMachine(Config{Memory: 2*checkpointBlockSize + 4096})
	for i := checkpointBlockSize; i < len(m.Mem); i++ {
		m.Mem[i] = byte(i)
	}
	want := bytes.Clone(m.Mem)
	cp := m.Checkpoint()
	if len(cp.mem.blocks) != 3 || cp.mem.blocks[0] != nil || len(cp.mem.blocks[1]) >= checkpointBlockSize {
		t.Fatal("checkpoint did not omit zeros and compress repeated data")
	}
	for range 2 {
		for i := range m.Mem {
			m.Mem[i] = 0x42
		}
		if err := m.Restore(cp); err != nil || !bytes.Equal(m.Mem, want) {
			t.Fatalf("restoring independent checkpoint memory: %v", err)
		}
	}
}

func TestBreakpointResumes(t *testing.T) {
	m := machineWith(t, dForm(14, 3, 0, 1), dForm(14, 3, 3, 1), dForm(14, 3, 3, 1))
	m.Breakpoints[0x1004] = true
	if r := runUntilStop(t, m, 10); r.Kind != "breakpoint" || m.CPUs[0].PC != 0x1004 {
		t.Fatal(r)
	}
	runUntilStop(t, m, 2)
	if m.CPUs[0].GPR[3] != 3 {
		t.Fatal("did not resume past breakpoint")
	}
}

func TestASMultipleAndStringDoubleword(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	code := []uint32{
		dForm(14, 3, 0, 0x2000),
		58<<26 | 14<<21 | 3<<16 | 0x0010 | 3, // lmd r14,16(r3)
		62<<26 | 14<<21 | 3<<16 | 0x0200 | 3, // stmd r14,512(r3)
		xForm(1, 9, 0, 467, false),           // mtxer r1 (patched below)
		xForm(20, 0, 3, 565, false),          // lsdx r20,0,r3
		xForm(20, 3, 4, 693, false),          // stsdx r20,r3,r4
	}
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	binary.BigEndian.PutUint32(m.Mem[0x100c:], 31<<26|1<<21|1<<16|467<<1) // mtxer r1
	for i := 0; i < 18; i++ {
		binary.BigEndian.PutUint64(m.Mem[0x2010+8*i:], uint64(i+1)*0x0101010101010101)
	}
	copy(m.Mem[0x2000:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	c := m.CPUs[0]
	c.PC = 0x1000
	c.GPR[1] = 11
	c.GPR[4] = 0x800
	runUntilStop(t, m, 6)
	if c.GPR[14] != 0x0101010101010101 || c.GPR[31] != 18*0x0101010101010101 || binary.BigEndian.Uint64(m.Mem[0x2200+8*17:]) != c.GPR[31] {
		t.Fatalf("lmd/stmd r14=%x r31=%x", c.GPR[14], c.GPR[31])
	}
	if c.GPR[20] != 0x0102030405060708 || c.GPR[21] != 0x090a0b0000000000 || m.Mem[0x2800+10] != 11 || m.Mem[0x2800+11] != 0 {
		t.Fatalf("lsdx r20=%x r21=%x", c.GPR[20], c.GPR[21])
	}
	// Without the extension the same words are illegal.
	plain := machineWith(t, 58<<26|14<<21|3<<16|0x10|3)
	plain.StopAllInterrupts = true
	if r := runUntilStop(t, plain, 1); r.Kind != "interrupt" || plain.CPUs[0].SRR1&ProgIllegal == 0 {
		t.Fatal("lmd accepted without the extension", r)
	}
}

func TestASImmediateStringDoubleword(t *testing.T) {
	m := machineWith(t, 0x7c8304ea, 0x7d0c04ea, xForm(31, 3, 11, 629, false), xForm(31, 0, 11, 757, false))
	m.as = true
	c := m.CPUs[0]
	c.MSR |= MSRTA
	c.GPR[3], c.GPR[12], c.XER = 0x2003, 0x2013, XERTAG|5
	for i := range 48 {
		m.Mem[0x2003+i] = byte(i + 1)
	}
	runUntilStop(t, m, 2)
	for i := range 4 {
		for _, pair := range []struct{ reg, offset int }{{4, 0x2003}, {8, 0x2013}} {
			want := binary.BigEndian.Uint64(m.Mem[pair.offset+8*i:])
			if got := c.GPR[pair.reg+i]; got != want {
				t.Fatalf("GPR%d = %016x, want %016x", pair.reg+i, got, want)
			}
		}
	}
	m.Mem[11] = 0xff
	runUntilStop(t, m, 2)
	if c.GPR[31] != 0x0102030405060708 || c.GPR[0] != 0x090a0b0000000000 ||
		!bytes.Equal(m.Mem[:11], m.Mem[0x2003:0x200e]) || m.Mem[11] != 0xff || c.XER != XERTAG|5 {
		t.Fatalf("wrapped registers %x %x, stored %x, XER %x", c.GPR[31], c.GPR[0], m.Mem[:12], c.XER)
	}
}

func TestASImmediateStringInvalid(t *testing.T) {
	for _, tc := range []struct {
		as, ta bool
		word   uint32
	}{
		{false, true, 0x7c8304ea}, {true, false, 0x7c8304ea}, {true, true, 0x7c8304eb},
		{true, true, xForm(31, 0, 9, 629, false)}, // RA overlaps a wrapped destination
		{true, false, xForm(2, 3, 1, 757, false)},
	} {
		m := machineWith(t, tc.word)
		m.as = tc.as
		c := m.CPUs[0]
		if tc.ta {
			c.MSR |= MSRTA
		}
		if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR1&ProgIllegal == 0 {
			t.Fatalf("accepted invalid form %+v: %v", tc, r)
		}
	}
}

func TestHypercallTableBeforeFallback(t *testing.T) {
	m := machineWith(t, dForm(14, 3, 0, 7), sc1, dForm(14, 3, 0, 8), sc1)
	var native, fallback int
	m.Hypercalls[7] = func(c *CPU) error { native++; return nil }
	m.Hypercall = func(c *CPU) error { fallback++; return nil }
	runUntilStop(t, m, 4)
	if native != 1 || fallback != 1 {
		t.Fatalf("native=%d fallback=%d", native, fallback)
	}
}

func TestHPTEFromHostPageTable(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	if err := c.SLBMTE(1<<62|0x77<<12, 0xffffff<<40|1<<27); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(0x77, 1, 0xff80100000, 12, PTE{Real: 0x5000, Write: true}); err != nil {
		t.Fatal(err)
	}
	d0, d1, ok := c.HPTE(0xffffffff80100123)
	if !ok || d0&1 != 1 || d0&4 != 0 || d0>>62 != 1 || (d1>>12)&(1<<45-1) != 5 || d1&3 != 2 {
		t.Fatalf("%x %x %v", d0, d1, ok)
	}
	if _, _, ok := c.HPTE(0xffffffff80200000); ok {
		t.Fatal("unmapped page reported valid")
	}
}

func TestASConditionalSelect(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	code := []uint32{
		31<<26 | 8<<16 | 9<<11 | 32<<1, // cmplw r8,r9
		0x7928429e,                     // r8 = gt ? r9 : r8 (min)
		31<<26 | 1<<21 | 3<<16 | 8<<11, // cmpld r3,r8
		0x791c1a9e,                     // r28 = gt ? r8 : r3 (min)
		11<<26 | 1<<21 | 4<<16,         // cmpdi r4,0
		30<<26 | 1<<21 | 4<<16 | 4<<11 | 24<<5 | 6<<2 | 1<<1, // r4 = eq ? 1 : r4
		11<<26 | 1<<21 | 5<<16 | 4,                           // cmpdi r5,4
		30<<26 | 3<<21 | 6<<16 | 7<<11 | 24<<5 | 6<<2,        // r6 = eq ? 3 : 7
	}
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	c := m.CPUs[0]
	c.PC = 0x1000
	c.GPR[8], c.GPR[9], c.GPR[3], c.GPR[4], c.GPR[5] = 40, 25, 30, 0, 5
	runUntilStop(t, m, uint64(len(code)))
	if c.GPR[8] != 25 || c.GPR[28] != 25 || c.GPR[4] != 1 || c.GPR[6] != 7 {
		t.Fatalf("r8=%d r28=%d r4=%d r6=%d", c.GPR[8], c.GPR[28], c.GPR[4], c.GPR[6])
	}
	plain := machineWith(t, 0x7928429e)
	plain.StopAllInterrupts = true
	if r := runUntilStop(t, plain, 1); r.Kind != "interrupt" {
		t.Fatal("select accepted without the extension", r)
	}
}

func TestHashedPageTableSlots(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 22})
	const vsid = 0x0ffffff
	if err := m.MapPage(vsid, 1, 0xff80000000, 12, PTE{Real: 0x3000, Write: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	k := PageKey{VSID: vsid, B: 1, Shift: 12, Page: 0xff80000000 >> 12}
	slot, ok := m.HPTESlot(k)
	if !ok || slot>>3 != m.HTAB.Group(vsid, 1, 12, k.Page, false) {
		t.Fatalf("existing mapping not placed in its primary group: %d %v", slot, ok)
	}
	// A guest-built entry for another page in the secondary group of its
	// hash decodes back to that page and translates.
	page := uint64(0xff80001234 >> 0)
	page >>= 12
	g := m.HTAB.Group(vsid, 1, 12, page, true)
	dw0, dw1 := pteWords(PageKey{VSID: vsid, B: 1, Shift: 12, Page: page}, PTE{Real: 0x5000, Write: true, Execute: true}, true)
	if err := m.HPTEWrite(g*8+3, dw0, dw1); err != nil {
		t.Fatal(err)
	}
	if p, ok := m.LookupPage(vsid, 1, page<<12, 12); !ok || p.Real != 0x5000 {
		t.Fatalf("slot entry not translated: %+v %v", p, ok)
	}
	if err := m.HPTEWrite(g*8+3, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.LookupPage(vsid, 1, page<<12, 12); ok {
		t.Fatal("invalidated slot still translates")
	}
	// 256MB segment, 4KB page: the low 11 page-index bits come from the hash.
	page = 0xabcd
	g = m.HTAB.Group(0x1234, 0, 12, page, false)
	dw0, dw1 = pteWords(PageKey{VSID: 0x1234, B: 0, Shift: 12, Page: page}, PTE{Real: 0x7000}, false)
	if err := m.HPTEWrite(g*8, dw0, dw1); err != nil {
		t.Fatal(err)
	}
	if p, ok := m.LookupPage(0x1234, 0, page<<12, 12); !ok || p.Real != 0x7000 || p.Write {
		t.Fatalf("256MB entry: %+v %v", p, ok)
	}
}

func TestIdentitySegments(t *testing.T) {
	m := machineWith(t, dForm(32, 3, 4, 0x34)) // lwz r3,0x34(r4)
	m.StopAllInterrupts = true
	c := m.CPUs[0]
	c.MSR |= MSRDR
	ea := uint64(0xb000100002b00000)
	if err := m.MapPage(ea>>28, 0, ea&(1<<28-1), 12, PTE{Real: 0x8000, Write: true}); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(m.Mem[0x8034:], 0xfeedf00d)
	c.GPR[4] = ea
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.DAR != ea+0x34 {
		t.Fatalf("expected a segment interrupt without identity segments: %+v", r)
	}
	m2 := machineWith(t, dForm(32, 3, 4, 0x34))
	m2.IdentitySegments = true
	m2.CPUs[0].MSR |= MSRDR
	m2.MapPage(ea>>28, 0, ea&(1<<28-1), 12, PTE{Real: 0x8000, Write: true})
	binary.BigEndian.PutUint32(m2.Mem[0x8034:], 0xfeedf00d)
	m2.CPUs[0].GPR[4] = ea
	runUntilStop(t, m2, 1)
	if m2.CPUs[0].GPR[3] != 0xfeedf00d {
		t.Fatalf("identity segment load: %x", m2.CPUs[0].GPR[3])
	}
}

func TestASTagCopy(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	code := []uint32{
		56<<26 | 28<<21 | 3<<16,     // lq r28,0(r3)
		0x60000000,                  // lq alone carries tag via XER
		62<<26 | 28<<21 | 4<<16 | 2, // stq r28,0(r4)
		56<<26 | 28<<21 | 5<<16,     // lq r28,0(r5) (untagged)
		0x60000000,
		62<<26 | 28<<21 | 6<<16 | 2, // stq r28,0(r6)
	}
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	m.tags[0x2000>>4>>6] |= 1 << ((0x2000 >> 4) & 63)
	m.tags[0x2400>>4>>6] |= 1 << ((0x2400 >> 4) & 63) // destination of the untagged copy starts tagged
	c := m.CPUs[0]
	c.PC = 0x1000
	c.GPR[3], c.GPR[4], c.GPR[5], c.GPR[6] = 0x2000, 0x2100, 0x2200, 0x2400
	runUntilStop(t, m, uint64(len(code)))
	if !m.Tag(0x2100) || m.Tag(0x2400) || !m.Tag(0x2000) {
		t.Fatalf("tags: copy %v untagged copy %v source %v", m.Tag(0x2100), m.Tag(0x2400), m.Tag(0x2000))
	}
}

func TestCPUHPTESlot(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	const ea = uint64(0x12345000)
	if err := m.MapPage(ea>>28, 0, ea&0xfffffff, 12, PTE{Real: 0x3000, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.HPTESlot(ea); ok {
		t.Fatal("slot lookup populated absent segment")
	}
	c.identitySegment(ea)
	slot, ok := c.HPTESlot(ea + 0x123)
	if !ok || slot == 0 {
		t.Fatalf("nonzero page slot: %x %v", slot, ok)
	}
	dw0, dw1, err := m.HPTERead(slot)
	if err != nil {
		t.Fatal(err)
	}
	w0, w1, ok := c.HPTE(ea)
	if !ok || w0 != dw0 || w1 != dw1 {
		t.Fatal("slot does not address the translated entry")
	}
	// A secondary slot must be reported as stored, including its index.
	key := PageKey{VSID: ea >> 28, Shift: 12, Page: (ea & 0xfffffff) >> 12}
	secondary := m.HTAB.Group(key.VSID, 0, 12, key.Page, true)*8 + 3
	if err := m.HPTEWrite(slot, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.HPTEWrite(secondary, dw0|hpteSecondary, dw1); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.HPTESlot(ea); !ok || got != secondary {
		t.Fatalf("secondary slot: %x %v", got, ok)
	}
	if err := m.HPTEWrite(secondary, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.HPTESlot(ea); ok {
		t.Fatal("invalid slot still found")
	}
}

func TestFetchPageFollowsLiveCodeAndExecutePermission(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	c.setSLB(0, SLBEntry{Valid: true})
	c.MSR = MSRSF | MSRDR | MSRIR
	c.PC = 0x1000
	mapCode := func(real uint64, execute bool) {
		t.Helper()
		if err := m.MapPage(0, 0, c.PC, 12, PTE{Real: real, Write: true, Execute: execute}); err != nil {
			t.Fatal(err)
		}
	}
	mapCode(0x2000, true)
	for _, word := range []uint32{0x38600001, 0x38600002} {
		if !c.Store(c.PC, 4, uint64(word)) {
			t.Fatal("code store failed")
		}
		if got, ok := c.fetch(); !ok || got != word {
			t.Fatalf("fetch after store = %x, %t", got, ok)
		}
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	slot, ok := c.HPTESlot(c.PC)
	if !ok {
		t.Fatal("code page missing from replacement HPT")
	}
	if _, ok := c.fetch(); !ok || m.HTAB.Entries[slot][1]&0x100 == 0 {
		t.Fatal("cached fetch must reference the replacement HPT")
	}
	mapCode(0x3000, true)
	if got, ok := c.fetch(); !ok || got != 0 {
		t.Fatalf("fetch after remapping = %x, %t", got, ok)
	}
	mapCode(0x3000, false)
	if _, ok := c.fetch(); ok || c.PC != VecInstrStorage {
		t.Fatalf("fetch after execute revocation at PC %x", c.PC)
	}
}

func TestHPTEReferenceChangeActualCPUAccesses(t *testing.T) {
	for _, shift := range []uint{12, 16} {
		m := NewMachine(Config{Memory: 1 << 20})
		c := m.CPUs[0]
		const ea = uint64(0x12340000)
		if err := m.MapPage(ea>>28, 0, ea&0xfffffff, shift, PTE{Real: 0, Write: true, Execute: true}); err != nil {
			t.Fatal(err)
		}
		if err := m.SetHashedPageTable(2048); err != nil {
			t.Fatal(err)
		}
		c.setSLB(0, SLBEntry{Valid: true, ESID: ea >> 28, VSID: ea >> 28})
		if shift == 16 {
			c.SLB[0].Flags = 0x110
		}
		c.MSR = MSRSF | MSRDR | MSRIR
		slot, _ := c.HPTESlot(ea)
		original := m.HTAB.Entries[slot]
		bits := func() uint64 { return m.HTAB.Entries[slot][1] & 0x180 }
		if _, err := c.Translate(ea, false, accessWrite); err != nil {
			t.Fatal(err)
		}
		c.ReadEffective(ea, 4)
		if bits() != 0 {
			t.Fatal("inspection changed reference/change bits")
		}
		if _, ok := c.Load(ea, 4); !ok || bits() != 0x100 {
			t.Fatal("load must set only reference")
		}
		if !c.Store(ea+8, 4, 0x12345678) || bits() != 0x180 {
			t.Fatal("cached store must set reference and change")
		}
		checkpoint := m.Checkpoint()
		if err := m.HPTEWrite(slot, original[0], original[1]); err != nil {
			t.Fatal(err)
		}
		if bits() != 0 {
			t.Fatal("backend clear failed")
		}
		c.PC = ea
		if _, ok := c.fetch(); !ok || bits() != 0x100 {
			t.Fatal("instruction fetch must set reference after clear")
		}
		if err := m.Restore(checkpoint); err != nil || bits() != 0x180 {
			t.Fatal("checkpoint lost reference/change state", err)
		}
		if err := m.HPTEWrite(slot, original[0], original[1]&^3|3); err != nil {
			t.Fatal(err)
		}
		if c.Store(ea, 4, 0) || bits() != 0 {
			t.Fatal("denied store set reference/change")
		}
	}
}

func TestTaggedStoreHPTEHistory(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	const ea = uint64(0x3100)
	const real = uint64(0x5100)
	if err := m.MapPage(0, 0, ea&^4095, 12, PTE{Real: real &^ 4095, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	c.setSLB(0, SLBEntry{Valid: true})
	c.MSR = MSRSF | MSRTA | MSRDR
	c.GPR[4] = ea
	slot, ok := c.HPTESlot(ea)
	if !ok {
		t.Fatal("missing HPTE for tagged store")
	}
	original := m.HTAB.Entries[slot]
	const stq = 62<<26 | 28<<21 | 4<<16 | 2
	c.exec(stq)
	if m.Tag(real) || m.HTAB.Entries[slot][1] != original[1]|0x180 {
		t.Fatal("untagged stq should set only R and C")
	}
	c.XER = XERTAG
	c.exec(stq)
	if !m.Tag(real) || m.HTAB.Entries[slot][1] != original[1]|0x180|hpteTagSet {
		t.Fatal("cached tagged stq lost tag or HPTE history")
	}
	if !c.Store(ea, 1, 0) || m.Tag(real) || m.HTAB.Entries[slot][1]&hpteTagSet == 0 {
		t.Fatal("ordinary store must clear only the quadword's tag")
	}
	if err := m.HPTEWrite(slot, original[0], original[1]); err != nil {
		t.Fatal(err)
	}
	c.MSR &^= MSRDR
	c.exec(stq)
	if !m.Tag(ea) || m.HTAB.Entries[slot] != original {
		t.Fatal("real-mode store changed HPTE history")
	}
	c.MSR |= MSRDR
	c.exec(stq)
	if !m.Tag(real) || m.HTAB.Entries[slot][1]&hpteTagSet == 0 {
		t.Fatal("new data translation did not record tagged store")
	}
}

func TestPointerTagsInspectionRangeAndBitOrder(t *testing.T) {
	m := NewMachine(Config{Memory: 0x4000, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for _, address := range []uint64{0x2000, 0x2010, 0x2080, 0x2ff0} {
		m.setTag(c, address)
	}
	bitmap, err := m.PointerTags(0x2000, 4096)
	want := make([]byte, 32)
	want[0], want[1], want[31] = 0xc0, 0x80, 1
	if err != nil || !bytes.Equal(bitmap, want) {
		t.Fatal("tag bitmap order", bitmap, err)
	}
	if !m.Tag(0x2000) || c.Instructions != 0 {
		t.Fatal("inspection changed tags or executed CPU")
	}
	if !c.Store(0x2000, 8, 0) {
		t.Fatal("ordinary store fixture")
	}
	bitmap, err = m.PointerTags(0x2000, 32)
	if err != nil || !bytes.Equal(bitmap, []byte{0x40}) {
		t.Fatal("inspection lost ordinary-store tag clearing or padding", bitmap, err)
	}
	for _, bad := range [][2]uint64{{1, 16}, {0, 1}, {0x3ff0, 32}, {^uint64(15), 32}} {
		if _, err := m.PointerTags(bad[0], bad[1]); err == nil {
			t.Fatal("invalid tag range accepted", bad)
		}
	}
	if bitmap, err := m.PointerTags(0x4000, 0); err != nil || len(bitmap) != 0 {
		t.Fatal("empty terminal tag range", err)
	}
}

func TestRestorePageTagsPreservesBytesAndUnmarkedTags(t *testing.T) {
	m := NewMachine(Config{Memory: 0x4000, CPUs: 2, Extensions: []string{"as"}})
	c, other := m.CPUs[0], m.CPUs[1]
	const page = 0x2000
	original := bytes.Repeat([]byte{0x98, 0x76, 0x54, 0x32}, 1024)
	if err := m.WriteReal(page, original); err != nil {
		t.Fatal(err)
	}
	m.setTag(c, page+16)
	other.reserve(page, 8)
	m.Watch(page+0xff0, page+0x1000)
	words := [4]uint64{0x8000000100000001, 0x8000000000000000, 0x0000000080000000, 1}
	if err := c.RestorePageTags(page, words); err != nil {
		t.Fatal(err)
	}
	want := []byte{0xc0, 0, 0, 1, 0, 0, 0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	bitmap, err := m.PointerTags(page, 4096)
	if err != nil || !bytes.Equal(bitmap, want) || !bytes.Equal(m.Mem[page:page+4096], original) {
		t.Fatal("tag restoration changed bytes or produced incorrect tags", bitmap, err)
	}
	if other.resValid || c.stop == nil || c.stop.Kind != "watch" {
		t.Fatal("tag restoration missed reservation or watch effects", c.stop)
	}
	for _, invalid := range []uint64{page + 16, 0x4000, ^uint64(4095)} {
		if err := c.RestorePageTags(invalid, words); err == nil {
			t.Fatal("invalid page accepted", invalid)
		}
	}
	untagged := NewMachine(Config{Memory: 0x4000})
	if err := untagged.CPUs[0].RestorePageTags(page, words); err == nil {
		t.Fatal("restored tags without AS support")
	}
}

func TestWideVirtualAddressHPTERoundTrip(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	for _, shift := range []uint8{12, 16, 24, 34} {
		key := PageKey{VSID: 0x1ffffff, B: 1, Shift: shift, Page: 3}
		dw0, dw1 := pteWords(key, PTE{Real: uint64(5) << shift, Write: true}, false)
		slot := m.HTAB.Group(key.VSID, key.B, uint(shift), key.Page, false) * 8
		if err := m.HPTEWrite(slot, dw0, dw1); err != nil {
			t.Fatal(err)
		}
		got, ok := m.HPTESlot(key)
		if !ok || got != slot {
			t.Fatalf("wide VA lost in encoding: shift%d slot%x found%v", shift, got, ok)
		}
		hit, secondary, words, err := m.HTAB.ProbeHPTE(key.VSID, key.Page<<shift, true, int(shift), int(shift))
		if err != nil || secondary || hit != int(slot) || words != [2]uint64{dw0, dw1} {
			t.Fatalf("raw lookup shift %d: %x %v %x %v", shift, hit, secondary, words, err)
		}
		p, ok := m.LookupPage(key.VSID, key.B, key.Page<<shift, uint(shift))
		if !ok || p.Real != uint64(5)<<shift {
			t.Fatalf("wide VA mapping: %+v %v", p, ok)
		}
	}
}

func TestASSelectUsesXERNotCR(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	// CR0 EQ remains true while a compare into CR1 records unequal in FXCC.
	c.CR = 2 << 28
	c.GPR[3], c.GPR[22], c.GPR[5] = 0xffffffffffff8000, 0xffffffffffff0000, 1
	c.exec(11<<26 | 1<<23 | 1<<21 | 5<<16 | 16) // cmpdi cr1,r5,16
	if !c.CRBit(2) || c.XER&(1<<25) != 0 {
		t.Fatal("compare did not independently record FXCC")
	}
	c.exec(0x7acf1b1e) // seleqrr r15,r22,r3
	if c.GPR[15] != c.GPR[3] {
		t.Fatalf("selected from stale CR0: %x", c.GPR[15])
	}
	// Modifying CR does not change the saved FXCC comparison.
	c.compareField(1, 1, 1)
	c.SetCRField(0, 8)
	c.exec(0x7acf1b1e)
	if c.GPR[15] != c.GPR[22] {
		t.Fatal("select failed to use saved XER EQ")
	}
	// Explicit XER save/restore must retain the predicate independently of CR.
	saved, ok := c.mfspr(1)
	if !ok {
		t.Fatal("mfxer")
	}
	c.compareField(0, 2, 1)
	c.mtspr(1, saved)
	c.exec(0x7acf1b1e)
	if c.GPR[15] != c.GPR[22] {
		t.Fatal("XER restore lost FXCC")
	}
	// All four operand forms, signed immediates, XER carry and Rc effects.
	for form := uint32(12); form <= 15; form++ {
		for _, bit := range []bool{false, true} {
			c.XER = 0
			if bit {
				c.XER = XERCA
			}
			c.GPR[31], c.GPR[30] = 123, 456
			w := uint32(30<<26 | 31<<21 | 7<<16 | 30<<11 | 2<<7 | form<<1 | 1)
			c.exec(w)
			wantFirst, wantSecond := uint64(123), uint64(456)
			if form < 14 {
				wantFirst = ^uint64(0)
			}
			if form&1 == 0 {
				wantSecond = ^uint64(1)
			}
			want := wantSecond
			if bit {
				want = wantFirst
			}
			if c.GPR[7] != want {
				t.Fatalf("form%d bit%v: %x want%x", form, bit, c.GPR[7], want)
			}
			if ((c.XER >> 24) & 14) != uint64(c.CR>>28)&14 {
				t.Fatal("record form did not update FXCC")
			}
		}
	}
}

func TestCopyRealPagePreservesTags(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for i := uint64(0); i < 4096; i++ {
		m.Mem[0x1000+i] = byte(i * 17)
	}
	m.tags[4], m.tags[7] = 0x8100000000000001, 1<<63
	for i := 8; i < 12; i++ {
		m.tags[i] = ^uint64(0)
	}
	m.CPUs[1].reserve(0x2000, 8)
	m.Watch(0x2000, 0x2001)
	if err := c.CopyRealPage(0x2000, 0x1000); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[0x1000:0x2000], m.Mem[0x2000:0x3000]) {
		t.Fatal("page bytes differ")
	}
	for i := 0; i < 4; i++ {
		if m.tags[4+i] != m.tags[8+i] {
			t.Fatalf("tag word%d differs", i)
		}
	}
	if m.CPUs[1].resValid {
		t.Fatal("copy left other CPU reservation intact")
	}
	if c.stop == nil || c.stop.Kind != "watch" {
		t.Fatal("page copy failed to trigger store watch")
	}
	if err := c.CopyRealPage(0x1000, 0x1000); err != nil {
		t.Fatal(err)
	}
	if m.tags[4] != 0x8100000000000001 {
		t.Fatal("self-copy lost tags")
	}
	before := slices.Clone(m.Mem)
	for _, pair := range [][2]uint64{{1, 0x1000}, {0x2000, 3}, {^uint64(4095), 0x1000}} {
		if err := c.CopyRealPage(pair[0], pair[1]); err == nil {
			t.Fatal("invalid page range accepted")
		}
	}
	if !bytes.Equal(before, m.Mem) {
		t.Fatal("rejected copy mutated memory")
	}
}

func TestVirtualCountersAdvanceAndRestore(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, MIPS: 100})
	c := m.CPUs[0]
	// The time base is partition-wide; instruction/utilization counts belong
	// to the CPU. Explicit writes set an offset, not a frozen counter.
	for _, spr := range []int{848, 849, 308, 309} {
		c.mtspr(spr, 500)
		if got, ok := c.mfspr(spr); !ok || got != 500 {
			t.Fatalf("SPR%d initial%d %v", spr, got, ok)
		}
	}
	cp := m.Checkpoint()
	m.instructions += 100
	c.Instructions += 25
	for _, spr := range []int{848, 849, 308, 309} {
		got, _ := c.mfspr(spr)
		want := uint64(628)
		if spr == 848 {
			want = 525
		}
		if spr == 849 {
			want = 1012
		}
		if got != want {
			t.Fatalf("SPR%d =%d want%d", spr, got, want)
		}
	}
	if err := m.Restore(cp); err != nil {
		t.Fatal(err)
	}
	for _, spr := range []int{848, 849, 308, 309} {
		if got, _ := m.CPUs[0].mfspr(spr); got != 500 {
			t.Fatalf("SPR%d restore%d", spr, got)
		}
	}
}

func TestASConditionalStoreRecordsFXCC(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	c.GPR[4], c.GPR[8] = 0x5000, 0x1234
	c.compareField(1, 1, 1)
	c.exec(xForm(8, 0, 4, 214, true)) // stdcx. with no reservation fails
	if (c.XER>>24)&15 != 0 || c.CRBit(2) {
		t.Fatal("failed store retained stale FXCC EQ")
	}
	c.exec(xForm(6, 0, 4, 84, false)) // ldarx
	c.compareField(1, 1, 2)
	c.XER |= XERSO
	c.exec(xForm(8, 0, 4, 214, true))
	if (c.XER>>24)&15 != 2 || c.CR>>28 != 3 {
		t.Fatalf("conditional store CR=%x XER=%x", c.CR, c.XER)
	}
	if binary.BigEndian.Uint64(m.Mem[0x5000:]) != 0x1234 {
		t.Fatal("conditional store did not happen")
	}
}

func TestParkedCPUsAndFirmwareRelease(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2})
	// Both CPUs loop on one instruction; only the released CPU may run.
	binary.BigEndian.PutUint32(m.Mem, branch(0, false))
	m.CPUs[1].Parked = true
	cp := m.Checkpoint()
	if r, err := m.Run(10); err != nil || r.Kind != "budget" || m.CPUs[1].Instructions != 0 {
		t.Fatalf("parked CPU ran: %v %v", r, err)
	}
	m.Hypercall = func(c *CPU) error {
		c.Parked = true
		m.CPUs[1].Parked = false
		return nil
	}
	// Code changes after execution go through WriteReal, which discards
	// compiled blocks.
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], 0x44000022) // CPU0 releases CPU1 via sc1
	m.WriteReal(0, word[:])
	binary.BigEndian.PutUint32(word[:], branch(0, false))
	m.WriteReal(8, word[:])
	m.CPUs[1].PC = 8
	if r, err := m.Run(11); err != nil || r.Kind != "budget" || m.CPUs[1].Instructions != 10 || m.CPUs[0].Instructions != 11 {
		t.Fatalf("firmware release: %v %v counts %d/%d", r, err, m.CPUs[0].Instructions, m.CPUs[1].Instructions)
	}
	m.CPUs[1].Parked = true
	if r, err := m.Run(10); err != nil || r.Kind != "idle" {
		t.Fatalf("all parked: %v %v", r, err)
	}
	if err := m.Restore(cp); err != nil || m.CPUs[0].Parked || !m.CPUs[1].Parked {
		t.Fatalf("park state restore: %v", err)
	}
}

func TestReservationGranule(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2})
	c, other := m.CPUs[0], m.CPUs[1]
	c.GPR[4], c.GPR[5], c.GPR[8] = 0x5000, 0x5078, 0x1234
	c.exec(xForm(6, 0, 4, 84, false)) // ldarx
	c.exec(xForm(8, 0, 5, 214, true)) // different doubleword, same granule
	if !c.CRBit(2) || binary.BigEndian.Uint64(m.Mem[0x5078:]) != 0x1234 {
		t.Fatal("conditional store within reserved granule failed")
	}
	c.exec(xForm(6, 0, 4, 84, false))
	other.Store(0x507f, 1, 1) // adjacent byte in the reserved cache line
	c.exec(xForm(8, 0, 4, 214, true))
	if c.CRBit(2) || binary.BigEndian.Uint64(m.Mem[0x5000:]) != 0 {
		t.Fatal("another CPU's store did not invalidate the whole granule")
	}
	c.exec(xForm(6, 0, 4, 84, false))
	other.Store(0x5080, 1, 1) // next line must not invalidate
	c.exec(xForm(8, 0, 4, 214, true))
	if !c.CRBit(2) {
		t.Fatal("store in another granule invalidated reservation")
	}
	c.GPR[5] = 0x5080
	c.exec(xForm(6, 0, 4, 84, false))
	c.exec(xForm(8, 0, 5, 214, true))
	if c.CRBit(2) || c.resValid {
		t.Fatal("unreserved granule stored or retained reservation")
	}
}

func TestFirmwareYieldSchedulesOtherCPU(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2})
	binary.BigEndian.PutUint32(m.Mem, 0x44000022)
	m.Hypercall = func(c *CPU) error {
		if c.Index == 0 {
			c.Yield()
		} else {
			c.Stop("stopped", "other CPU ran")
		}
		return nil
	}
	r, err := m.Run(100)
	if err != nil || r.CPU != 1 || r.Kind != "stopped" || m.CPUs[0].PC != 4 || m.CPUs[0].Instructions != 1 || m.CPUs[1].Instructions != 1 {
		t.Fatalf("yield failed: %v %v counts%d/%d", r, err, m.CPUs[0].Instructions, m.CPUs[1].Instructions)
	}
}

func TestWaitingCPUClockAndWake(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	c.MSR |= MSREE
	c.PC = 0x1000
	c.SetDEC(512000000)
	c.WaitForInterrupt()
	cp := m.Checkpoint()
	r, err := m.Run(1)
	if err != nil || r.Kind != "interrupt" || c.SRR0 != 0x1000 || c.Waiting || m.TB() != 512000000 || c.Instructions != 0 {
		t.Fatalf("waiting timer: %v %v TB%d SRR0%x count%d waiting%v", r, err, m.TB(), c.SRR0, c.Instructions, c.Waiting)
	}
	if err := m.Restore(cp); err != nil || m.TB() != 0 || !c.Waiting {
		t.Fatalf("waiting clock restore: %v TB%d waiting%v", err, m.TB(), c.Waiting)
	}
	c.MSR &^= MSREE
	if r, err := m.Run(1); err != nil || r.Kind != "idle" || m.TB() != 0 {
		t.Fatalf("masked timer: %v %v", r, err)
	}
	c.Wake()
	binary.BigEndian.PutUint32(m.Mem[0x1000:], branch(0, false))
	if r, err := m.Run(1); err != nil || r.Kind != "budget" || c.Instructions != 1 {
		t.Fatalf("backend wake: %v %v", r, err)
	}
	c.Wake() // event arrives before the next cede
	c.WaitForInterrupt()
	if c.Waiting {
		t.Fatal("wake before wait was lost")
	}
	c.WaitForInterrupt()
	if !c.Waiting {
		t.Fatal("one wake event bypassed two waits")
	}
	c.Wake()
	if c.Waiting {
		t.Fatal("wake during wait was lost")
	}
}

func TestExternalInterruptLevelMaskWaitAndCheckpoint(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	c.PC = 0x1000
	binary.BigEndian.PutUint32(m.Mem[0x1000:], branch(0, false))
	c.SetExternalInterrupt(true)
	if r, err := m.Run(1); err != nil || r.Kind != "budget" || c.Instructions != 1 {
		t.Fatalf("masked external input must permit execution: %v %v", r, err)
	}
	c.WaitForInterrupt()
	if r, err := m.Run(1); err != nil || r.Kind != "idle" || !c.Waiting {
		t.Fatalf("masked external input must not wake wait: %v %v", r, err)
	}
	c.MSR |= MSREE
	cp := m.Checkpoint()
	for attempt := 0; attempt < 2; attempt++ {
		c.PC = 0x1000
		c.MSR |= MSREE
		before := c.Instructions
		if r, err := m.Run(1); err != nil || r.Kind != "interrupt" || c.PC != VecExternal || c.SRR0 != 0x1000 || c.SRR1&MSREE == 0 || c.MSR&MSREE != 0 || c.Waiting || c.Instructions != before {
			t.Fatalf("external input delivery %d: %v %v CPU%+v", attempt, r, err, c)
		}
	}
	c.SetExternalInterrupt(false)
	c.PC, c.MSR = 0x1000, c.MSR|MSREE
	if r, err := m.Run(1); err != nil || r.Kind != "budget" {
		t.Fatalf("withdrawn external input: %v %v", r, err)
	}
	if err := m.Restore(cp); err != nil || !c.Waiting || !c.external {
		t.Fatalf("restore pending level and wait: %v", err)
	}
	c.Parked = true
	if r, err := m.Run(1); err != nil || r.Kind != "idle" {
		t.Fatalf("external input must not release parked CPU: %v %v", r, err)
	}
	c.Parked = false
	if r, err := m.Run(1); err != nil || r.Kind != "interrupt" || c.PC != VecExternal {
		t.Fatalf("restored external input: %v %v", r, err)
	}
}

func TestASTrapOnXER(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for xbi := uint32(0); xbi < 16; xbi++ {
		for to := uint32(0); to < 2; to++ {
			for bit := uint64(0); bit < 2; bit++ {
				for _, ui := range []uint32{0, 1, 1023} {
					c.PC, c.MSR, c.CR = 0x1000, MSRSF|MSRME|MSREE, ^uint32(0)
					c.fault, c.stop = false, nil
					c.XER = 0xa5a5000012345678&^(uint64(1)<<(31-xbi)) | bit<<(31-xbi)
					before, registers := c.XER, c.GPR
					w := uint32(31<<26) | to<<21 | ui<<11 | xbi<<7 | 36<<1
					c.exec(w)
					trapped := c.fault && c.PC == VecProgram && c.SRR1&ProgTrap != 0 && c.SRR0 == 0x1000
					if trapped != (bit == uint64(to)) || c.XER != before || c.CR != ^uint32(0) || c.GPR != registers {
						t.Fatalf("txer TO%d UI%d XBI%d value%d: trap%v XER%x/%x CR%x", to, ui, xbi, bit, trapped, c.XER, before, c.CR)
					}
				}
			}
		}
	}
	for _, w := range []uint32{0x7c400348, 0x7fe00348, 0x7c000349} {
		c.PC, c.fault, c.stop = 0x1000, false, nil
		c.exec(w)
		if !c.fault || c.SRR1&ProgIllegal == 0 {
			t.Fatalf("invalid txer %08x accepted", w)
		}
	}
	plain := NewMachine(Config{Memory: 1 << 20})
	plain.CPUs[0].exec(0x7c000348)
	if plain.CPUs[0].SRR1&ProgIllegal == 0 {
		t.Fatal("txer accepted without AS")
	}
}

func TestASCompareLogicalAddresses(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for _, tt := range []struct {
		a, b uint64
		want uint32
	}{
		{0x123456, 0x123456, 2},
		{0x123456, 0xffffffffffff, 8}, // high16 zero: full48-bit range
		{0xffffffffffff, 0x123456, 4},
		{0xb000100002000001, 0xb000100002ffffff, 8},
		{0xb000100002ffffff, 0xb000100002000001, 4},
		{0xb000100002ffffff, 0xb000100003000001, 1}, // distinct24-bit spaces
		{0xb000100002000001, 0xc000100002000001, 1},
		{0, 0xb000100002000001, 1},
	} {
		c.GPR[5], c.GPR[4] = tt.a, tt.b
		c.CR, c.XER = 0xaaaaaaaa, XERSO|XERCA
		c.exec(xForm(3*4+1, 5, 4, 64, false))
		if c.CR != 0xaaa0aaaa|tt.want<<16 || (c.XER>>24)&15 != uint64(tt.want) || c.XER&(XERSO|XERCA) != XERSO|XERCA {
			t.Fatalf("cmpla %x/%x CR%x XER%x want%x", tt.a, tt.b, c.CR, c.XER, tt.want)
		}
	}
	plain := NewMachine(Config{Memory: 1 << 20}).CPUs[0]
	plain.exec(0x7c252080)
	if plain.SRR1&ProgIllegal == 0 {
		t.Fatal("cmpla accepted without AS")
	}
}

func TestASQuadwordTagPredicatesAndSetTag(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	c.GPR[3], c.GPR[4] = 0x2000, 0x2100
	for _, tt := range []struct {
		typ    byte
		pt     uint32
		tagged bool
		want   uint64
	}{
		{0x00, 8, true, XERT02 | XERTAG},
		{0x40, 4, true, XERT02 | XERTAG},
		{0x80, 2, true, XERT02 | XERTAG},
		{0xc0, 1, true, XERT02 | XERTAG},
		{0x20, 15, true, XERTAG}, // type bit2 excludes T02
		{0xa6, 6, true, XERT07 | XERTAG},
		{0xa6, 7, true, XERTAG},
		{0x00, 0, true, XERTAG},
		{0x40, 4, false, 0},
		{0xa6, 6, false, 0},
	} {
		m.Mem[0x2000] = tt.typ
		m.tags[8] = 0
		if tt.tagged {
			m.tags[8] = 1
		}
		c.XER = XERSO | XERCA | uint64(2)<<24 | XERT02 | XERT07 | XERTAG
		c.exec(56<<26 | 28<<21 | 3<<16 | tt.pt)
		if got := c.XER & (XERT02 | XERT07 | XERTAG); got != tt.want || c.GPR[28]>>56 != uint64(tt.typ) || c.XER&^(XERT02|XERT07|XERTAG) != XERSO|XERCA|uint64(2)<<24 {
			t.Fatalf("lq type%x PT%x tag%v => XER%x want%x", tt.typ, tt.pt, tt.tagged, c.XER, tt.want)
		}
	}
	c.XER = XERSO
	c.exec(0x7c0103e6) // settag must set1 even following an untagged lq
	for _, addr := range []uint64{0x2100, 0x2200} {
		c.GPR[4] = addr
		c.exec(62<<26 | 28<<21 | 4<<16 | 2)
		if !m.Tag(addr) || c.XER != XERSO|XERTAG {
			t.Fatal("stq must write TAG without clearing it")
		}
	}
	cp := m.Checkpoint()
	c.mtspr(1, 0) // explicit XER update controls next stq's tag
	c.exec(62<<26 | 28<<21 | 4<<16 | 2)
	if m.Tag(0x2200) {
		t.Fatal("untagged stq retained memory tag")
	}
	if err := m.Restore(cp); err != nil || !m.Tag(0x2200) || c.XER != XERSO|XERTAG {
		t.Fatalf("pointer tags and XER restore: %v", err)
	}
	c.GPR[4] = 0x2104
	before := slices.Clone(m.Mem[0x2100:0x2120])
	c.exec(62<<26 | 28<<21 | 4<<16 | 2)
	if c.PC != VecAlignment || c.DAR != 0x2104 || !bytes.Equal(before, m.Mem[0x2100:0x2120]) || !m.Tag(0x2100) {
		t.Fatal("unaligned stq must fault before changing bytes or tags")
	}
}

func TestBackendWriteTagAndReservationEffects(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2, Extensions: []string{"as"}})
	m.tags[8] = 3 // quadwords2000 and2010 tagged
	for _, c := range m.CPUs {
		c.GPR[4] = 0x2000
		c.exec(xForm(6, 0, 4, 84, false))
	}
	if err := m.WriteReal(0x207f, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if m.CPUs[0].resValid || m.CPUs[1].resValid || !m.Tag(0x2000) || !m.Tag(0x2010) {
		t.Fatal("backend must invalidate the whole reservation, but only affected tags")
	}
	if err := m.WriteReal(0x200f, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if m.Tag(0x2000) || m.Tag(0x2010) {
		t.Fatal("backend bytes crossing a quadword boundary must clear both tags")
	}
	before := slices.Clone(m.Mem)
	if m.WriteReal(^uint64(0), []byte{1}) == nil || m.WriteReal(uint64(len(m.Mem))-1, []byte{1, 2}) == nil || !bytes.Equal(before, m.Mem) {
		t.Fatal("rejected backend write mutated bytes")
	}
}

func TestBackendTranslationWindow(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	c.MSR |= MSRIR | MSRDR
	const base = uint64(0x8000000006000000)
	if err := m.MapWindow(TranslationWindow{Effective: base, Real: 0x4000, Size: 0x2000, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	if !c.Store(base+0xffc, 8, 0x1122334455667788) {
		t.Fatal("window crossing page store")
	}
	if got, ok := c.Load(base+0xffc, 8); !ok || got != 0x1122334455667788 || binary.BigEndian.Uint64(m.Mem[0x4ffc:]) != got {
		t.Fatal("window did not alias real bytes")
	}
	if _, err := c.Translate(base, true, accessExec); err == nil {
		t.Fatal("nonexecuting window accepted fetch")
	}
	c.MSR |= MSRPR
	if _, err := c.Translate(base, false, accessRead); err == nil {
		t.Fatal("supervisor window exposed to user")
	}
	c.MSR &^= MSRPR
	cp := m.Checkpoint()
	if err := m.MapWindow(TranslationWindow{Effective: 0x90000000, Real: 0, Size: 4096}); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(cp); err != nil || len(m.windows) != 1 {
		t.Fatalf("window restore: %v", err)
	}
	if err := m.MapWindow(TranslationWindow{Effective: base + 4096, Real: 0, Size: 4096}); err == nil || len(m.windows) != 1 {
		t.Fatal("overlapping window accepted")
	}
	for _, w := range []TranslationWindow{{Effective: ^uint64(4095), Real: 0, Size: 4096}, {Effective: 0x10000, Real: 0x100000, Size: 4096}, {Effective: 0x10001, Size: 4096}} {
		if m.MapWindow(w) == nil {
			t.Fatal("invalid window accepted")
		}
	}
}

func TestGuestSegmentRanges(t *testing.T) {
	m := machineWith(t, 62<<26|4<<21|6<<16|2) // stq r4,0(r6)
	c := m.CPUs[0]
	c.MSR |= MSRDR
	const esid, vsid = 0x4004, 0x1e2f4a99ed
	const ea = esid << 28
	m.IdentitySegments = true
	c.identitySegment(ea)
	if err := m.SetIdentitySegments(true, []SegmentRange{{0x4000, 0x40000}, {0x80000, 0xc0000}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint64{0x3fff, 0x40000, 0x7ffff, 0xc0000, 0xfffffffff} {
		if !m.useIdentitySegment(id << 28) {
			t.Fatalf("missing global segment %x", id)
		}
	}
	for _, id := range []uint64{0x4000, 0x3ffff, 0x80000, 0xbffff} {
		if m.useIdentitySegment(id << 28) {
			t.Fatalf("unexpected identity segment %x", id)
		}
	}
	if err := m.MapPage(vsid, 0, 0, 12, PTE{Real: 0x8000, Write: true}); err != nil {
		t.Fatal(err)
	}
	m.StopAllInterrupts = true
	c.GPR[4], c.GPR[5], c.GPR[6] = 0x1234, 0x5678, ea
	c.GPR[11], c.GPR[30] = vsid<<12|0x4c0, ea|1<<27|1
	binary.BigEndian.PutUint32(m.Mem[VecDataSegment:], xForm(11, 0, 30, 402, false)) // slbmte r11,r30
	binary.BigEndian.PutUint32(m.Mem[VecDataSegment+4:], rfid)
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.PC != VecDataSegment || c.DAR != ea {
		t.Fatalf("expected segment miss for process page: %+v", r)
	}
	if r := runUntilStop(t, m, 3); r.Kind != "budget" || c.PC != 0x1004 ||
		binary.BigEndian.Uint64(m.Mem[0x8000:]) != 0x1234 ||
		binary.BigEndian.Uint64(m.Mem[0x8008:]) != 0x5678 {
		t.Fatalf("retried store at %x: %v, bytes %x", c.PC, r, m.Mem[0x8000:0x8010])
	}
}

func TestHPTEOverlappingSlotLifetimes(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20})
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	k := PageKey{VSID: 0x1e2f4a99ed, Shift: 12}
	put := func(secondary bool, real uint64) uint64 {
		t.Helper()
		slot := m.HTAB.Group(k.VSID, 0, 12, 0, secondary) * 8
		v, r := pteWords(k, PTE{Real: real, Write: true}, secondary)
		if err := m.HPTEWrite(slot, v, r); err != nil {
			t.Fatal(err)
		}
		return slot
	}
	check := func(wantSlot, wantReal uint64) {
		t.Helper()
		slot, ok := m.HPTESlot(k)
		page, mapped := m.LookupPage(k.VSID, 0, 0, 12)
		if !ok || !mapped || slot != wantSlot || page.Real != wantReal {
			t.Fatalf("slot %d, mapped page %+v, found %v/%v", slot, page, ok, mapped)
		}
	}
	primary := put(false, 0x4000)
	secondary := put(true, 0x8000)
	check(primary, 0x4000)
	if err := m.HPTEWrite(primary, 0, 0); err != nil {
		t.Fatal(err)
	}
	check(secondary, 0x8000)
	primary = put(false, 0x9000)
	if err := m.HPTEWrite(secondary, 0, 0); err != nil {
		t.Fatal(err)
	}
	check(primary, 0x9000)
}
