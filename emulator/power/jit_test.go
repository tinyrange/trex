package power

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// jitProgram generates random instructions from the forms the JIT
// compiles, plus a few it leaves to the interpreter, so blocks, side exits
// and interpreter fallbacks interleave.
func jitProgram(r *rand.Rand, n int) []uint32 {
	// r1..r10 hold data and code addresses; random results go elsewhere.
	reg := func() uint32 {
		if n := uint32(r.Intn(22)); n > 0 {
			return n + 10
		}
		return 0
	}
	base := func() uint32 { return uint32(1 + r.Intn(6)) } // r1..r6 hold data addresses
	d := func(align int) uint32 { return uint32(int16(r.Intn(0x800)-0x400)) &^ uint32(align-1) & 0xffff }
	var words []uint32
	for len(words) < n {
		rt, ra, rb := reg(), reg(), uint32(r.Intn(32))
		rc := uint32(r.Intn(2))
		var w uint32
		switch r.Intn(34) {
		case 0: // D-form arithmetic/logical
			po := []uint32{7, 10, 11, 14, 15, 24, 25, 26, 27, 28, 29, 2, 3, 8, 12, 13}[r.Intn(16)]
			if po == 2 || po == 3 {
				rt = []uint32{0, 1, 2, 4, 8, 16, 5, 24}[r.Intn(8)] // mostly untaken traps
			}
			if po == 10 || po == 11 {
				rt = uint32(r.Intn(8))<<2 | uint32(r.Intn(2))
			}
			w = po<<26 | rt<<21 | ra<<16 | uint32(r.Intn(0x10000))
		case 1, 2: // rotate word
			po := []uint32{20, 21, 23}[r.Intn(3)]
			w = po<<26 | rt<<21 | ra<<16 | rb<<11 | uint32(r.Intn(32))<<6 | uint32(r.Intn(32))<<1 | rc
		case 3, 4: // rotate doubleword and AS selects
			w = 30<<26 | rt<<21 | ra<<16 | rb<<11 | uint32(r.Intn(64))<<5 | uint32(r.Intn(8))<<2 | uint32(r.Intn(4))
			if r.Intn(3) == 0 {
				w = 30<<26 | rt<<21 | ra<<16 | rb<<11 | uint32(r.Intn(16))<<7 | uint32(6+r.Intn(2))<<2 | uint32(r.Intn(2))<<1 | rc
			}
		case 5, 6, 7: // opcode 31 integer
			xo := []uint32{266, 40, 104, 233, 235, 73, 9, 75, 11, 489, 457, 491, 459, 10, 8, 138,
				0, 32, 19, 144, 24, 27, 536, 539, 26, 58, 28, 60, 124, 284, 316, 412, 444, 476, 922, 954, 986, 15, 824, 792,
				202, 200, 234, 232, 136, 794, 506, 378, 68, 4, 83, 413}[r.Intn(52)]
			if xo == 68 || xo == 4 {
				rt = []uint32{0, 1, 2, 4, 8, 16, 5, 24}[r.Intn(8)]
			}
			if xo == 413 { // sradi
				w = 31<<26 | rt<<21 | ra<<16 | rb<<11 | 413<<2 | uint32(r.Intn(2))<<1 | rc
				break
			}
			if xo == 19 && r.Intn(2) == 0 { // mfocrf
				w = 31<<26 | rt<<21 | 1<<20 | uint32(r.Intn(256))<<12 | 19<<1
				break
			}
			oe := uint32(r.Intn(2))
			if xo == 0 || xo == 32 {
				rt = uint32(r.Intn(8))<<2 | uint32(r.Intn(2))
				rc = 0
			}
			if xo == 15 { // isel
				w = 31<<26 | rt<<21 | ra<<16 | rb<<11 | uint32(r.Intn(32))<<6 | 15<<1
				break
			}
			if xo == 144 {
				w = 31<<26 | rt<<21 | uint32(r.Intn(256))<<12 | 144<<1
				break
			}
			if xoForms[xo&0x1ff] && xo < 512 {
				w = 31<<26 | rt<<21 | ra<<16 | rb<<11 | oe<<10 | xo<<1 | rc
			} else {
				w = 31<<26 | rt<<21 | ra<<16 | rb<<11 | xo<<1 | rc
			}
		case 8, 9, 10: // D-form loads and stores
			po := []uint32{32, 33, 34, 35, 40, 41, 42, 43, 36, 37, 38, 39, 44, 45}[r.Intn(14)]
			b := base()
			if rt == b {
				rt = 0
			}
			w = po<<26 | rt<<21 | b<<16 | d(1)
		case 11, 12: // DS-form
			b := base()
			if rt == b {
				rt = 0
			}
			if r.Intn(2) == 0 {
				w = 58<<26 | rt<<21 | b<<16 | d(4) | uint32(r.Intn(3))
			} else {
				w = 62<<26 | rt<<21 | b<<16 | d(4) | uint32(r.Intn(2))
			}
		case 13, 14: // X-form loads and stores
			xo := []uint32{21, 53, 23, 55, 87, 119, 279, 311, 343, 375, 341, 373, 149, 181, 151, 183, 215, 247, 407, 439}[r.Intn(20)]
			b := base()
			if rt == b {
				rt = 0
			}
			w = 31<<26 | rt<<21 | b<<16 | uint32(7+r.Intn(2))<<11 | xo<<1
		case 15: // conditional branch forward
			bo := []uint32{4, 12, 20, 0, 2, 8, 10, 16, 18}[r.Intn(9)]
			w = 16<<26 | bo<<21 | uint32(r.Intn(32))<<16 | uint32(4*(1+r.Intn(6))) | uint32(r.Intn(2))
		case 16: // unconditional branch forward
			w = 18<<26 | uint32(4*(1+r.Intn(6))) | uint32(r.Intn(2))
		case 17: // CR logical
			xo := []uint32{257, 449, 193, 225, 33, 289, 129, 417}[r.Intn(8)]
			w = 19<<26 | rt<<21 | ra<<16 | rb<<11 | xo<<1
		case 18: // move to/from LR, CTR, XER
			spr := []uint32{1, 8, 9}[r.Intn(3)]
			xo := []uint32{339, 467}[r.Intn(2)]
			if spr != 1 && xo == 467 {
				rt = 9 + uint32(r.Intn(2)) // code addresses
			}
			w = 31<<26 | rt<<21 | (spr&31)<<16 | (spr>>5)<<11 | xo<<1
		case 19: // bclr/bcctr
			bo := []uint32{20, 12, 4, 16, 0}[r.Intn(5)]
			xo := []uint32{16, 528}[r.Intn(2)]
			if xo == 528 && bo&4 == 0 {
				bo |= 4
			}
			w = 19<<26 | bo<<21 | uint32(r.Intn(32))<<16 | xo<<1 | uint32(r.Intn(2))
		case 20: // lwarx/stwcx. pairs, which force interpreted stores
			b := base()
			w = 31<<26 | rt<<21 | b<<11 | 20<<1
			words = append(words, w)
			w = 31<<26 | rt<<21 | b<<11 | 150<<1 | 1
		case 21: // ldarx/stdcx., or lqarx/stqcx. on an even pair
			b := base()
			if r.Intn(2) == 0 {
				q := uint32(12 + 2*r.Intn(9))
				w = 31<<26 | q<<21 | b<<11 | 276<<1
				words = append(words, w)
				if r.Intn(4) == 0 {
					b = base() // sometimes a different granule
				}
				w = 31<<26 | q<<21 | b<<11 | 182<<1 | 1
				break
			}
			w = 31<<26 | rt<<21 | b<<11 | 84<<1
			words = append(words, w)
			w = 31<<26 | rt<<21 | b<<11 | 214<<1 | 1
		case 22: // dcbz
			w = 31<<26 | base()<<16 | uint32(7+r.Intn(2))<<11 | 1014<<1
		case 23: // SPRG moves
			spr := []uint32{272, 273, 274, 275, 259, 268, 269, 848, 849, 308, 309, 136, 152, 26, 27, 18, 19, 22}[r.Intn(18)]
			xo := []uint32{339, 467}[r.Intn(2)]
			if spr == 26 {
				xo = 339 // SRR0 stays a program address for case 29's rfid
			}
			w = 31<<26 | rt<<21 | (spr&31)<<16 | (spr>>5)<<11 | xo<<1
		case 24: // lq / stq, mostly aligned, sometimes after settag
			b := base()
			q := uint32(12 + 2*r.Intn(10))
			dq := d(16)
			if r.Intn(8) == 0 {
				dq = d(4)
			}
			if r.Intn(2) == 0 {
				w = 56<<26 | q<<21 | b<<16 | dq&0xfff0 | uint32(r.Intn(16))
				if r.Intn(8) == 0 {
					w = 56<<26 | q<<21 | b<<16 | dq | uint32(r.Intn(16)) // unaligned
				}
			} else {
				if r.Intn(2) == 0 {
					words = append(words, 0x7c0103e6) // settag
				}
				w = 62<<26 | q<<21 | b<<16 | dq&0xfffc | 2
			}
		case 25: // lmd / stmd
			first := uint32(20 + r.Intn(12))
			w = []uint32{58, 62}[r.Intn(2)]<<26 | first<<21 | base()<<16 | d(8) | 3
		case 26: // cmpla, TX trap, mcrxrt
			switch r.Intn(3) {
			case 0:
				w = 31<<26 | (uint32(r.Intn(8))<<2|1)<<21 | uint32(r.Intn(32))<<16 | uint32(r.Intn(32))<<11 | 64<<1
			case 1:
				w = 31<<26 | uint32(r.Intn(2))<<21 | uint32(r.Intn(16))<<11 | uint32(r.Intn(16))<<7 | 36<<1
			default:
				w = 31<<26 | uint32(r.Intn(8))<<23 | 544<<1
			}
		case 28: // AS lsdx after setting a short XER length (0..12)
			words = append(words, 14<<26|11<<21|uint32(r.Intn(13))) // li r11, n
			words = append(words, 31<<26|11<<21|1<<16|467<<1)       // mtxer r11
			// lsdx: RA=0 keeps EA in memory; RT 7..16 keeps even a 16-register load
			// (XER length left random by a skipped mtxer) off the base registers.
			w = 31<<26 | uint32(7+r.Intn(10))<<21 | base()<<11 | 565<<1
		case 29: // rfid to the next instruction with a reservation held
			// The harness's handlers skip the interrupted instruction, so
			// SRR0 is set twice and survives one skipped setup word.
			b := base()
			after := uint32(0x1000 + 4*(len(words)+8))
			li, mtsrr0 := 14<<26|11<<21|after, uint32(31<<26|11<<21|26<<16|467<<1)
			words = append(words, li, mtsrr0, li, mtsrr0,
				31<<26|12<<21|83<<1,         // mfmsr r12
				31<<26|12<<21|27<<16|467<<1, // mtsrr1 r12
				31<<26|12<<21|b<<11|84<<1,   // ldarx r12, 0, b
				19<<26|18<<1)                // rfid
			w = 31<<26 | 12<<21 | b<<11 | 214<<1 | 1 // stdcx. r12, 0, b
		case 30: // AS region td (TO 28/29/30) on nearby, small or zero operands
			src := uint32(reg())
			switch r.Intn(3) {
			case 0:
				words = append(words, 14<<26|11<<21|src<<16|uint32(r.Intn(0x10000))) // addi r11, src, si
			case 1:
				words = append(words, 14<<26|11<<21|uint32(r.Intn(0x10000))) // li r11, si
			default:
				words = append(words, 14<<26|11<<21) // li r11, 0
			}
			to := []uint32{28, 29, 30}[r.Intn(3)]
			if r.Intn(2) == 0 {
				w = 31<<26 | to<<21 | 11<<16 | src<<11 | 68<<1
			} else {
				w = 31<<26 | to<<21 | src<<16 | 11<<11 | 68<<1
			}
		case 32: // AS rfscv to the next instruction (MSR from CTR, PC from LR)
			after := uint32(0x1000 + 4*(len(words)+8))
			li, mtlr := 14<<26|11<<21|after, uint32(31<<26|11<<21|8<<16|467<<1)
			mfmsr, mtctr := uint32(31<<26|12<<21|83<<1), uint32(31<<26|12<<21|9<<16|467<<1)
			words = append(words, li, mtlr, li, mtlr, mfmsr, mtctr, mfmsr, mtctr)
			w = 19<<26 | 82<<1
		case 31: // lfd lfdu stfd stfdu
			w = []uint32{50, 51, 54, 55}[r.Intn(4)]<<26 | uint32(r.Intn(32))<<21 | base()<<16 | d(1)
		case 27: // mtmsrd L=1: random EE/RI, with DEC writes making interrupts pending
			w = 31<<26 | rt<<21 | 1<<16 | 178<<1
		default: // simple adds keep register values varied
			w = 31<<26 | rt<<21 | ra<<16 | rb<<11 | 266<<1
		}
		words = append(words, w)
	}
	return words
}

func jitTestMachine(t *testing.T, seed int64, msr uint64, as bool, jit, htab bool) *Machine {
	cfg := Config{Memory: 1 << 20, CPUs: 2, MIPS: 7}
	if as {
		cfg.Extensions = []string{"as"}
	}
	m := NewMachine(cfg)
	if !jit {
		m.SetJIT(false)
	} else if !m.SetJIT(true) {
		t.Skip("no native JIT on this host")
	}
	m.StopAllInterrupts = false
	m.IdentitySegments = true
	if htab {
		if err := m.SetHashedPageTable(2048); err != nil {
			t.Fatal(err)
		}
	}
	for ea := uint64(0); ea < 1<<20; ea += 4096 {
		if err := m.MapPage(ea>>28, 0, ea&(1<<28-1), 12, PTE{Real: ea, Write: ea >= 0x10000, Execute: true}); err != nil {
			t.Fatal(err)
		}
	}
	r := rand.New(rand.NewSource(seed))
	code := jitProgram(r, 3000)
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	for a := 0x10000; a < 0xf0000; a++ {
		m.Mem[a] = byte(r.Intn(256))
	}
	if as {
		// Tagged pointer-like quadwords exercise lq's tag and type status.
		for k := 0; k < 4000; k++ {
			q := uint64(0x1000 + r.Intn(0xe000))
			m.Mem[q*16] = []byte{0xa0, 0xa1, 0xa4, 0xa8, 0xaf, 0x00, 0x40, 0xc0}[r.Intn(8)]
			if r.Intn(2) == 0 {
				m.Mem[q*16] = 0xa0 | byte(r.Intn(16))
			}
			m.tags[q>>6] |= 1 << (q & 63)
		}
	}
	// Interrupt vectors return to the program at the next instruction.
	for _, v := range []uint64{0x300, 0x380, 0x400, 0x480, 0x600, 0x700, 0x800, 0x900, 0xc00, 0xf20, 0xf40} {
		binary.BigEndian.PutUint32(m.Mem[v:], 0x7c7a02a6)    // mfsrr0 r3
		binary.BigEndian.PutUint32(m.Mem[v+4:], 0x38630004)  // addi r3,r3,4
		binary.BigEndian.PutUint32(m.Mem[v+8:], 0x7c7a03a6)  // mtsrr0 r3
		binary.BigEndian.PutUint32(m.Mem[v+12:], 0x4c000024) // rfid
	}
	for _, c := range m.CPUs {
		for i := range c.GPR {
			c.GPR[i] = r.Uint64()
			if r.Intn(3) == 0 {
				c.GPR[i] = uint64(r.Intn(5)) - 2
			}
		}
		for i := 1; i <= 6; i++ {
			c.GPR[i] = 0x40000 + uint64(r.Intn(0x80000))
		}
		c.GPR[7], c.GPR[8] = uint64(r.Intn(64)), uint64(r.Intn(64))
		c.GPR[9], c.GPR[10] = 0x1000+uint64(4*r.Intn(3000)), 0x1000+uint64(4*r.Intn(3000))
		c.CR, c.XER, c.LR, c.CTR = r.Uint32(), r.Uint64()&0xffffffff, c.GPR[9], uint64(r.Intn(20))
		c.MSR = msr | MSRME
		if seed%2 == 0 {
			c.MSR |= MSRFP // FP loads/stores run natively; odd seeds raise FP unavailable
		}
		c.PC = 0x1000 + uint64(4*r.Intn(100))
	}
	return m
}

func TestJITMatchesInterpreter(t *testing.T) {
	modes := []struct {
		name   string
		msr    uint64
		as     bool
		breaks bool
		htab   bool
	}{
		{"hashed-page-table", MSRSF | MSRIR | MSRDR, true, false, true},
		{"breakpoints", MSRSF | MSRIR | MSRDR, true, true, false},
		{"real64", MSRSF, false, false, false},
		{"translated64", MSRSF | MSRIR | MSRDR, false, false, false},
		{"translated32", MSRIR | MSRDR, false, false, false},
		{"as-real", MSRSF, true, false, false},
		{"as-translated", MSRSF | MSRIR | MSRDR, true, false, false},
		{"as-tags-active", MSRSF | MSRIR | MSRDR | MSRTA, true, false, false},
		{"as-problem", MSRSF | MSRIR | MSRDR | MSRPR, true, false, false},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			for seed := int64(1); seed <= jitFuzzSeeds; seed++ {
				want := jitTestMachine(t, seed, mode.msr, mode.as, false, mode.htab)
				got := jitTestMachine(t, seed, mode.msr, mode.as, true, mode.htab)
				churn := rand.New(rand.NewSource(seed * 7))
				if mode.breaks {
					r := rand.New(rand.NewSource(seed))
					for k := 0; k < 30; k++ {
						a := 0x1000 + uint64(4*r.Intn(3000))
						want.Breakpoints[a], got.Breakpoints[a] = true, true
					}
				}
				for step := 0; step < 40; step++ {
					rw, errw := want.Run(5000)
					rg, errg := got.Run(5000)
					if rw != rg || (errw == nil) != (errg == nil) {
						t.Fatalf("seed %d step %d: stop %v/%v, want %v/%v", seed, step, rg, errg, rw, errw)
					}
					if want.StateDigest() != got.StateDigest() {
						for i := range want.CPUs {
							w, g := want.CPUs[i], got.CPUs[i]
							if w.PC != g.PC || w.GPR != g.GPR || w.CR != g.CR || w.XER != g.XER || w.LR != g.LR || w.CTR != g.CTR {
								t.Fatalf("seed %d step %d cpu %d: pc %x/%x cr %08x/%08x xer %x/%x lr %x/%x ctr %x/%x\ngpr %x\nwant %x", seed, step, i,
									g.PC, w.PC, g.CR, w.CR, g.XER, w.XER, g.LR, w.LR, g.CTR, w.CTR, g.GPR, w.GPR)
							}
						}
						t.Fatalf("seed %d step %d: state differs (memory or tags)", seed, step)
					}
					if mode.htab {
						// Remap data pages to other real pages, or clear change
						// bits, identically on both machines.
						for k := 0; k < 20; k++ {
							ea := 0x40000 + uint64(churn.Intn(0x80))*4096
							real := 0x40000 + uint64(churn.Intn(0x80))*4096
							clean := churn.Intn(2) == 0
							for _, m := range []*Machine{want, got} {
								slot, ok := m.CPUs[0].HPTESlot(ea)
								if !ok {
									t.Fatalf("no slot for %x", ea)
								}
								dw0, dw1, _ := m.HPTERead(slot)
								if clean {
									dw1 &^= 0x180
								} else {
									dw1 = dw1&^hpteRPNMask | real
								}
								if err := m.HPTEWrite(slot, dw0, dw1); err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					if rw.Kind == "breakpoint" {
						continue
					}
					if rw.Kind != "budget" {
						if seed <= 3 {
							t.Logf("seed %d step %d stop %v", seed, step, rw)
						}
						break
					}
				}
				if s := got.JITStats(); seed == 1 {
					t.Logf("stats %+v", s)
				}
				if s := got.JITStats(); s.NativeInstructions == 0 {
					t.Fatalf("seed %d: no native execution: %+v", seed, s)
				}
			}
		})
	}
}

// TestJITSelfModifyingCode stores over an instruction that has already been
// compiled; the next execution must see the new instruction.
func TestJITSelfModifyingCode(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, MIPS: 100})
	if !m.SetJIT(true) {
		t.Skip("no native JIT on this host")
	}
	m.StopAllInterrupts = false
	c := m.CPUs[0]
	prog := []uint32{
		0x38600001, // 0x1000 li r3,1
		0x38800000, // 0x1004 li r4,0
		0x7c632214, // 0x1008 add r3,r3,r4   (patched to addi r3,r3,100)
		0x90a60000, // 0x100c stw r5,0(r6)   (patch the add)
		0x4bfffff8, // 0x1010 b 0x1008
	}
	for i, w := range prog {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	c.MSR = MSRSF | MSRME
	c.PC = 0x1000
	c.GPR[5], c.GPR[6] = 0x38630064, 0x1008
	if _, err := m.Run(5 + 3*4); err != nil {
		t.Fatal(err)
	}
	// One add of zero, then the patched addi ran four times.
	if c.GPR[3] != 1+4*100 {
		t.Fatalf("r3 = %d, want %d (stats %+v)", c.GPR[3], 1+4*100, m.JITStats())
	}
}
