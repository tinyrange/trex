package power

import (
	"encoding/binary"
	"testing"
)

// TestJITCounterReads checks that native time-base and instruction-count
// reads see the interpreter's count at every position in a block, across
// chained blocks and run boundaries.
func TestJITCounterReads(t *testing.T) {
	mfspr := func(rt, spr uint32) uint32 { return 31<<26 | rt<<21 | (spr&31)<<16 | (spr>>5)<<11 | 339<<1 }
	prog := []uint32{
		0x38a50001,    // addi r5,r5,1
		mfspr(3, 268), // mftb r3
		0x38a50001,    // addi r5,r5,1
		mfspr(4, 848), // IC
		mfspr(6, 309), // PURR
		0x2c050010,    // cmpwi r5,16
		0x4180ffe8,    // blt 0x1000
		mfspr(7, 849), // VTB
		0x48000000,    // b .
	}
	run := func(jit bool) *Machine {
		m := NewMachine(Config{Memory: 1 << 20, MIPS: 7})
		if !jit {
			m.SetJIT(false)
		} else if !m.SetJIT(true) {
			t.Skip("no native JIT on this host")
		}
		m.StopAllInterrupts = false
		for i, w := range prog {
			binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
		}
		c := m.CPUs[0]
		c.MSR, c.PC = MSRSF|MSRME, 0x1000
		c.mtspr(848, 1000)
		c.mtspr(309, 7)
		c.mtspr(849, 99)
		for _, n := range []uint64{3, 17, 1, 40, 200} {
			m.Run(n)
		}
		return m
	}
	want, got := run(false), run(true)
	wc, gc := want.CPUs[0], got.CPUs[0]
	if wc.GPR != gc.GPR || wc.PC != gc.PC {
		t.Fatalf("got r3 %x r4 %x r6 %x r7 %x pc %x, want r3 %x r4 %x r6 %x r7 %x pc %x",
			gc.GPR[3], gc.GPR[4], gc.GPR[6], gc.GPR[7], gc.PC, wc.GPR[3], wc.GPR[4], wc.GPR[6], wc.GPR[7], wc.PC)
	}
}

// TestJITQuadwordTags runs lq with every pointer-type mask over tagged and
// untagged quadwords whose headers select each status path, recording XER
// after each, then stq with and without settag, comparing native and
// interpreted state.
func TestJITQuadwordTags(t *testing.T) {
	headers := []byte{0xa0, 0xa5, 0xaf, 0x00, 0x20, 0x40, 0x80, 0xc0, 0xe0}
	var prog []uint32
	slot := uint32(0)
	for pt := uint32(0); pt < 16; pt++ {
		for i := range headers {
			for _, off := range []uint32{uint32(32 * i), uint32(32*i + 16)} {
				prog = append(prog, 56<<26|12<<21|1<<16|off|pt, // lq r12,off(r1),pt
					31<<26|15<<21|1<<16|339<<1, // mfxer r15
					62<<26|15<<21|3<<16|8*slot) // std r15,8*slot(r3)
				slot++
			}
		}
	}
	prog = append(prog, 0x7c0103e6, 62<<26|12<<21|2<<16|2, 62<<26|12<<21|2<<16|16|2, 0x48000000)
	run := func(jit bool) *Machine {
		m := NewMachine(Config{Memory: 1 << 20, MIPS: 100, Extensions: []string{"as"}})
		if !jit {
			m.SetJIT(false)
		} else if !m.SetJIT(true) {
			t.Skip("no native JIT on this host")
		}
		m.StopAllInterrupts = false
		for i, w := range prog {
			binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
		}
		for i, h := range headers {
			q := uint64(0x8000 + 32*i)
			m.Mem[q] = h
			m.Mem[q+16] = h
			m.tags[(q>>4)>>6] |= 1 << ((q >> 4) & 63) // first copy tagged
		}
		c := m.CPUs[0]
		c.MSR, c.PC = MSRSF|MSRME|MSRTA, 0x1000
		c.GPR[1], c.GPR[2], c.GPR[3] = 0x8000, 0x9000, 0x20000
		m.Run(uint64(len(prog)) + 10)
		return m
	}
	want, got := run(false), run(true)
	if got.JITStats().NativeInstructions < uint64(len(prog))/2 {
		t.Fatalf("mostly interpreted: %+v", got.JITStats())
	}
	if want.StateDigest() != got.StateDigest() {
		for k := uint64(0); k < uint64(slot); k++ {
			w := binary.BigEndian.Uint64(want.Mem[0x20000+8*k:])
			g := binary.BigEndian.Uint64(got.Mem[0x20000+8*k:])
			if w != g {
				t.Fatalf("lq %d: XER %x, want %x", k, g, w)
			}
		}
		t.Fatal("state differs after stq")
	}
}
