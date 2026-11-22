package power

import (
	"encoding/binary"
	"testing"
)

// benchmarkJITLoop runs body (then bdnz back to it) natively with
// translation on, identity segments and a hashed page table, the setup of
// a hashed-page-table guest, and reports host time per guest instruction.
func benchmarkJITLoop(b *testing.B, body ...uint32) {
	m := NewMachine(Config{Memory: 1 << 20, MIPS: 100})
	if !m.SetJIT(true) {
		b.Skip("no native JIT on this host")
	}
	m.StopAllInterrupts = false
	m.IdentitySegments = true
	if err := m.SetHashedPageTable(2048); err != nil {
		b.Fatal(err)
	}
	for ea := uint64(0); ea < 1<<20; ea += 4096 {
		if err := m.MapPage(ea>>28, 0, ea&(1<<28-1), 12, PTE{Real: ea, Write: ea >= 0x10000, Execute: true}); err != nil {
			b.Fatal(err)
		}
	}
	code := append(append([]uint32{}, body...), 0x4200_0000|uint32(-4*len(body))&0xfffc) // bdnz body
	for i, w := range code {
		binary.BigEndian.PutUint32(m.Mem[0x1000+4*i:], w)
	}
	// A leaf function at 0x2000 for call/return loops: blr.
	binary.BigEndian.PutUint32(m.Mem[0x2000:], 0x4e800020)
	c := m.CPUs[0]
	c.MSR = MSRSF | MSRME | MSRIR | MSRDR
	c.PC = 0x1000
	c.CTR = 1 << 62
	for i := 1; i <= 6; i++ {
		c.GPR[i] = 0x40000 + uint64(i)*0x1000
	}
	for i := 1; i < len(m.CPUs); i++ {
		m.CPUs[i].Parked = true
	}
	const run = 1 << 24
	if _, err := m.Run(run); err != nil { // warm the caches and compile
		b.Fatal(err)
	}
	b.ResetTimer()
	start := m.Instructions()
	for i := 0; i < b.N; i++ {
		if _, err := m.Run(run); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	n := m.Instructions() - start
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(n), "ns/insn")
	if s := m.JITStats(); s.NativeInstructions < n/2 {
		b.Fatalf("mostly interpreted: %+v", s)
	}
}

func BenchmarkJITALU(b *testing.B) {
	benchmarkJITLoop(b,
		0x38630001, // addi r3,r3,1
		0x7c832214, // add r4,r3,r4
		0x5485103a, // rlwinm r5,r4,2,0,29
		0x7ca63378, // or r6,r5,r6 (r6 is a base; harmless here)
		0x7c871a78, // xor r7,r4,r3
		0x3908ffff, // addi r8,r8,-1
		0x7d294214, // add r9,r9,r8
		0x794a0fa4, // rldicr r10,r10,1,62
	)
}

func BenchmarkJITCompareBranch(b *testing.B) {
	benchmarkJITLoop(b,
		0x38630001, // addi r3,r3,1
		0x2c030000, // cmpwi r3,0
		0x41820008, // beq +8 (not taken)
		0x38840001, // addi r4,r4,1
		0x7c032000, // cmpw r3,r4
		0x40820008, // bne +8 (taken)
		0x60000000, // nop (skipped)
		0x60000000, // nop
	)
}

func BenchmarkJITLoad(b *testing.B) {
	benchmarkJITLoop(b,
		0xe8e10000, // ld r7,0(r1)
		0xe9010008, // ld r8,8(r1)
		0x81220010, // lwz r9,16(r2)
		0x89430018, // lbz r10,24(r3)
		0xe9640020, // ld r11,32(r4)
		0xe9850028, // ld r12,40(r5)
		0x81a60030, // lwz r13,48(r6)
		0xe9c10038, // ld r14,56(r1)
	)
}

func BenchmarkJITStore(b *testing.B) {
	benchmarkJITLoop(b,
		0xf8e10000, // std r7,0(r1)
		0xf9010008, // std r8,8(r1)
		0x91220010, // stw r9,16(r2)
		0x99430018, // stb r10,24(r3)
		0xf9640020, // std r11,32(r4)
		0xf9850028, // std r12,40(r5)
		0x91a60030, // stw r13,48(r6)
		0xf9c10038, // std r14,56(r1)
	)
}

func BenchmarkJITCallReturn(b *testing.B) {
	benchmarkJITLoop(b,
		0x48000000|uint32(0x2000-0x1000)|1, // bl 0x2000 (blr returns through the branch cache)
		0x38630001,                         // addi r3,r3,1
	)
}
