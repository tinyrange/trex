package s390

import (
	"testing"
	"time"
)

// BenchmarkInterpreter runs a loop of common instructions (loads, stores,
// address arithmetic, register arithmetic, a compare, MVC, CLC and a
// branch on count) with DAT on, and reports nanoseconds per instruction.
func BenchmarkInterpreter(b *testing.B) {
	code := []byte{
		0x58, 0x20, 0x60, 0x00, // L 2,0(,6)
		0x41, 0x22, 0x00, 0x01, // LA 2,1(2)
		0x50, 0x20, 0x60, 0x00, // ST 2,0(,6)
		0x18, 0x42, // LR 4,2
		0x1a, 0x45, // AR 4,5
		0x19, 0x45, // CR 4,5
		0xd2, 0x0f, 0x61, 0x00, 0x62, 0x00, // MVC X'100'(16,6),X'200'(6)
		0xd5, 0x0f, 0x61, 0x00, 0x62, 0x00, // CLC X'100'(16,6),X'200'(6)
		0x47, 0x80, 0x70, 0x22, // BC 8,X'22'(,7) (taken: next)
		0x46, 0x30, 0x70, 0x00, // BCT 3,0(,7)
	}
	m := NewMachine(Config{Memory: 4 << 20, Start: time.Date(2003, 11, 1, 12, 0, 0, 0, time.UTC), NoIdleSkip: true})
	c := m.CPUs[0]
	copy(m.S.Mem[0x1000:], append(code, stop()...))
	setupStop(m)
	be.PutUint64(m.S.Mem[pswPgmNew:], 0x000A0000_0000DEAD)
	// Identity-mapped first 64 KB: segment 0's page table at 0x11000.
	be.PutUint32(m.S.Mem[0x10000:], 0x00011000)
	for p := uint32(0); p < 16; p++ {
		be.PutUint32(m.S.Mem[0x11000+p*4:], p<<12)
	}
	c.CR[0] = 0x00b00000 // 4K pages, 1M segments
	c.CR[1] = 0x00010000
	c.GR[6], c.GR[7] = 0x8000, 0x1000
	const perLoop = 10
	const loops = 1_000_000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Stopped = false
		c.loadPSW(0x040C0000_80001000) // DAT on, key 0
		c.GR[3] = loops
		if r := m.Run(perLoop*loops + 100); r.Kind != "disabled-wait" || c.GR[3] != 0 {
			b.Fatalf("stopped %v, GR3 %d, program old PSW %X code %X", r, c.GR[3], m.S.Mem[0x28:0x30], m.S.Mem[0x8c:0x90])
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*perLoop*loops), "ns/instr")
}
