package r3000

// The GE5 HQ1 sequences a 40-bit microstore, the host FIFO and the RE2
// register bus. The low 32 bits of a FIFO word carry host data, and
// the high 8 bits form the dispatch index.
type ip12GE5 struct {
	code            [16384]uint64
	data            [8192]uint32
	fifo            [512]uint64
	head, queued    uint16
	pc, memptr      uint16
	hostPC          uint16
	fetchPC         uint16
	savedPC         uint16
	indirectPC      uint16
	indirectTarget  uint16
	fetchToken      uint8
	reads, writes   uint64
	reptr, sp       uint8
	stack           [8]uint16
	finish          [2]uint32
	bus             uint64
	dmaCount        uint32
	wait            ge5Wait
	irq, singleStep bool
	condition       bool
	clock           uint64
	phase           uint8
	fpu             ip12WTL3132
}

type ge5Wait uint8

const (
	ge5Halted ge5Wait = iota
	ge5Running
	ge5WaitFIFO
	ge5WaitRaster
	ge5WaitDMA
)

func (g *ip12GE5) push(word uint64) {
	if g.queued == uint16(len(g.fifo)) {
		return
	}
	g.fifo[(g.head+g.queued)&511] = word
	g.writes++
	g.queued++
	if g.wait == ge5WaitFIFO {
		g.wait = ge5Running
	}
}

func (g *ip12GE5) run(cycles uint64, raster *ip12RE2, cwen bool, dma *ip12GraphicsDMA, pic *ip12PIC) {
	if g.wait == ge5WaitDMA && dma.active {
		g.wait = ge5Running
	}
	if g.wait != ge5Running || cycles < g.clock {
		return
	}
	// The HQ1 has a 10 MHz crystal. Advance by 3.6 CPU clocks per word.
	g.clock = cycles + 3
	g.phase += 3
	if g.phase >= 5 {
		g.phase -= 5
		g.clock++
	}
	g.step(raster, cwen, dma, pic)
	if g.singleStep {
		g.wait = ge5Halted
	}
}

func (g *ip12GE5) step(raster *ip12RE2, cwen bool, dma *ip12GraphicsDMA, pic *ip12PIC) {
	word := g.code[g.pc&0x3fff]
	source, dest := (word>>38)&3, (word>>33)&3
	control := (word >> 29) & 15
	next := (g.pc + 1) & 0x3fff
	var op uint8
	var imm uint16
	if word&(1<<36) != 0 {
		second := g.code[next]
		op, imm = uint8(second>>32)&0xfe, uint16(second>>19)&0x3fff
		next = (next + 1) & 0x3fff
	}

	hostRead := control == 15 && source == 1
	hostWrite := control == 15 && dest == 1
	if (hostRead || hostWrite) && (dma == nil || !dma.active) {
		g.wait = ge5WaitDMA
		return
	}
	if source == 1 && !hostRead && g.queued == 0 {
		g.wait = ge5WaitFIFO
		return
	}

	mem, re := g.memptr, g.reptr
	switch op {
	case 0x8c:
		re = uint8(g.bus) & 0x3f
	case 0x90:
		mem, re = uint16(g.bus)&0x7fff, uint8(imm)&0x3f
	case 0x9c:
		re = uint8(imm) & 0x3f
	case 0xb0:
		mem = uint16(g.bus) & 0x7fff
	case 0xb4, 0xb6, 0xb8:
		mem = imm
	}
	if word&(1<<35) != 0 {
		mem = (mem + 1) & 0x7fff
	}
	if word&(1<<37) != 0 {
		re = (re + 1) & 0x3f
	}
	if source == 0 && !raster.canRead(re) {
		g.wait = ge5WaitRaster
		return
	}

	if dest == 0 && !raster.canWrite(re) {
		g.wait = ge5WaitRaster
		return
	}

	switch op {
	case 0xb6:
		g.finish[imm&1] = 1
	case 0xfc:
		if imm != 0 {
			g.irq = true
		}
	case 0xfe:
		if imm != 0 {
			g.dmaCount = uint32(g.bus)
		} else {
			g.dmaCount = 0
		}
	}

	priorBus := g.bus
	switch source {
	case 0:
		g.bus = uint64(raster.read(re))
	case 1:
		if hostRead {
			value, ok := dma.word(pic, false, 0)
			if !ok {
				g.wait = ge5WaitDMA
				return
			}
			g.bus = uint64(value)
		} else {
			g.bus = g.fifo[g.head]
			g.head = (g.head + 1) & 511
			g.queued--
			g.reads++
		}
	case 2:
		g.bus = uint64(g.data[mem&0x1fff])
	case 3:
		g.bus = uint64(g.fpu.output)
	}
	if hostWrite {
		if _, ok := dma.word(pic, true, uint32(g.bus)); !ok {
			g.wait = ge5WaitDMA
			return
		}
	}
	if op == 0x3c {
		switch imm {
		case 0:
			g.bus = uint64(g.savedPC)
		case 1:
			g.bus = uint64(g.memptr)
		case 2:
			g.bus = uint64(g.reptr)
		default:
			g.bus = priorBus
		}
	}
	if op != 0xb8 {
		g.memptr = mem
	}
	g.reptr = re

	take, call := false, false
	negative := uint32(g.bus)>>31 != 0
	switch control {
	case 1, 4:
		take, call = true, control == 4
	case 2, 5:
		take, call = g.condition, control == 5
	case 3, 6:
		take, call = !g.condition, control == 6
	case 7:
		g.sp = (g.sp - 1) & 7
		next = g.stack[g.sp]
	case 8:
		next = uint16(g.bus>>31) & 0x1fe
		g.fetchPC, g.fetchToken = g.pc, uint8(g.bus>>32)
		g.savedPC = g.pc
	case 9:
		next = uint16(g.bus) & 0x3fff
		if word&(1<<36) == 0 {
			// Short-form indirect branch consumes the preceding bus
			// latch, which the context restore code loads from WTL.
			next = uint16(priorBus) & 0x3fff
		}
		g.indirectPC, g.indirectTarget = g.pc, next
	case 10, 13:
		take, call = negative, control == 13
	case 11, 14:
		take, call = !negative, control == 14
	case 12:
		g.pc, g.wait = next, ge5Halted
		return
	case 15:
		if g.dmaCount != 0 {
			g.dmaCount--
		}
		if g.dmaCount != 0 {
			next = g.pc
		}
	}
	if take {
		if call {
			g.stack[g.sp] = next
			g.sp = (g.sp + 1) & 7
		}
		next = imm
	}

	fpu := ((word & 0x1ffff800) << 5) | ((word & 0x7ff) << 2) | 2
	if cwen {
		fpu |= 1 << 15
	}
	if source == 3 {
		fpu |= 2 << 13
	}
	switch dest {
	case 0:
		raster.write(re, uint32(g.bus))
	case 2:
		g.data[mem&0x1fff] = uint32(g.bus)
	case 3:
		g.fpu.input = uint32(g.bus)
		fpu |= 3 << 13
	}

	// HQ1 samples the previous WTL condition line before the FPU clock.
	g.condition = g.fpu.condition
	g.fpu.step(fpu, control == 8)
	g.pc = next
}
