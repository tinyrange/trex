package r3000

import (
	"encoding/binary"
	"math"
)

func (m *IP24) nextDeviceEvent() uint64 {
	next := uint64(math.MaxUint64)
	for _, deadline := range [...]uint64{m.vdma.deadline, m.keyboard.deadline, m.int3.nextIRQ()} {
		if deadline != 0 {
			next = min(next, deadline)
		}
	}
	if m.newport != nil {
		next = min(next, m.newport.nextRetrace)
	}
	return next
}

// Cycle time can advance in batches when the guest provably repeats its
// CPU/RAM state. Device changes and clock-register accesses break the proof.
func (m *IP24) idleCycles(limit uint64) uint64 {
	limit = min(limit, 2_000_000)
	now := m.cycles
	deadline := m.nextDeviceEvent()
	if deadline <= now {
		return 0
	}
	limit = min(limit, deadline-now)
	// Count increments after every even CPU cycle. An already-latched
	// interrupt stays set, including when Compare wraps around.
	if m.cpu.cp0[cause]&(1<<15) == 0 {
		distance := uint64(uint32(m.cpu.cp0[11]) - uint32(m.cpu.cp0[9]))
		if distance == 0 {
			distance = 1 << 32
		}
		limit = min(limit, distance*2-(now&1))
	}
	return limit
}

// The upstream PIT counts at 1 MHz. Only a downstream counter expiring can
// alter the interrupt lines, so intermediate ticks can be aggregated.
func (d *ip12INT) nextIRQ() uint64 {
	var pulses uint32
	for i := range d.counter[:2] {
		count := d.counter[i].count
		if count != 0 && (pulses == 0 || count < pulses) {
			pulses = count
		}
	}
	source := &d.counter[2]
	if pulses == 0 || source.count == 0 || pulses > 1 && source.mode != 2 && source.mode != 3 {
		return 0
	}
	ticks := uint64(source.count) + uint64(pulses-1)*uint64(source.reload)
	return (d.microseconds + ticks) * (ip24Clock / 1_000_000)
}

func (m *IP24) advanceIdle(cycles uint64) {
	c := &m.cpu
	ticks := (cycles + (m.cycles & 1)) / 2
	count := uint32(c.cp0[9])
	distance := uint64(uint32(c.cp0[11]) - count)
	if distance == 0 {
		distance = 1 << 32
	}
	if ticks >= distance {
		c.cp0[cause] |= 1 << 15
	}
	c.cp0[9] = uint64(count + uint32(ticks))

	random, wired := c.cp0[1], c.cp0[6]
	top := uint64(len(c.tlb) - 1)
	if random > wired && cycles <= random-wired {
		c.cp0[1] -= cycles
	} else {
		remaining := cycles - 1
		if random > wired {
			remaining -= random - wired
		}
		c.cp0[1] = top
		if wired < top {
			c.cp0[1] -= remaining % (top - wired + 1)
		}
	}
	m.cycles += cycles
	m.int3.updatePIT((m.cycles - 1) / (ip24Clock / 1_000_000))
}

// countdown recognizes a two-instruction bgtz/subu loop on RAM. It skips
// complete taken iterations and leaves the exit branch to the interpreter.
func (m *IP24) countdown(limit uint64) uint64 {
	c := &m.cpu
	pc := c.pc
	if c.delaySlot {
		pc -= 4
		if c.next != pc {
			return 0
		}
	} else if c.next != pc+4 {
		return 0
	}
	if pc&3 != 0 || pc < mipsWord(0x80000000) || pc > mipsWord(0xbffffff8) || !c.kernel() {
		return 0
	}
	code := m.memory(pc&0x1fffffff, 8)
	if code == nil {
		return 0
	}
	branch, decrement := binary.BigEndian.Uint32(code[:4]), binary.BigEndian.Uint32(code[4:])
	reg := (branch >> 21) & 31
	stepReg := (decrement >> 16) & 31
	if reg == 0 || stepReg == reg || branch != 0x1c00ffff|reg<<21 ||
		decrement != 0x23|reg<<21|stepReg<<16|reg<<11 {
		return 0
	}
	a, step := c.gpr[reg], c.gpr[stepReg]
	if a == 0 || step == 0 || a > 0x7fffffff || step > 0x7fffffff {
		return 0
	}
	iterations := (a + step - 1) / step
	if c.delaySlot {
		iterations = (a - 1) / step
	}
	iterations = min(iterations, limit/2)
	if iterations == 0 {
		return 0
	}
	c.gpr[reg] = mipsWord(uint32(a - iterations*step))
	return iterations * 2
}

// A proof can observe RAM and keep a bounded journal of temporary writes.
// The loop is repeatable only if it leaves the CPU and all RAM unchanged.
type ip24LoopBus struct {
	machine *IP24
	writes  map[uint64]byte
}

func (b *ip24LoopBus) read64(address uint64, size uint32) (uint64, bool) {
	data := b.machine.memory(address, uint64(size))
	if data == nil {
		return 0, false
	}
	if len(b.writes) != 0 {
		var value uint64
		for i, original := range data {
			valueByte, ok := b.writes[loopRAMOffset(address)+uint64(i)]
			if !ok {
				valueByte = original
			}
			value = value<<8 | uint64(valueByte)
		}
		return value, true
	}
	switch size {
	case 1:
		return uint64(data[0]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(data)), true
	case 4:
		return uint64(binary.BigEndian.Uint32(data)), true
	case 8:
		return binary.BigEndian.Uint64(data), true
	}
	return 0, false
}

func (b *ip24LoopBus) write64(address uint64, size uint32, value uint64) bool {
	data := b.machine.memory(address, uint64(size))
	if data == nil {
		return false
	}
	for i, original := range data {
		offset := loopRAMOffset(address) + uint64(i)
		next := byte(value >> (8 * (len(data) - i - 1)))
		if next == original {
			delete(b.writes, offset)
			continue
		}
		if b.writes == nil {
			b.writes = make(map[uint64]byte)
		}
		b.writes[offset] = next
		if len(b.writes) > 64 {
			return false
		}
	}
	return true
}

func loopRAMOffset(address uint64) uint64 {
	if address >= ip24RAMBase {
		return address - ip24RAMBase
	}
	return address
}

func (m *IP24) repeatingLoop(limit uint64) uint64 {
	const maxProbeInstructions = 384
	original := &m.cpu
	probe := *original
	bus := ip24LoopBus{machine: m}
	for length := uint64(1); length <= maxProbeInstructions; length++ {
		executed := probe.step(&bus)
		if executed.exception >= 0 {
			return 0
		}
		word := executed.word
		if word>>26 == 16 {
			format, reg := word>>21&31, word>>11&31
			switch format {
			case 0, 1:
				if reg == 1 || reg == 9 {
					return 0
				}
			case 4, 5:
				if reg != status {
					return 0
				}
			default:
				// CP0 writes and TLB instructions can depend on cycle time.
				return 0
			}
		}
		if probe.pc == original.pc && probe == *original && len(bus.writes) == 0 {
			return limit / length * length
		}
	}
	return 0
}

func (m *IP24) batchLoop(repeatedPC bool, limit uint64) uint64 {
	if len(m.breaks) != 0 || m.cpu.cp0[status]&7 == 1 && m.cpu.cp0[status]&m.cpu.cp0[cause]&0xff00 != 0 {
		return 0
	}
	limit = m.idleCycles(limit)
	if limit < 8 {
		return 0
	}
	n := m.countdown(limit)
	if n == 0 && repeatedPC {
		n = m.repeatingLoop(limit)
	}
	if n != 0 {
		m.advanceIdle(n)
	}
	return n
}
