package r3000

import (
	"encoding/binary"
	"time"

	"github.com/tinyrange/trex/channel"
)

type ioCacheBlock struct {
	physical, logical, mask uint32
	data                    [8]uint32
}

func (m *Machine) boardIO(offset, size, value uint32, write bool) (uint32, bool) {
	lane := offset & 7
	if offset >= 0x240 || lane+size > 4 {
		return 0, false
	}
	reg := offset &^ 7
	cell := &m.board[reg/8]
	selector := m.board[0x30/8]
	cache := &m.ioCache[selector>>2&7]
	switch reg {
	case 0x48:
		cell = &cache.physical
	case 0x50:
		cell = &cache.logical
	case 0x58:
		cell = &cache.mask
	case 0x60:
		cell = &cache.data[(selector&3)*2]
	case 0x68:
		cell = &cache.data[(selector&3)*2+1]
	}
	mask := uint32(0xffffffff) >> (32 - size*8)
	if !write {
		if reg == 0x230 {
			m.timerIRQ = false
		}
		return (*cell >> (lane * 8)) & mask, true
	}
	switch reg {
	case 8, 0x10, 0x200, 0x208, 0x218, 0x238:
		return 0, true
	}
	shift := lane * 8
	next := *cell&^(mask<<shift) | (value&mask)<<shift
	if reg == 0x58 {
		next |= *cell
	}
	if reg >= 0x108 && reg < 0x200 && reg&31 == 8 && *cell&0x101 == 1 {
		next = next&^2 | *cell&2
	}
	*cell = next
	if reg >= 0x48 && reg <= 0x68 {
		index := byte(1 << (selector >> 2 & 7))
		if cache.mask != 0 && cache.physical&cache.logical&1 != 0 {
			m.ioPending |= index
		} else {
			m.ioPending &^= index
		}
	}
	if reg == 0x228 {
		m.timerPeriod = (uint64(next) + 1) * (cyclesPerSecond / 1000)
		m.timerNext = m.cycles + m.timerPeriod
		m.timerIRQ = false
	}
	return 0, true
}

func (m *Machine) flushIO(address, size uint32) {
	for i := range m.ioCache {
		if m.ioPending&(1<<i) == 0 {
			continue
		}
		cache := &m.ioCache[i]
		base := cache.physical &^ 1
		if uint64(address)+uint64(size) <= uint64(base) || uint64(base)+32 <= uint64(address) {
			continue
		}
		if uint64(base)+32 <= uint64(len(m.ram)) {
			for lane := uint32(0); lane < 32; lane++ {
				if cache.mask&(1<<lane) != 0 {
					m.ram[base+lane] = byte(cache.data[lane/4] >> (8 * (lane & 3)))
				}
			}
		}
		cache.mask = 0
		cache.physical &^= 1
		cache.logical &^= 1
		m.ioPending &^= 1 << i
	}
}

func (m *Machine) dma(logical uint32, data []byte, toGuest bool) bool {
	for len(data) > 0 {
		slot := uint64(logical>>12) * 8
		base := m.board[0x18/8]
		if base >= 0xa0000000 && base < 0xc0000000 {
			base &= 0x1fffffff
		}
		entry := uint64(base) + slot
		if slot >= uint64(m.board[0x20/8]) || entry+4 > uint64(len(m.ram)) {
			m.board[0x10/8] = logical
			return false
		}
		physical := binary.LittleEndian.Uint32(m.ram[entry:])&^0xfff | logical&0xfff
		n := min(len(data), 4096-int(logical&0xfff))
		if uint64(physical)+uint64(n) > uint64(len(m.ram)) {
			return false
		}
		if m.ioPending != 0 {
			m.flushIO(physical, uint32(n))
		}
		if toGuest {
			copy(m.ram[physical:], data[:n])
		} else {
			copy(data[:n], m.ram[physical:physical+uint32(n)])
		}
		data = data[n:]
		if len(data) > 0 && uint64(logical)+uint64(n) > 0xffffffff {
			return false
		}
		logical += uint32(n)
	}
	return true
}

type serialPort struct {
	guest, host                           *channel.Memory
	dll, dlm, ier, fcr, lcr, mcr, scratch byte
	txIRQ, ready                          bool
	rx                                    byte
}

func (p *serialPort) poll() {
	if p.ready {
		return
	}
	select {
	case <-p.guest.ReadReady():
		var data [1]byte
		if n, _ := p.guest.Read(data[:]); n != 0 {
			p.rx, p.ready = data[0], true
		}
	default:
	}
}

func (p *serialPort) interrupt() byte {
	if p.ier&1 != 0 && p.ready {
		return 4
	}
	if p.ier&2 != 0 && p.txIRQ {
		return 2
	}
	return 1
}

func (p *serialPort) access(reg uint32, data byte, write bool) byte {
	if p.lcr&0x80 != 0 && reg < 2 {
		value := &p.dll
		if reg == 1 {
			value = &p.dlm
		}
		if write {
			*value = data
		}
		return *value
	}
	if write {
		switch reg {
		case 0:
			if p.mcr&0x10 != 0 {
				if !p.ready {
					p.rx, p.ready = data, true
				}
			} else {
				_, _ = p.guest.Write([]byte{data})
			}
			p.txIRQ = true
		case 1:
			if p.ier&2 == 0 && data&2 != 0 {
				p.txIRQ = true
			}
			p.ier = data & 15
		case 2:
			p.fcr = data & 0xc9
			if data&2 != 0 {
				p.ready = false
			}
		case 3:
			p.lcr = data
		case 4:
			p.mcr = data & 31
		case 7:
			p.scratch = data
		}
		return 0
	}
	switch reg {
	case 0:
		p.poll()
		data = p.rx
		p.ready = false
		return data
	case 1:
		return p.ier
	case 2:
		p.poll()
		irq := p.interrupt()
		if irq == 2 {
			p.txIRQ = false
		}
		if p.fcr&1 != 0 {
			irq |= 0xc0
		}
		return irq
	case 3:
		return p.lcr
	case 4:
		return p.mcr
	case 5:
		p.poll()
		return 0x60 | byte(truth(p.ready))
	case 6:
		if p.mcr&16 != 0 {
			return (p.mcr&1)<<5 | (p.mcr&2)<<3 | (p.mcr&4)<<4 | (p.mcr&8)<<4
		}
		return 0xb0
	case 7:
		return p.scratch
	}
	return 0
}

type rtc struct {
	index byte
	regs  [128]byte
	ticks uint64
}

func (r *rtc) init(start time.Time) {
	if start.IsZero() {
		start = time.Date(1991, 4, 1, 0, 0, 0, 0, time.UTC)
	}
	r.regs[0], r.regs[2], r.regs[4] = byte(start.Second()), byte(start.Minute()), byte(start.Hour())
	r.regs[6], r.regs[7], r.regs[8], r.regs[9] = byte(start.Weekday()+1), byte(start.Day()), byte(start.Month()), byte(start.Year()%100)
	r.regs[1], r.regs[3], r.regs[5] = 0xff, 0xff, 0xff
	r.regs[10], r.regs[11], r.regs[13] = 0x26, 6, 0x80
}

func (r *rtc) update(cycles uint64) {
	if r.regs[11]&0x80 != 0 || r.regs[10]&0x70 != 0x20 {
		r.ticks = cycles
		return
	}
	seconds := (cycles - r.ticks) / cyclesPerSecond
	if seconds == 0 {
		return
	}
	r.ticks += seconds * cyclesPerSecond
	bcd := r.regs[11]&4 == 0
	read := func(i int) int {
		v := int(r.regs[i])
		if bcd {
			return (v>>4)*10 + (v & 15)
		}
		return v
	}
	put := func(i int, v int) {
		if bcd {
			v = (v/10)<<4 | v%10
		}
		r.regs[i] = byte(v)
	}
	date := time.Date(1900+read(9), time.Month(read(8)), read(7), read(4), read(2), read(0), 0, time.UTC).Add(time.Duration(seconds) * time.Second)
	put(0, date.Second())
	put(2, date.Minute())
	put(4, date.Hour())
	put(6, int(date.Weekday())+1)
	put(7, date.Day())
	put(8, int(date.Month()))
	put(9, date.Year()%100)
	r.regs[12] |= 0x10
}

func (r *rtc) access(cycles uint64, value byte, write bool) byte {
	r.update(cycles)
	i := r.index
	if write {
		switch i {
		case 10:
			r.regs[i] = value & 0x7f
		case 12, 13:
		default:
			r.regs[i] = value
		}
		return 0
	}
	value = r.regs[i]
	if i == 10 && r.regs[11]&0x80 == 0 && r.regs[10]&0x70 == 0x20 && cycles-r.ticks >= cyclesPerSecond-6100 {
		value |= 0x80
	}
	if i == 12 {
		r.regs[i] = 0
	}
	return value
}
