package cc

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/tinyrange/trex/vmm/ethernet"
	"j5.nz/cc/hypervisor"
)

// 82540EM register interface, legacy RX and legacy/extended TX descriptors.
// Device state and DMA are owned by the platform coordinator. The Ethernet
// endpoint never retains guest memory. Register definitions follow Intel's
// 8254x software interface (also documented by Intel's Linux e1000 driver).
const e1000Address = 0xd1000000
const e1000Size = 0x20000

type e1000 struct {
	config          [256]byte
	regs            [e1000Size / 4]uint32
	eeprom          [64]uint16
	phy             [32]uint16
	port            ethernet.Endpoint
	memory          func(uint64, uint64) ([]byte, error)
	irq             func(bool) error
	asserted        bool
	eeCommand       uint16
	eeBits, eeOut   int
	ioAddress       uint32
	txPacket        []byte
	txContext       [16]byte
	txOptions       byte
	txTSO           bool
	tx, rx, dropped uint64
	trace           []any
}

func newE1000(port ethernet.Endpoint, mac [6]byte, memory func(uint64, uint64) ([]byte, error), irq func(bool) error) *e1000 {
	d := &e1000{port: port, memory: memory, irq: irq}
	binary.LittleEndian.PutUint16(d.config[0:], 0x8086)
	binary.LittleEndian.PutUint16(d.config[2:], 0x100e)
	d.config[4] = 7
	d.config[8] = 3
	d.config[11] = 2
	binary.LittleEndian.PutUint32(d.config[0x10:], e1000Address)
	binary.LittleEndian.PutUint32(d.config[0x14:], 0xc101)
	binary.LittleEndian.PutUint32(d.config[0x2c:], 0x001e8086)
	d.config[0x3c], d.config[0x3d] = 18, 1
	for i := 0; i < 3; i++ {
		d.eeprom[i] = binary.LittleEndian.Uint16(mac[i*2:])
	}
	d.eeprom[0xa] = 0x4408
	d.eeprom[0xb] = 0x001e
	d.eeprom[0xc] = 0x8086
	d.eeprom[0xd] = 0x100e
	d.eeprom[0xe] = 0x8086
	d.eeprom[0xf] = 0x3040
	d.eeprom[0x3f] = 0xbaba
	for _, v := range d.eeprom[:0x3f] {
		d.eeprom[0x3f] -= v
	}
	d.reset()
	return d
}
func (d *e1000) reset() {
	clear(d.regs[:])
	d.regs[0] = 0x00140240
	d.regs[8/4] = 0x80080783
	d.regs[0x10/4] = 0x180
	d.regs[0x1000/4] = 0x30
	d.regs[0x5400/4] = uint32(d.eeprom[0]) | uint32(d.eeprom[1])<<16
	d.regs[0x5404/4] = uint32(d.eeprom[2]) | 1<<31
	d.phy = [32]uint16{0: 0x1140, 1: 0x796d, 2: 0x0141, 3: 0x0c20, 4: 0x0de1, 5: 0x0de1, 6: 1, 9: 0x0300, 10: 0x3c00, 15: 0x3000, 16: 0x0360, 17: 0xac00, 20: 0x0d60}
	d.eeCommand, d.eeBits, d.eeOut = 0, 0, 0
	d.txPacket = nil
	d.txContext = [16]byte{}
	d.txOptions = 0
	d.txTSO = false
}
func (d *e1000) writeConfig(off int, v byte) {
	switch off {
	case 4:
		d.config[off] = v & 7
	case 5:
		d.config[off] = v & 4
	case 0x10, 0x11:
		d.config[off] = 0
	case 0x12:
		d.config[off] = v & 0xfe
	case 0x13:
		d.config[off] = v
	case 0x14:
		d.config[off] = v&0xf8 | 1
	case 0x15, 0x16, 0x17, 0x3c:
		d.config[off] = v
	}
}
func (d *e1000) base() uint64 { return uint64(binary.LittleEndian.Uint32(d.config[0x10:])) }
func (d *e1000) contains(a uint64, n uint8) bool {
	return d.config[4]&2 != 0 && a >= d.base() && a-d.base() < e1000Size && uint64(n) <= e1000Size-(a-d.base())
}
func (d *e1000) syncIRQ() error {
	level := d.regs[0xc0/4]&d.regs[0xd0/4] != 0 && d.config[5]&4 == 0
	if level == d.asserted {
		return nil
	}
	if err := d.irq(level); err != nil {
		return err
	}
	d.asserted = level
	return nil
}
func (d *e1000) cause(v uint32) error { d.regs[0xc0/4] |= v; return d.syncIRQ() }
func (d *e1000) readReg(off uint32) (uint32, error) {
	if off >= e1000Size || off&3 != 0 {
		return 0, fmt.Errorf("unaligned e1000 register %#x", off)
	}
	v := d.regs[off/4]
	if off == 0xc0 {
		d.regs[off/4] = 0
		return v, d.syncIRQ()
	}
	if off >= 0x4000 && off < 0x4100 {
		d.regs[off/4] = 0
	}
	return v, nil
}
func (d *e1000) writeReg(off, v uint32) error {
	if off >= e1000Size || off&3 != 0 {
		return fmt.Errorf("unaligned e1000 register %#x", off)
	}
	if len(d.trace) == 64 {
		copy(d.trace, d.trace[1:])
		d.trace = d.trace[:63]
	}
	d.trace = append(d.trace, []any{int64(off), int64(v)})
	switch off {
	case 0:
		if v&(1<<26) != 0 {
			d.reset()
			return d.syncIRQ()
		}
		d.regs[0] = v &^ (1 << 31)
	case 8:
	case 0x10:
		d.writeEEPROM(v)
	case 0x14:
		d.regs[off/4] = v
		if v&1 != 0 {
			d.regs[off/4] = v&0xff00 | 0x10 | uint32(d.eeprom[(v>>8)&63])<<16
		}
	case 0x20:
		r := (v >> 16) & 31
		result := v | 1<<28
		if (v>>21)&31 != 1 {
			result |= 1 << 30
		} else if v&(1<<27) != 0 {
			result = result&0xffff0000 | uint32(d.phy[r])
		} else if v&(1<<26) != 0 {
			d.phy[r] = uint16(v)
			if r == 0 {
				d.phy[0] &= ^uint16(0x8200)
			}
		}
		d.regs[off/4] = result
		if v&(1<<29) != 0 {
			return d.cause(1 << 9)
		}
	case 0xc0:
		d.regs[off/4] &= ^v
		return d.syncIRQ()
	case 0xc8:
		return d.cause(v)
	case 0xd0:
		d.regs[off/4] |= v
		return d.syncIRQ()
	case 0xd8:
		d.regs[0xd0/4] &= ^v
		return d.syncIRQ()
	case 0x2800, 0x3800:
		d.regs[off/4] = v &^ 15
	case 0x2808, 0x3808:
		d.regs[off/4] = v & 0xfff80
	case 0x2810, 0x2818, 0x3810:
		d.regs[off/4] = v & 0xffff
	case 0x3818:
		d.regs[off/4] = v & 0xffff
		return d.transmit()
	default:
		d.regs[off/4] = v
	}
	return nil
}
func (d *e1000) writeEEPROM(v uint32) {
	old := d.regs[0x10/4]
	out := old & 8
	if v&2 == 0 || old&2 == 0 {
		d.eeBits, d.eeOut = 0, 0
		d.eeCommand = 0
		out = 0
	}
	if v&2 != 0 && v&1 != 0 && old&1 == 0 {
		if d.eeBits < 9 {
			d.eeCommand = d.eeCommand<<1 | uint16((v>>2)&1)
			d.eeBits++
		} else if d.eeCommand>>6 == 6 {
			word := d.eeprom[(int(d.eeCommand&63)+d.eeOut/16)&63]
			out = uint32((word>>uint(15-d.eeOut%16))&1) << 3
			d.eeOut = (d.eeOut + 1) % (64 * 16)
		}
	}
	d.regs[0x10/4] = v&0x77 | 0x180 | out
}
func (d *e1000) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86) error {
	if ex.Size != 4 || ex.Address&3 != 0 {
		return fmt.Errorf("e1000 MMIO requires aligned dword access")
	}
	off := uint32(ex.Address - d.base())
	if ex.Write {
		return d.writeReg(off, binary.LittleEndian.Uint32(ex.Data))
	}
	v, err := d.readReg(off)
	if err == nil {
		cpu.CompleteMMIORead(uint64(v), 4)
	}
	return err
}
func (d *e1000) io(ex hypervisor.X86Exit) error {
	base := uint16(binary.LittleEndian.Uint32(d.config[0x14:]) &^ 7)
	if ex.Size != 4 {
		return fmt.Errorf("e1000 I/O requires dword access")
	}
	for i := uint32(0); i < ex.Count; i++ {
		b := ex.Data[i*4 : (i+1)*4]
		if ex.Port == base {
			if ex.Write {
				d.ioAddress = binary.LittleEndian.Uint32(b)
			} else {
				binary.LittleEndian.PutUint32(b, d.ioAddress)
			}
		} else if ex.Write {
			if err := d.writeReg(d.ioAddress, binary.LittleEndian.Uint32(b)); err != nil {
				return err
			}
		} else {
			v, err := d.readReg(d.ioAddress)
			if err != nil {
				return err
			}
			binary.LittleEndian.PutUint32(b, v)
		}
	}
	return nil
}
func (d *e1000) ring(base uint32) (uint64, uint32, uint32, uint32, error) {
	addr := uint64(d.regs[base/4]) | uint64(d.regs[(base+4)/4])<<32
	count := d.regs[(base+8)/4] / 16
	head, tail := d.regs[(base+16)/4], d.regs[(base+24)/4]
	if count == 0 {
		return addr, 0, head, tail, nil
	}
	if head >= count || tail >= count {
		return 0, 0, 0, 0, fmt.Errorf("e1000 invalid ring indices %d/%d length %d", head, tail, count)
	}
	if addr > ^uint64(0)-uint64(count)*16 {
		return 0, 0, 0, 0, fmt.Errorf("e1000 ring address overflows")
	}
	return addr, count, head, tail, nil
}
func (d *e1000) transmit() error {
	if d.config[4]&4 == 0 || d.regs[0x400/4]&2 == 0 {
		return nil
	}
	base, count, head, tail, err := d.ring(0x3800)
	if err != nil || count == 0 {
		return err
	}
	interrupt := uint32(0)
	for visited := uint32(0); head != tail && visited < count; visited++ {
		raw, err := d.memory(base+uint64(head)*16, 16)
		if err != nil {
			return fmt.Errorf("e1000 TX descriptor: %w", err)
		}
		desc := [16]byte(raw)
		command := desc[11]
		extended := command&0x20 != 0
		if extended && desc[10]&0x10 == 0 {
			d.txContext = desc
		} else {
			length := uint32(binary.LittleEndian.Uint16(desc[8:]))
			if extended {
				length |= uint32(desc[10]&15) << 16
				d.txOptions = desc[13]
				d.txTSO = command&4 != 0
			}
			if length > 65535 || len(d.txPacket)+int(length) > 131072 {
				return fmt.Errorf("e1000 TX packet exceeds bounded buffer")
			}
			buf, err := d.memory(binary.LittleEndian.Uint64(desc[:]), uint64(length))
			if err != nil {
				return fmt.Errorf("e1000 TX buffer: %w", err)
			}
			d.txPacket = append(d.txPacket, buf...)
			if command&1 != 0 {
				if err := d.sendPacket(extended, desc); err != nil {
					return err
				}
				d.txPacket = nil
				d.txOptions = 0
				d.txTSO = false
			}
		}
		if command&8 != 0 {
			raw[12] |= 1
			interrupt |= 1
		}
		head = (head + 1) % count
		d.regs[0x3810/4] = head
	}
	if head == tail {
		interrupt |= 2
	}
	return d.cause(interrupt)
}
func (d *e1000) sendFrame(frame []byte) error {
	if len(frame) < 14 || len(frame) > ethernet.MaxFrame {
		d.dropped++
		return nil
	}
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	if d.regs[0x100/4]&0xc0 != 0 {
		return d.receive(frame)
	}
	if err := d.port.Send(frame); err != nil {
		return err
	}
	d.tx++
	d.regs[0x4080/4]++
	return nil
}
func (d *e1000) accepts(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	dest := [6]byte(frame)
	if dest == [6]byte{255, 255, 255, 255, 255, 255} {
		return d.regs[0x100/4]&0x8000 != 0
	}
	if dest[0]&1 != 0 {
		if d.regs[0x100/4]&0x10 != 0 {
			return true
		}
		shift := uint(4 - ((d.regs[0x100/4] >> 12) & 3))
		if shift == 1 {
			shift = 0
		}
		hash := (uint32(dest[4])>>shift | uint32(dest[5])<<(8-shift)) & 0xfff
		return d.regs[(0x5200+hash/32*4)/4]&(1<<(hash%32)) != 0
	}
	if d.regs[0x100/4]&8 != 0 {
		return true
	}
	for i := uint32(0); i < 16; i++ {
		lo, hi := d.regs[(0x5400+i*8)/4], d.regs[(0x5404+i*8)/4]
		if hi&0x80000000 != 0 && binary.LittleEndian.Uint32(frame) == lo && binary.LittleEndian.Uint16(frame[4:]) == uint16(hi) {
			return true
		}
	}
	return false
}
func (d *e1000) receive(frame []byte) error {
	if d.config[4]&4 == 0 || d.regs[0x100/4]&2 == 0 || !d.accepts(frame) {
		return nil
	}
	base, count, head, tail, err := d.ring(0x2800)
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	packet := append([]byte(nil), frame...)
	if len(packet) < 60 {
		packet = append(packet, make([]byte, 60-len(packet))...)
	}
	if d.regs[0x100/4]&(1<<26) == 0 {
		packet = binary.LittleEndian.AppendUint32(packet, crc32.ChecksumIEEE(packet))
	}
	size := 2048 >> ((d.regs[0x100/4] >> 16) & 3)
	if d.regs[0x100/4]&(1<<25) != 0 {
		size *= 16
	}
	needed := (len(packet) + size - 1) / size
	available := (tail + count - head) % count
	if uint32(needed) > available {
		d.dropped++
		d.regs[0x4010/4]++
		return d.cause(1 << 6)
	}
	type dest struct{ desc, buffer []byte }
	targets := make([]dest, 0, needed)
	cursor := head
	remaining := len(packet)
	for i := 0; i < needed; i++ {
		desc, err := d.memory(base+uint64(cursor)*16, 16)
		if err != nil {
			return err
		}
		buf, err := d.memory(binary.LittleEndian.Uint64(desc), uint64(min(size, remaining)))
		if err != nil {
			return err
		}
		targets = append(targets, dest{desc, buf})
		remaining -= len(buf)
		cursor = (cursor + 1) % count
	}
	for i, target := range targets {
		n := copy(target.buffer, packet)
		packet = packet[n:]
		binary.LittleEndian.PutUint16(target.desc[8:], uint16(n))
		clear(target.desc[10:])
		target.desc[12] = 1 | 4
		if i == len(targets)-1 {
			target.desc[12] |= 2
		}
	}
	d.regs[0x2810/4] = cursor
	d.rx++
	d.regs[0x4074/4]++
	return d.cause(1 << 7)
}
func (d *e1000) poll() error {
	if err := d.syncIRQ(); err != nil {
		return err
	}
	for i := 0; i < 64; i++ {
		frame := d.port.Receive()
		if frame == nil {
			break
		}
		if err := d.receive(frame); err != nil {
			return err
		}
	}
	return nil
}
