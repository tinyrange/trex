package cc

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/tinyrange/trex/vmm/ethernet"
	"j5.nz/cc/hypervisor"
)

// ne2000 models an ISA NE2000 at 300h, IRQ 9, with 16 KiB packet RAM.
// The DP8390 register pages, remote DMA and receive ring are guest-owned.
type ne2000 struct {
	port                                                                    ethernet.Endpoint
	irq                                                                     func(bool) error
	asserted                                                                bool
	mem                                                                     [65536]byte
	command, start, stop, boundary, current, txPage                         byte
	txCount, remote, remaining                                              uint16
	isr, imr, receiveConfig, transmitConfig, dataConfig, txStatus, rxStatus byte
	physical                                                                [6]byte
	multicast                                                               [8]byte
	tx, rx                                                                  uint64
}

func newNE2000(port ethernet.Endpoint, mac [6]byte, irq func(bool) error) *ne2000 {
	n := &ne2000{port: port, irq: irq, command: 0x21, isr: 0x80, physical: mac}
	for i, b := range mac {
		n.mem[i*2], n.mem[i*2+1] = b, b
	}
	n.mem[28], n.mem[29], n.mem[30], n.mem[31] = 0x57, 0x57, 0x57, 0x57
	return n
}

func (n *ne2000) updateIRQ() error {
	level := n.isr&n.imr&0x7f != 0
	if level == n.asserted {
		return nil
	}
	if err := n.irq(level); err != nil {
		return err
	}
	n.asserted = level
	return nil
}

func (n *ne2000) io(ex hypervisor.X86Exit) error {
	reg := byte(ex.Port - 0x300)
	for i := uint32(0); i < ex.Count; i++ {
		data := ex.Data[int(i)*int(ex.Size) : int(i+1)*int(ex.Size)]
		if reg == 0x10 {
			for j := range data {
				if n.remaining == 0 {
					if !ex.Write {
						data[j] = 0xff
					}
					continue
				}
				if ex.Write {
					if n.remote >= 0x4000 && n.remote < 0x8000 {
						n.mem[n.remote] = data[j]
					}
				} else {
					data[j] = n.mem[n.remote]
				}
				n.remote++
				if n.remote == uint16(n.stop)<<8 {
					n.remote = uint16(n.start) << 8
				}
				n.remaining--
				// In word mode an 8-bit host access still advances the
				// ASIC's remote DMA word counter (the other byte is unused).
				if ex.Size == 1 && n.dataConfig&1 != 0 {
					n.remote++
					if n.remote == uint16(n.stop)<<8 {
						n.remote = uint16(n.start) << 8
					}
					if n.remaining > 0 {
						n.remaining--
					}
				}
				if n.remaining == 0 {
					n.isr |= 0x40
				}
			}
		} else if reg == 0x1f {
			if !ex.Write {
				n.command = 0x21
				n.isr = 0x80
				n.imr = 0
				clear(data)
			}
		} else if reg < 16 {
			if ex.Write {
				if err := n.write(reg, data[0]); err != nil {
					return err
				}
			} else {
				data[0] = n.read(reg)
				for j := 1; j < len(data); j++ {
					data[j] = 0xff
				}
			}
		} else if !ex.Write {
			for j := range data {
				data[j] = 0xff
			}
		}
	}
	return n.updateIRQ()
}

func (n *ne2000) read(reg byte) byte {
	if reg == 0 {
		return n.command
	}
	switch n.command >> 6 {
	case 0:
		switch reg {
		case 3:
			return n.boundary
		case 4:
			return n.txStatus
		case 7:
			return n.isr
		case 8:
			return byte(n.remote)
		case 9:
			return byte(n.remote >> 8)
		case 12:
			return n.rxStatus
		}
	case 1:
		if reg <= 6 {
			return n.physical[reg-1]
		}
		if reg == 7 {
			return n.current
		}
		return n.multicast[reg-8]
	case 2:
		switch reg {
		case 1:
			return n.start
		case 2:
			return n.stop
		case 3:
			return n.boundary
		case 4:
			return n.txPage
		case 12:
			return n.receiveConfig
		case 13:
			return n.transmitConfig
		case 14:
			return n.dataConfig
		case 15:
			return n.imr
		}
	}
	return 0
}

func (n *ne2000) write(reg, value byte) error {
	if reg == 0 {
		n.command = value
		if value&1 != 0 {
			n.isr |= 0x80
		} else if value&2 != 0 {
			n.isr &^= 0x80
		}
		if value&0x38 == 8 && n.remaining == 0 {
			n.isr |= 0x40
		}
		if value&4 != 0 {
			at, size := int(n.txPage)<<8, int(n.txCount)
			if at >= 0x4000 && at+size <= 0x8000 && size >= 14 && size <= ethernet.MaxFrame {
				frame := append([]byte(nil), n.mem[at:at+size]...)
				if n.transmitConfig&6 != 0 {
					n.receive(frame, true)
				} else if err := n.port.Send(frame); err != nil {
					return err
				}
				n.tx++
				n.txStatus = 1
				n.isr |= 2
			} else {
				n.txStatus = 8
				n.isr |= 8
			}
			n.command &^= 4
		}
		return nil
	}
	switch n.command >> 6 {
	case 0:
		switch reg {
		case 1:
			n.start = value
		case 2:
			n.stop = value
		case 3:
			n.boundary = value
		case 4:
			n.txPage = value
		case 5:
			n.txCount = n.txCount&0xff00 | uint16(value)
		case 6:
			n.txCount = n.txCount&255 | uint16(value)<<8
		case 7:
			n.isr &^= value & 0x7f
		case 8:
			n.remote = n.remote&0xff00 | uint16(value)
		case 9:
			n.remote = n.remote&255 | uint16(value)<<8
		case 10:
			n.remaining = n.remaining&0xff00 | uint16(value)
		case 11:
			n.remaining = n.remaining&255 | uint16(value)<<8
		case 12:
			n.receiveConfig = value
		case 13:
			n.transmitConfig = value
		case 14:
			n.dataConfig = value
		case 15:
			n.imr = value
		}
	case 1:
		if reg <= 6 {
			n.physical[reg-1] = value
		} else if reg == 7 {
			n.current = value
		} else {
			n.multicast[reg-8] = value
		}
	}
	return nil
}

func (n *ne2000) poll() error {
	for i := 0; i < 64; i++ {
		frame := n.port.Receive()
		if frame == nil {
			break
		}
		n.receive(frame, false)
	}
	return n.updateIRQ()
}

func (n *ne2000) receive(frame []byte, loopback bool) {
	if len(frame) < 14 || len(frame) > ethernet.MaxFrame || n.command&1 != 0 || n.receiveConfig&0x20 != 0 {
		return
	}
	if !loopback && n.transmitConfig&6 != 0 {
		return
	}
	dest := [6]byte(frame[:6])
	if n.receiveConfig&0x10 == 0 {
		if dest == [6]byte{255, 255, 255, 255, 255, 255} {
			if n.receiveConfig&4 == 0 {
				return
			}
		} else if dest[0]&1 != 0 {
			if n.receiveConfig&8 == 0 {
				return
			}
			// DP8390 hashes destination bits least-significant first into a
			// non-reflected Ethernet CRC, selecting its top six bits.
			crc := uint32(0xffffffff)
			for _, b := range dest {
				for bit := 0; bit < 8; bit++ {
					carry := crc>>31 ^ uint32(b&1)
					crc <<= 1
					if carry != 0 {
						crc ^= 0x04c11db7
					}
					b >>= 1
				}
			}
			hash := crc >> 26
			if n.multicast[hash>>3]&(1<<(hash&7)) == 0 {
				return
			}
		} else if dest != n.physical {
			return
		}
	}
	if n.start < 0x40 || n.stop > 0x80 || n.start >= n.stop || n.current < n.start || n.current >= n.stop {
		return
	}
	if len(frame) < 60 {
		frame = append(append([]byte(nil), frame...), make([]byte, 60-len(frame))...)
	}
	pages := (len(frame) + 8 + 255) / 256
	next := int(n.current)
	for i := 0; i < pages; i++ {
		next++
		if next == int(n.stop) {
			next = int(n.start)
		}
		if next == int(n.boundary) {
			n.isr |= 0x10
			return
		}
	}
	status := byte(1)
	if dest[0]&1 != 0 {
		status |= 0x20
	}
	packet := make([]byte, len(frame)+8)
	packet[0], packet[1] = status, byte(next)
	binary.LittleEndian.PutUint16(packet[2:], uint16(len(frame)+4))
	copy(packet[4:], frame)
	binary.LittleEndian.PutUint32(packet[4+len(frame):], crc32.ChecksumIEEE(frame))
	at := int(n.current) << 8
	for _, b := range packet {
		n.mem[at] = b
		at++
		if at == int(n.stop)<<8 {
			at = int(n.start) << 8
		}
	}
	n.current = byte(next)
	n.rxStatus = status
	n.isr |= 1
	n.rx++
}
