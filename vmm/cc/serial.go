package cc

import (
	"fmt"
	"time"

	"j5.nz/cc/hypervisor"
)

const serialCapacity = 65536

// serialBIOS implements the firmware's initialization and status services for
// its advertised COM1. Character transfers remain direct UART/channel traffic.
func (p *pc) serialBIOS(function, settings byte, port uint16) (uint16, bool, error) {
	if !p.serial.attached || port != 0 || (function != 0 && function != 3) {
		return 0, false, nil
	}
	if function == 0 {
		divisor := uint16(0x600 >> (settings >> 5))
		if settings>>5 == 0 {
			divisor = 0x417 // 110 baud
		}
		p.serial.dll, p.serial.dlm = byte(divisor), byte(divisor>>8)
		p.serial.lcr = settings & 0x1f
	}
	line, err := p.serial.read(5, p.now())
	if err != nil {
		return 0, true, err
	}
	modem, err := p.serial.read(6, p.now())
	return uint16(line)<<8 | uint16(modem), true, err
}

// uart16550 is serialized with the owning PC. Host channel writes enter the
// hardware receive FIFO, so a slow guest applies backpressure without dropping
// bytes. Baud divisors determine the four-character receive timeout.
type uart16550 struct {
	dll, dlm, ier, fcr, lcr, mcr, scratch byte
	rx                                    [16]byte
	rxHead, rxCount                       int
	overrun, timeout, thre, irq           bool
	modem, delta                          byte
	rxDeadline                            time.Time
	tx                                    []byte
	attached                              bool
	setIRQ                                func(uint32, bool) error
}

func (u *uart16550) capacity() int {
	if u.fcr&1 != 0 {
		return 16
	}
	return 1
}
func (u *uart16550) trigger() int {
	if u.fcr&1 == 0 {
		return 1
	}
	return [4]int{1, 4, 8, 14}[u.fcr>>6]
}
func (u *uart16550) receiverTimeout() time.Duration {
	bits := 1 + int(u.lcr&3) + 5 + 1
	if u.lcr&8 != 0 {
		bits++
	}
	if u.lcr&4 != 0 {
		bits++
	}
	divisor := max(1, int(u.dll)|int(u.dlm)<<8)
	return time.Second * time.Duration(4*bits*divisor) / 115200
}
func (u *uart16550) receive(value byte, now time.Time) {
	if u.rxCount == u.capacity() {
		u.overrun = true
		return
	}
	u.rx[(u.rxHead+u.rxCount)%len(u.rx)] = value
	u.rxCount++
	u.timeout = false
	u.rxDeadline = now.Add(u.receiverTimeout())
}
func (u *uart16550) cause() byte {
	switch {
	case u.ier&4 != 0 && u.overrun:
		return 6
	case u.ier&1 != 0 && u.rxCount >= u.trigger():
		return 4
	case u.ier&1 != 0 && u.rxCount != 0 && u.timeout:
		return 12
	case u.ier&2 != 0 && u.thre && len(u.tx) < serialCapacity:
		return 2
	case u.ier&8 != 0 && u.delta != 0:
		return 0
	default:
		return 1
	}
}
func (u *uart16550) syncIRQ() error {
	level := u.mcr&8 != 0 && u.cause() != 1
	if level != u.irq {
		if u.setIRQ != nil {
			if err := u.setIRQ(4, level); err != nil {
				return err
			}
		}
		u.irq = level
	}
	return nil
}
func (u *uart16550) poll(now time.Time) error {
	if u.rxCount != 0 && !u.rxDeadline.IsZero() && !now.Before(u.rxDeadline) {
		u.timeout = true
	}
	return u.syncIRQ()
}
func (u *uart16550) deadline() time.Time {
	if u.mcr&8 != 0 && u.ier&1 != 0 && u.rxCount > 0 && u.rxCount < u.trigger() && !u.timeout && !u.irq {
		return u.rxDeadline
	}
	return time.Time{}
}
func (u *uart16550) read(reg int, now time.Time) (byte, error) {
	var value byte
	switch reg {
	case 0:
		if u.lcr&0x80 != 0 {
			return u.dll, nil
		}
		if u.rxCount != 0 {
			value = u.rx[u.rxHead]
			u.rxHead = (u.rxHead + 1) % len(u.rx)
			u.rxCount--
		}
		u.timeout = false
		u.rxDeadline = now.Add(u.receiverTimeout())
	case 1:
		if u.lcr&0x80 != 0 {
			return u.dlm, nil
		}
		value = u.ier
	case 2:
		value = u.cause()
		if value == 2 {
			u.thre = false
		}
		if u.fcr&1 != 0 {
			value |= 0xc0
		}
	case 3:
		value = u.lcr
	case 4:
		value = u.mcr
	case 5:
		if len(u.tx) < serialCapacity {
			value = 0x60
		}
		if u.rxCount != 0 {
			value |= 1
		}
		if u.overrun {
			value |= 2
			u.overrun = false
		}
	case 6:
		value = u.modem | u.delta
		u.delta = 0
	case 7:
		value = u.scratch
	}
	return value, u.syncIRQ()
}
func (u *uart16550) write(reg int, value byte, now time.Time, console func(byte)) error {
	switch reg {
	case 0:
		if u.lcr&0x80 != 0 {
			u.dll = value
			return nil
		}
		u.thre = false
		if err := u.syncIRQ(); err != nil {
			return err
		}
		if u.mcr&0x10 != 0 {
			u.receive(value, now)
		} else {
			if u.attached {
				if len(u.tx) == serialCapacity {
					return fmt.Errorf("cc serial: transmit without available holding register")
				}
				u.tx = append(u.tx, value)
			}
			if console != nil {
				console(value)
			}
		}
		u.thre = true
	case 1:
		if u.lcr&0x80 != 0 {
			u.dlm = value
			return nil
		}
		if u.ier&2 == 0 && value&2 != 0 {
			u.thre = true
		}
		u.ier = value & 15
	case 2:
		if (u.fcr^value)&1 != 0 || value&2 != 0 {
			u.rxHead, u.rxCount = 0, 0
			u.timeout, u.overrun = false, false
			u.rxDeadline = time.Time{}
		}
		if value&4 != 0 {
			u.thre = true
		}
		u.fcr = value & 0xc9
	case 3:
		u.lcr = value
	case 4:
		u.mcr = value & 31
		modem := byte(0xb0)
		if u.mcr&0x10 != 0 {
			modem = (u.mcr&2)<<3 | (u.mcr&1)<<5 | (u.mcr&4)<<4 | (u.mcr&8)<<4
		}
		changed := modem ^ u.modem
		u.delta |= changed >> 4 & 0xb
		if u.modem&0x40 != 0 && modem&0x40 == 0 {
			u.delta |= 4
		}
		u.modem = modem
	case 7:
		u.scratch = value
	}
	return u.syncIRQ()
}

func (p *pc) serialIO(ex hypervisor.X86Exit) error {
	for i := uint32(0); i < ex.Count; i++ {
		data := ex.Data[int(i)*int(ex.Size) : int(i+1)*int(ex.Size)]
		if ex.Size != 1 {
			if !ex.Write {
				for j := range data {
					data[j] = 0xff
				}
			}
			continue
		}
		reg := int(ex.Port - 0x3f8)
		if ex.Write {
			if err := p.serial.write(reg, data[0], p.now(), func(value byte) {
				p.console = append(p.console, value)
				if len(p.console) > 65536 {
					p.console = p.console[len(p.console)-65536:]
				}
			}); err != nil {
				return err
			}
		} else {
			value, err := p.serial.read(reg, p.now())
			if err != nil {
				return err
			}
			data[0] = value
		}
	}
	return nil
}
