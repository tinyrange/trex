// Package pl011 implements a polled PrimeCell UART from ARM DDI 0183G.
// It uses portable byte input and a transmit callback, without host terminals.
package pl011

import "fmt"

type UART struct {
	Base                                   uint64
	Transmit                               func(byte) error
	control, line, integer, fraction, ifls uint32
	rx                                     []byte
}

func New(base uint64, transmit func(byte) error) *UART {
	return &UART{Base: base, Transmit: transmit, control: 0x300, ifls: 0x12}
}
func (u *UART) Contains(address uint64, size int) bool {
	return address >= u.Base && address-u.Base < 0x1000 && (size == 1 || size == 2 || size == 4) && address%uint64(size) == 0 && (address-u.Base)%4 == 0
}
func (u *UART) Receive(b []byte) error {
	if len(b) > 32-len(u.rx) {
		return fmt.Errorf("pl011: receive FIFO full")
	}
	u.rx = append(u.rx, b...)
	return nil
}
func (u *UART) Read(address uint64, size int) (uint64, error) {
	if !u.Contains(address, size) {
		return 0, fmt.Errorf("pl011: invalid read")
	}
	var value uint32
	switch off := address - u.Base; off {
	case 0:
		if len(u.rx) > 0 {
			value = uint32(u.rx[0])
			u.rx = u.rx[1:]
		}
	case 4:
	case 0x18:
		value = 0x80
		if len(u.rx) == 0 {
			value |= 0x10
		}
		if len(u.rx) == 32 {
			value |= 0x40
		}
	case 0x20:
	case 0x24:
		value = u.integer
	case 0x28:
		value = u.fraction
	case 0x2c:
		value = u.line
	case 0x30:
		value = u.control
	case 0x34:
		value = u.ifls
	case 0x38, 0x40, 0x48:
	case 0x3c:
		value = 1 << 5
		if len(u.rx) > 0 {
			value |= 1 << 4
		}
	case 0xfe0:
		value = 0x11
	case 0xfe4:
		value = 0x10
	case 0xfe8:
		value = 0x34
	case 0xfec:
	case 0xff0:
		value = 0x0d
	case 0xff4:
		value = 0xf0
	case 0xff8:
		value = 0x05
	case 0xffc:
		value = 0xb1
	default:
		return 0, fmt.Errorf("pl011: unsupported read at %#x", off)
	}
	return uint64(value) & (uint64(1)<<(size*8) - 1), nil
}
func (u *UART) Write(address uint64, size int, value uint64) error {
	if !u.Contains(address, size) {
		return fmt.Errorf("pl011: invalid write")
	}
	switch off := address - u.Base; off {
	case 0:
		if u.control&0x101 != 0x101 {
			return nil
		}
		if u.control&0x80 != 0 {
			return u.Receive([]byte{byte(value)})
		}
		if u.Transmit != nil {
			return u.Transmit(byte(value))
		}
	case 4, 0x44:
	case 0x20:
	case 0x24:
		u.integer = uint32(value) & 0xffff
	case 0x28:
		u.fraction = uint32(value) & 0x3f
	case 0x2c:
		u.line = uint32(value) & 0xff
	case 0x30:
		u.control = uint32(value) & 0xffff
	case 0x34:
		u.ifls = uint32(value) & 0x3f
	case 0x38, 0x48:
		if value != 0 {
			return fmt.Errorf("pl011: interrupt/DMA mode unsupported")
		}
	default:
		return fmt.Errorf("pl011: unsupported write at %#x", off)
	}
	return nil
}
