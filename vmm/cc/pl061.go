package cc

import "fmt"

// pl061 is the static eight-pin button GPIO. Unpressed inputs are low; no
// button input events are attached to this headless machine.
type pl061 struct {
	address                                                   uint64
	data, direction, sense, both, polarity, enable, alternate uint8
}

func (d *pl061) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x1000 && (n == 1 || n == 4) && a&3 == 0
}
func (d *pl061) Read(a uint64, n int) (uint64, error) {
	o := a - d.address
	if o < 0x400 {
		return uint64(d.data & uint8(o>>2)), nil
	}
	switch o {
	case 0x400:
		return uint64(d.direction), nil
	case 0x404:
		return uint64(d.sense), nil
	case 0x408:
		return uint64(d.both), nil
	case 0x40c:
		return uint64(d.polarity), nil
	case 0x410:
		return uint64(d.enable), nil
	case 0x414:
		return uint64(d.sense & ^d.polarity & ^d.direction), nil
	case 0x418:
		return uint64(d.sense & ^d.polarity & ^d.direction & d.enable), nil
	case 0x420:
		return uint64(d.alternate), nil
	case 0xfe0:
		return 0x61, nil
	case 0xfe4:
		return 0x10, nil
	case 0xfe8:
		return 4, nil
	case 0xfec:
		return 0, nil
	case 0xff0:
		return 0xd, nil
	case 0xff4:
		return 0xf0, nil
	case 0xff8:
		return 5, nil
	case 0xffc:
		return 0xb1, nil
	}
	return 0, fmt.Errorf("PL061: unsupported read at %#x", a)
}
func (d *pl061) Write(a uint64, n int, v uint64) error {
	o := a - d.address
	if o < 0x400 {
		mask := uint8(o>>2) & d.direction
		d.data = d.data&^mask | uint8(v)&mask
		return nil
	}
	switch o {
	case 0x400:
		d.direction = uint8(v)
		d.data &= d.direction
	case 0x404:
		d.sense = uint8(v)
	case 0x408:
		d.both = uint8(v)
	case 0x40c:
		d.polarity = uint8(v)
	case 0x410:
		d.enable = uint8(v)
	case 0x41c: // No edge input transitions have occurred.
	case 0x420:
		d.alternate = uint8(v)
	default:
		return fmt.Errorf("PL061: unsupported write at %#x", a)
	}
	return nil
}
