package cc

import "fmt"

// pl031 models ARM DDI0224's counter, load, match and interrupt registers.
// The clock is supplied as elapsed ticks and frequency by the native backend.
type pl031 struct {
	address uint64

	clock                            func() (uint64, uint64, error)
	start                            uint64
	value, match, control, mask, raw uint32
	last                             uint32
}

func (d *pl031) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x1000 && n == 4 && a&3 == 0
}
func (d *pl031) counter() (uint32, error) {
	if d.control&1 == 0 {
		return d.value, nil
	}
	t, f, e := d.clock()
	if e != nil {
		return 0, e
	}
	if f == 0 {
		return 0, fmt.Errorf("PL031: zero clock frequency")
	}
	return d.value + uint32((t-d.start)/f), nil
}
func (d *pl031) Read(a uint64, n int) (uint64, error) {
	v, e := d.counter()
	if e != nil {
		return 0, e
	}
	distance, elapsed := d.match-d.last, v-d.last
	if d.control&1 != 0 && (v == d.match || distance != 0 && distance <= elapsed) {
		d.raw = 1
	}
	d.last = v
	switch a - d.address {
	case 0:
		return uint64(v), nil
	case 4:
		return uint64(d.match), nil
	case 8:
		return uint64(d.value), nil
	case 12:
		return uint64(d.control), nil
	case 16:
		return uint64(d.mask), nil
	case 20:
		return uint64(d.raw), nil
	case 24:
		return uint64(d.raw & d.mask), nil
	case 0xfe0:
		return 0x31, nil
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
	return 0, fmt.Errorf("PL031: unsupported read at %#x", a)
}
func (d *pl031) Write(a uint64, n int, v uint64) error {
	switch a - d.address {
	case 4:
		counter, e := d.counter()
		if e != nil {
			return e
		}
		d.last = counter
		d.match = uint32(v)
	case 8:
		t, _, e := d.clock()
		if e != nil {
			return e
		}
		d.start = t
		d.value = uint32(v)
		d.last = uint32(v)
	case 12:
		if v > 1 {
			return fmt.Errorf("PL031: reserved control bits")
		}
		counter, e := d.counter()
		if e != nil {
			return e
		}
		t, _, e := d.clock()
		if e != nil {
			return e
		}
		d.value = counter
		d.start = t
		d.control = uint32(v)
	case 16:
		if v > 1 {
			return fmt.Errorf("PL031: reserved mask bits")
		}
		// Preserve mask/status independently of output-pin wiring.
		d.mask = uint32(v)
	case 28:
		d.raw &^= uint32(v) & 1
	default:
		return fmt.Errorf("PL031: unsupported write at %#x", a)
	}
	return nil
}
