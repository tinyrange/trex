package cc

import "fmt"

// virtualCTRR implements the version-1 virtual Apple CTRR register protocol. The first four banks protect read-only
// ranges; the second four banks' observed control=1 locks configuration only.
// Other control modes fail explicitly until their protection semantics are known.
type virtualCTRR struct {
	address uint64

	base, size uint64
	banks      [8]ctrrBank
	protect    func(base, size uint64) error
}
type ctrrBank struct{ lower, upper, control uint64 }

func (d *virtualCTRR) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x10000 && (n == 4 || n == 8) && a%uint64(n) == 0
}
func (d *virtualCTRR) Read(a uint64, n int) (uint64, error) {
	o := a - d.address
	if n == 4 {
		switch o {
		case 0:
			return 0x63747272, nil
		case 4:
			return 1, nil
		case 12:
			return 8, nil
		case 16:
			return 14, nil
		}
	}
	if n == 8 {
		switch o {
		case 32:
			return d.base, nil
		case 40:
			return d.base + d.size - 1, nil
		}
		if o >= 0x40 && o < 0x140 {
			b := &d.banks[(o-0x40)/32]
			switch (o - 0x40) % 32 {
			case 0:
				return b.lower, nil
			case 8:
				return b.upper, nil
			case 16:
				return b.control, nil
			}
		}
	}
	return 0, fmt.Errorf("virtual CTRR: unsupported read%d at %#x", n, o)
}
func (d *virtualCTRR) Write(a uint64, n int, v uint64) error {
	o := a - d.address
	if n != 8 || o < 0x40 || o >= 0x140 {
		return fmt.Errorf("virtual CTRR: unsupported write%d at %#x", n, o)
	}
	i, r := (o-0x40)/32, (o-0x40)%32
	b := &d.banks[i]
	if b.control&1 != 0 {
		return fmt.Errorf("virtual CTRR: bank %d is locked", i)
	}
	switch r {
	case 0:
		b.lower = v
	case 8:
		b.upper = v
	case 16:
		if i < 4 && v != 7 || i >= 4 && v != 1 {
			return fmt.Errorf("virtual CTRR: unsupported bank %d control %#x", i, v)
		}
		if b.lower != 0 || b.upper != 0 {
			if b.upper < b.lower || b.upper == ^uint64(0) || b.lower&0x3fff != 0 || (b.upper+1)&0x3fff != 0 || b.lower < d.base || b.upper-d.base >= d.size {
				return fmt.Errorf("virtual CTRR: invalid bank %d range %#x..%#x", i, b.lower, b.upper)
			}
			if i < 4 {
				if d.protect == nil {
					return fmt.Errorf("virtual CTRR: protection backend unavailable")
				}
				if err := d.protect(b.lower, b.upper-b.lower+1); err != nil {
					return err
				}
			}
		}
		b.control = v
	default:
		return fmt.Errorf("virtual CTRR: unsupported bank register %#x", r)
	}
	return nil
}

// writable also guards emulated DMA, which accesses RAM outside stage 2.
func (d *virtualCTRR) writable(a, n uint64) bool {
	if a+n < a {
		return false
	}
	for _, b := range d.banks[:4] {
		if b.control == 7 && (b.lower != 0 || b.upper != 0) && a <= b.upper && a+n > b.lower {
			return false
		}
	}
	return true
}
