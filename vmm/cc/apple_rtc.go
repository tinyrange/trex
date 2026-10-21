package cc

import "fmt"

// avpRTC exposes the PCC virtual clock's microsecond counter and host-change
// notification controls. This backend has a fixed rate and epoch, so no host
// rate/epoch-change notification is generated.
type avpRTC struct {
	address uint64

	clock                       func() (uint64, uint64, error)
	start, epoch, control, mask uint64
}

func (d *avpRTC) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x1000 && n == 8 && a&7 == 0
}
func (d *avpRTC) Read(a uint64, n int) (uint64, error) {
	switch a - d.address {
	case 0:
		t, f, e := d.clock()
		if e != nil {
			return 0, e
		}
		if f == 0 {
			return 0, fmt.Errorf("AVP RTC: zero frequency")
		}
		t -= d.start
		return d.epoch + t/f*1000000 + (t%f)*1000000/f, nil
	case 24:
		return d.control, nil
	case 32:
		return d.mask, nil
	case 48:
		return 0, nil
	}
	return 0, fmt.Errorf("AVP RTC: unsupported read at %#x", a)
}
func (d *avpRTC) Write(a uint64, n int, v uint64) error {
	switch a - d.address {
	case 24:
		if v > 1 {
			return fmt.Errorf("AVP RTC: unknown control %#x", v)
		}
		d.control = v
	case 32:
		if v&^uint64(6) != 0 {
			return fmt.Errorf("AVP RTC: unknown mask %#x", v)
		}
		d.mask = v
	case 56: // W1C host notification status; no changes pending.
	default:
		return fmt.Errorf("AVP RTC: unsupported write at %#x", a)
	}
	return nil
}
