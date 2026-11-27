package r3000

import "time"

// DP8572A clock and battery-backed registers, driven by guest cycles.
type ip12RTC struct {
	reg, bank [32]byte
	timeSave  byte
	flags     byte
	clock     time.Time
	millis    uint64
}

func newIP12RTC() ip12RTC {
	d := ip12RTC{clock: time.Date(1991, 4, 1, 0, 0, 0, 0, time.UTC)}
	d.bank[1] = 8 // Start the clock in 24-hour mode.
	d.updateCounters()
	return d
}

func rtcBCD(value int) byte     { return byte(value/10<<4 | value%10) }
func rtcDecimal(value byte) int { return int(value>>4)*10 + int(value&15) }

func (d *ip12RTC) updateCounters() {
	now := d.clock
	hour := rtcBCD(now.Hour())
	if d.bank[1]&4 != 0 {
		hour = rtcBCD((now.Hour()+11)%12+1) | byte(now.Hour()/12)<<5
	}
	values := [...]byte{rtcBCD(now.Nanosecond() / int(10*time.Millisecond)), rtcBCD(now.Second()), rtcBCD(now.Minute()),
		hour, rtcBCD(now.Day()), rtcBCD(int(now.Month())), rtcBCD(now.Year() % 100)}
	copy(d.reg[5:12], values[:])
	d.reg[14] = byte(now.Weekday() + 1)
}

func (d *ip12RTC) update(cycles uint64) {
	millis := cycles / 36000
	elapsed := millis - d.millis
	d.millis = millis
	if elapsed == 0 || d.bank[1]&8 == 0 {
		return
	}
	old := d.clock
	d.clock = old.Add(time.Duration(elapsed) * time.Millisecond)
	before, after := old.UnixMilli(), d.clock.UnixMilli()
	for i, period := range [...]int64{60000, 10000, 1000, 100, 10, 1} {
		if before/period != after/period {
			d.flags |= 1 << i
		}
	}
	d.updateCounters()
	if d.timeSave&0x80 != 0 {
		copy(d.reg[25:30], d.reg[6:11])
	}
}

func (d *ip12RTC) access(cycles uint64, index uint32, value byte, write bool) uint32 {
	d.update(cycles)
	if index == 0 {
		if write {
			d.reg[0] = value & 0xf0
		}
		return uint32(d.reg[0])
	}
	if index < 5 {
		if d.reg[0]&0x40 != 0 {
			if write {
				if index == 1 && d.bank[1]&8 == 0 && value&8 != 0 {
					year := d.clock.Year()/100*100 + rtcDecimal(d.reg[11])
					hour := rtcDecimal(d.reg[8] & 0x3f)
					if value&4 != 0 {
						hour = rtcDecimal(d.reg[8]&0x1f)%12 + int(d.reg[8]>>5&1)*12
					}
					d.clock = time.Date(year, time.Month(rtcDecimal(d.reg[10])), rtcDecimal(d.reg[9]),
						hour, rtcDecimal(d.reg[7]), rtcDecimal(d.reg[6]),
						rtcDecimal(d.reg[5])*int(10*time.Millisecond), time.UTC)
				}
				d.bank[index] = value
			}
			return uint32(d.bank[index])
		}
		switch index {
		case 3:
			if write {
				d.flags = d.flags&0x3f | value&0x80
			}
			flags := d.flags
			if !write {
				d.flags &= 0xc0
			}
			return uint32(flags)
		case 4:
			if write {
				if d.timeSave&0x80 == 0 && value&0x80 != 0 {
					copy(d.reg[25:30], d.reg[6:11])
				}
				d.timeSave = value
			}
			return uint32(d.timeSave)
		}
	}
	if write {
		d.reg[index] = value
	}
	return uint32(d.reg[index])
}
