package cc

import (
	"context"
	"errors"
	"fmt"
	"j5.nz/cc/hypervisor"
	"time"
)

// run schedules the RTC between native runs, keeping all device and CPU
// mutation serialized. The clock is injected by the platform owner.
func (p *pc) run(ctx context.Context) (hypervisor.X86Exit, error) {
	for {
		if err := ctx.Err(); err != nil {
			return hypervisor.X86Exit{}, err
		}
		now := p.now()
		if p.nic != nil {
			if err := p.nic.poll(); err != nil {
				return hypervisor.X86Exit{}, err
			}
		}
		rate := p.cmos[0xa] & 15
		if p.cmos[0xb]&0x40 == 0 || rate < 3 {
			p.rtcNext = time.Time{}
			return p.cpu.Run(ctx)
		}
		period := time.Second * time.Duration(uint64(1)<<(rate-1)) / 32768
		if p.rtcNext.IsZero() {
			p.rtcNext = now.Add(period)
		}
		if !now.Before(p.rtcNext) {
			p.rtcNext = now.Add(period)
			p.cmos[0xc] |= 0xc0
			if !p.rtcIRQ {
				if err := p.cpu.SetIRQ(8, true); err != nil {
					return hypervisor.X86Exit{}, err
				}
				p.rtcIRQ = true
			}
		}
		child, cancel := context.WithDeadline(ctx, p.rtcNext)
		ex, err := p.cpu.Run(child)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			continue
		}
		return ex, err
	}
}

func (p *pc) handleIO(ex hypervisor.X86Exit) error {
	if p.nic != nil && ex.Port >= 0x300 && ex.Port <= 0x31f {
		return p.nic.io(ex)
	}
	if (ex.Port == 0x60 || ex.Port == 0x64) && ex.Write {
		p.inputTrace = append(p.inputTrace, fmt.Sprintf("%04x <- %x", ex.Port, ex.Data))
		if len(p.inputTrace) > 64 {
			p.inputTrace = p.inputTrace[1:]
		}
	}
	if ex.Port == 0x60 || ex.Port == 0x64 {
		return p.keyboard.io(ex)
	}
	if ex.Port >= 0x3b0 && ex.Port <= 0x3df {
		return p.vga.io(ex)
	}
	if ex.Port >= 0x1f0 && ex.Port <= 0x1f7 || ex.Port == 0x3f6 {
		return p.ide.io(ex)
	}
	if ex.Port == biosPort && ex.Write && ex.Size == 1 && ex.Count == 1 {
		return p.bios()
	}
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
		value := byte(0xff)
		switch ex.Port {
		case 0x70:
			if ex.Write {
				p.cmosIndex = data[0] & 127
			}
			value = p.cmosIndex
		case 0x71:
			if ex.Write {
				p.observeRTC(true, data[0])
				p.cmos[p.cmosIndex] = data[0]
				if p.cmosIndex == 0xa || p.cmosIndex == 0xb {
					p.rtcNext = time.Time{}
				}
				break
			}
			t := p.now().UTC()
			bcd := func(v int) byte { return byte(v/10*16 + v%10) }
			value = p.cmos[p.cmosIndex]
			switch p.cmosIndex {
			case 0:
				value = bcd(t.Second())
			case 2:
				value = bcd(t.Minute())
			case 4:
				value = bcd(t.Hour())
			case 6:
				value = bcd(int(t.Weekday()) + 1)
			case 7:
				value = bcd(t.Day())
			case 8:
				value = bcd(int(t.Month()))
			case 9:
				value = bcd(t.Year() % 100)
			case 0xa:
				value = p.cmos[0xa] & 0x7f
			case 0xb:
				value = p.cmos[0xb]
			case 0xc:
				p.cmos[0xc] = 0
				if p.rtcIRQ {
					if err := p.cpu.SetIRQ(8, false); err != nil {
						return err
					}
					p.rtcIRQ = false
				}
			case 0xd:
				value = 0x80
			case 0x32:
				value = bcd(t.Year() / 100)
			}
			p.observeRTC(false, value)
		case 0x61:
			value = p.ports[ex.Port] ^ 0x20
			p.ports[ex.Port] = value
		case 0x80, 0x92:
			value = p.ports[ex.Port]
			if ex.Write {
				p.ports[ex.Port] = data[0]
			}
		default:
			// Unpopulated ISA ports float high; writes have no receiver.
			value = 0xff
		}
		if !ex.Write {
			data[0] = value
		}
	}
	return nil
}

func (p *pc) observeRTC(write bool, value byte) {
	if p.cmosIndex <= 9 || p.cmosIndex == 0xb || p.cmosIndex == 0x32 {
		p.rtcTrace = append(p.rtcTrace, map[string]any{"register": int(p.cmosIndex), "value": int(value), "write": write})
		if len(p.rtcTrace) > 64 {
			p.rtcTrace = p.rtcTrace[1:]
		}
	}
}
