package cc

import (
	"context"
	"fmt"
	"j5.nz/cc/hypervisor"
	"time"
)

// run schedules the RTC between native runs, keeping all device and CPU
// mutation serialized. The clock is injected by the platform owner.
func (p *pc) run(ctx context.Context) (hypervisor.X86Exit, error) {
	return p.runWithHandler(ctx, nil)
}

func (p *pc) runDevices(ctx context.Context) (hypervisor.X86Exit, error) {
	return p.runWithHandler(ctx, func(ex hypervisor.X86Exit) (bool, error) {
		switch ex.Reason {
		case hypervisor.X86ExitIO:
			// Bulk disk data can use hundreds of native exits per sector.
			// Leave control-port writes to the outer loop so timer changes
			// immediately recompute their native execution deadline.
			if ex.Port == 0x1f0 {
				return true, p.ideIO(ex)
			}
			return false, nil
		case hypervisor.X86ExitMMIO:
			if ex.Address >= 0xa0000 && ex.Address+uint64(ex.Size) <= 0xc0000 {
				return true, p.vga.mmio(ex, p.cpu)
			}
			return false, nil
		default:
			return false, nil
		}
	})
}

func (p *pc) runWithHandler(ctx context.Context, handle func(hypervisor.X86Exit) (bool, error)) (hypervisor.X86Exit, error) {
	for {
		if err := ctx.Err(); err != nil {
			return hypervisor.X86Exit{}, err
		}
		now := p.now()
		if p.acpi != nil {
			if err := p.acpi.poll(now); err != nil {
				return hypervisor.X86Exit{}, err
			}
		}
		if p.nic != nil {
			if err := p.nic.poll(); err != nil {
				return hypervisor.X86Exit{}, err
			}
		}
		if p.hpet != nil {
			if err := p.hpet.poll(now); err != nil {
				return hypervisor.X86Exit{}, err
			}
		}
		var deadline time.Time
		var deliver func() error
		var commit func()
		rate := p.cmos[0xa] & 15
		if p.cmos[0xb]&0x40 == 0 || rate < 3 {
			p.rtcNext = time.Time{}
		} else {
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
			if !p.rtcIRQ {
				deadline = p.rtcNext
				deliver = func() error { return p.cpu.SetIRQ(8, true) }
				commit = func() { p.rtcIRQ = true; p.cmos[0xc] |= 0xc0; p.rtcNext = p.now().Add(period) }
			}
		}
		if p.hpet != nil {
			i, next := p.hpet.deadline()
			if i >= 0 && (deadline.IsZero() || next.Before(deadline)) {
				deadline = next
				deliver = p.hpet.delivery(i)
				commit = func() { p.hpet.expire(i, p.now()) }
			}
		}
		if deadline.IsZero() {
			return p.cpu.RunUntil(ctx, handle)
		}
		// Only accelerator IRQ delivery runs concurrently. Join the callback
		// and publish device state before processing any timer register access.
		// Cancelling each tick would starve host-delayed split-lock instructions.
		fired := make(chan struct{})
		var irqErr error
		timer := time.AfterFunc(deadline.Sub(now), func() { irqErr = deliver(); close(fired) })
		ex, err := p.cpu.RunUntil(ctx, handle)
		if !timer.Stop() {
			<-fired
			if irqErr != nil {
				return hypervisor.X86Exit{}, irqErr
			}
			commit()
		}
		return ex, err
	}
}

func (p *pc) handleIO(ex hypervisor.X86Exit) error {
	if p.efi != nil && ex.Port == efiPort && ex.Write && ex.Size == 1 && ex.Count == 1 {
		return p.efiCall()
	}
	if p.acpi != nil && ex.Port >= 0xcf8 && ex.Port <= 0xcff {
		return p.pciIO(ex)
	}
	if p.pciIDE != nil && p.pciIDE.config[4]&1 != 0 {
		base := p.pciIDE.busMasterBase()
		if uint32(ex.Port) >= base && uint32(ex.Port) < base+16 {
			return p.busMasterIO(ex)
		}
	}
	if ex.Port == videoRequestPort || ex.Port == videoDataPort {
		return p.videoIO(ex)
	}
	if p.acpi != nil && ex.Port >= acpiPMBase && ex.Port < acpiPMBase+12 {
		return p.acpi.io(ex, p.now())
	}
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
		return p.ideIO(ex)
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
