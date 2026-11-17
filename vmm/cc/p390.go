package cc

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tinyrange/trex/emulator/s390"

	"j5.nz/cc/hypervisor"
)

// p390Adapter models the PCI transport of the IBM P/390 (1014:0036,
// subsystem 1014:0059). Register locations are taken from the original
// AWS370DD 06.07 PCI initialization path. A portable HLE monitor connects
// original OS/2 support and device managers to the architectural ESA engine.
// Uploaded private ASIC microcode is retained, not executed. Opt-in support
// and bounded observations do not imply complete hardware or IPL compatibility.
type p390Adapter struct {
	service        *s390.P390
	nextRun        time.Time
	config         [256]byte
	memory         []byte
	ports          [32]byte
	trace          []any
	transfers      uint64
	irq            bool
	irqLine        uint32
	channelReplyPC string
}

func newP390Adapter() *p390Adapter { return newP390AdapterWithConfig(false, time.Time{}) }

func newP390AdapterWithConfig(compat bool, start time.Time) *p390Adapter {
	model := uint16(0x7490)
	if compat {
		model = 0x9672
	}
	service, err := s390.NewP390WithConfig(s390.Config{Memory: 32 << 20, CPUs: 1, CPUModel: model, S370: compat, Start: start})
	if err != nil {
		panic(err)
	} // fixed configuration, validated by the constructor
	d := &p390Adapter{memory: service.Aperture, service: service}
	binary.LittleEndian.PutUint16(d.config[0:], 0x1014)
	binary.LittleEndian.PutUint16(d.config[2:], 0x0036)
	d.config[4] = 3
	d.config[8], d.config[10], d.config[11] = 1, 0x40, 0x0b
	binary.LittleEndian.PutUint32(d.config[0x10:], 0x1c01)
	binary.LittleEndian.PutUint32(d.config[0x14:], 0xd0000000)
	binary.LittleEndian.PutUint16(d.config[0x2c:], 0x1014)
	binary.LittleEndian.PutUint16(d.config[0x2e:], 0x0059)
	d.config[0x3c], d.config[0x3d] = 11, 1
	return d
}

func (d *p390Adapter) writeConfig(offset int, value byte) {
	switch {
	case offset == 4:
		d.config[offset] = value & 7
	case offset >= 0x10 && offset < 0x14:
		d.config[offset] = value
		d.config[0x10] = d.config[0x10]&0xe0 | 1
	case offset >= 0x14 && offset < 0x18:
		d.config[offset] = value
		d.config[0x14], d.config[0x15] = 0, 0
		d.config[0x16] &= 0xc0
	case offset == 0x3c:
		d.config[offset] = value
	}
}

func (d *p390Adapter) ioBase() uint32 {
	return binary.LittleEndian.Uint32(d.config[0x10:]) &^ 31
}
func (d *p390Adapter) memoryBase() uint64 {
	return uint64(binary.LittleEndian.Uint32(d.config[0x14:]) &^ ((4 << 20) - 1))
}
func (d *p390Adapter) record(kind string, offset uint64, write bool, data []byte) {
	d.transfers++
	encoded := fmt.Sprintf("%x", data)
	if len(d.trace) != 0 {
		last := d.trace[len(d.trace)-1].(map[string]any)
		if last["kind"] == kind && last["offset"] == int64(offset) && last["write"] == write && last["data"] == encoded {
			last["count"] = last["count"].(int64) + 1
			return
		}
	}
	if len(d.trace) == 64 {
		copy(d.trace, d.trace[1:])
		d.trace = d.trace[:63]
	}
	d.trace = append(d.trace, map[string]any{"kind": kind, "offset": int64(offset), "write": write, "data": encoded, "count": int64(1)})
}
func (d *p390Adapter) io(ex hypervisor.X86Exit) error {
	if ex.Size == 0 || ex.Size > 4 || ex.Count == 0 || uint64(ex.Size)*uint64(ex.Count) != uint64(len(ex.Data)) || uint64(ex.Port) < uint64(d.ioBase()) || uint64(ex.Port)+uint64(ex.Size) > uint64(d.ioBase())+32 {
		return fmt.Errorf("p390: invalid I/O transfer")
	}
	off := int(uint32(ex.Port) - d.ioBase())
	for n := uint32(0); n < ex.Count; n++ {
		b := ex.Data[int(n)*int(ex.Size) : int(n+1)*int(ex.Size)]
		if len(b) != 1 {
			return fmt.Errorf("p390: unsupported I/O width +%#x = %d", off, len(b))
		}
		if ex.Write {
			switch {
			case off == 5 && (b[0] == 0x80 || b[0] == 0 || b[0] == 3):
				// Original PCI initialization: assert reset, release, enable IRQ.
				d.ports[off] = b[0]
				if b[0]&0x80 != 0 {
					d.service.ResetAdapter()
				}
			case off == 4 && b[0] == 0xe0:
				// AWS370DD interrupt handler acknowledges at BAR0+4.
				d.service.AcknowledgeInterrupt()
			default:
				d.record("io", uint64(off), true, b)
				return fmt.Errorf("p390: unsupported I/O write +%#x = %x", off, b)
			}
		} else {
			switch off {
			case 5:
				b[0] = d.ports[5]
			case 6:
				b[0] = d.service.InterruptReason
			case 7:
				b[0] = 0
				if d.service.InterruptPending {
					b[0] = 2
				}
			default:
				d.record("io", uint64(off), false, nil)
				return fmt.Errorf("p390: unsupported I/O read +%#x", off)
			}
		}
		d.record("io", uint64(off), ex.Write, b)
	}
	return nil
}
func (d *p390Adapter) contains(address uint64, size uint8) bool {
	base := d.memoryBase()
	return size != 0 && d.config[4]&2 != 0 && address >= base && address-base < uint64(len(d.memory)) && uint64(size) <= uint64(len(d.memory))-(address-base)
}
func (d *p390Adapter) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86) error {
	if (ex.Size != 1 && ex.Size != 2 && ex.Size != 4 && ex.Size != 8) || !d.contains(ex.Address, ex.Size) || ex.Write && len(ex.Data) != int(ex.Size) {
		return fmt.Errorf("p390: invalid memory transfer address=%#x size=%d", ex.Address, ex.Size)
	}
	off := ex.Address - d.memoryBase()
	b := make([]byte, int(ex.Size))
	if ex.Write {
		copy(b, ex.Data)
		d.record("memory", off, true, b)
		if off == 0x20010 && d.service.IOPending && cpu != nil {
			r, err := cpu.Registers()
			if err != nil {
				return err
			}
			s, err := cpu.SystemRegisters()
			if err != nil {
				return err
			}
			d.channelReplyPC = fmt.Sprintf("%04x:%x", s.Cs.Selector, r.Rip)
		}
		return d.service.WriteAperture(uint32(off), b)
	} else {
		if err := d.service.ReadAperture(uint32(off), b); err != nil {
			return err
		}
		var value uint64
		for i, v := range b {
			value |= uint64(v) << (8 * i)
		}
		cpu.CompleteMMIORead(value, uint32(ex.Size))
	}
	d.record("memory", off, ex.Write, b)
	return nil
}
func (d *p390Adapter) state() any {
	if d == nil {
		return nil
	}
	operations := make([]any, 0, len(d.service.Operations))
	for _, op := range d.service.Operations {
		operations = append(operations, map[string]any{"kind": op.Kind, "command": int(op.Command), "arguments": fmt.Sprintf("%x", op.Arguments), "options": fmt.Sprintf("%x", op.Options)})
	}
	return map[string]any{"cpu_gr": fmt.Sprintf("%08x", d.service.Machine.CPUs[0].GR), "s370_compatibility": d.service.Machine.S370, "io_status_reports": int64(d.service.IOStatusReports), "channel_reply_pc": d.channelReplyPC, "io_pending": d.service.IOPending, "io_instruction": int(d.service.IOInstruction), "io_requests": int64(d.service.IORequests), "io_completions": int64(d.service.IOCompletions), "io_aborted": int64(d.service.IOAborted), "monitor_loads": int64(d.service.MonitorLoads), "interrupt_pending": d.service.InterruptPending, "operations": operations, "config": fmt.Sprintf("%x", d.config[:]), "transfers": int64(d.transfers), "trace": d.trace, "scope": "experimental-hle-host-channel", "cpu_implemented": true, "monitor_initialized": d.service.Initialized, "manual_requests": int64(d.service.ManualCommands), "last_manual": int(d.service.LastManual), "cpu_stopped": d.service.Machine.CPUs[0].Stopped, "cpu_check": d.service.Machine.CPUs[0].Check, "cpu_instructions": int64(d.service.Machine.CPUs[0].Instructions), "cpu_psw": d.service.Machine.CPUs[0].PSW.String(), "run_reason": d.service.RunReason.String(), "monitor_commands": int64(d.service.Commands), "monitor_last_command": int(d.service.LastCommand), "monitor_error": d.service.LastError, "control": fmt.Sprintf("%x", d.memory[0x100:0x120]), "mailbox": fmt.Sprintf("%x", d.memory[0x20000:0x20080])}
}

func (d *p390Adapter) updateIRQ(cpu hypervisor.X86) error {
	line := uint32(d.config[0x3c])
	asserted := d.service.InterruptPending && d.ports[5]&3 == 3 && line < 16 && line != 0
	if d.irq && (!asserted || d.irqLine != line) {
		if err := cpu.SetIRQ(d.irqLine, false); err != nil {
			return err
		}
		d.irq = false
	}
	if asserted && !d.irq {
		if err := cpu.SetIRQ(line, true); err != nil {
			return err
		}
		d.irq, d.irqLine = true, line
	}
	return nil
}

func (d *p390Adapter) poll(now time.Time) {
	if !d.service.Running() {
		d.nextRun = time.Time{}
		return
	}
	if d.nextRun.IsZero() || !now.Before(d.nextRun) {
		d.service.Advance(50000)
		d.nextRun = now.Add(time.Millisecond)
	}
}

func (d *p390Adapter) deadline() time.Time {
	if !d.service.Running() {
		return time.Time{}
	}
	return d.nextRun
}
