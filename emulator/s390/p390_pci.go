package s390

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tinyrange/trex/vmm/device"
)

// P390PCI models the PCI transport of the IBM P/390 (1014:0036,
// subsystem 1014:0059). Register locations are taken from the original
// AWS370DD 06.07 PCI initialization path. A portable HLE monitor connects
// original OS/2 support and device managers to the architectural ESA engine.
// Uploaded private ASIC microcode is retained, not executed. Opt-in support
// and bounded observations do not imply complete hardware or IPL compatibility.
type P390PCI struct {
	service        *P390
	nextRun        time.Time
	regions        [2]device.Region
	config         [256]byte
	memory         []byte
	ports          [32]byte
	trace          []any
	transfers      uint64
	channelReplyPC string
}

func newP390PCI() *P390PCI { return NewP390PCI(false, time.Time{}) }

func NewP390PCI(compat bool, start time.Time) *P390PCI {
	model := uint16(0x7490)
	if compat {
		model = 0x9672
	}
	service, err := NewP390WithConfig(Config{Memory: 32 << 20, CPUs: 1, CPUModel: model, S370: compat, Start: start})
	if err != nil {
		panic(err)
	} // fixed configuration, validated by the constructor
	d := &P390PCI{memory: service.Aperture, service: service}
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

func (d *P390PCI) writeConfig(offset int, value byte) {
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

func (d *P390PCI) ioBase() uint32 {
	return binary.LittleEndian.Uint32(d.config[0x10:]) &^ 31
}
func (d *P390PCI) memoryBase() uint64 {
	return uint64(binary.LittleEndian.Uint32(d.config[0x14:]) &^ ((4 << 20) - 1))
}
func (d *P390PCI) record(kind string, offset uint64, write bool, data []byte) {
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

// ReadConfig and WriteConfig implement byte-level configuration mechanism 1.
func (d *P390PCI) ReadConfig(offset uint16) byte {
	if offset >= 256 {
		return 0xff
	}
	return d.config[offset]
}
func (d *P390PCI) WriteConfig(offset uint16, value byte) {
	if offset < 256 {
		d.writeConfig(int(offset), value)
	}
}
func (d *P390PCI) Regions() []device.Region {
	out := d.regions[:0]
	// BAR0's 32-bit sizing mask is not an x86 port decoder.
	if d.config[4]&1 != 0 && d.ioBase() < 1<<16 {
		out = append(out, device.Region{BAR: 0, Space: device.IO, Base: uint64(d.ioBase()), Size: 32})
	}
	if d.config[4]&2 != 0 {
		out = append(out, device.Region{BAR: 1, Space: device.Memory, Base: d.memoryBase(), Size: uint64(len(d.memory))})
	}
	return out
}
func (d *P390PCI) Access(a device.Access) error {
	b, off := a.Data, a.Offset
	if a.BAR == 0 {
		if off >= 32 || len(b) != 1 {
			return fmt.Errorf("p390: invalid I/O transfer +%#x width=%d", off, len(b))
		}
		if a.Write {
			switch {
			case off == 5 && (b[0] == 0x80 || b[0] == 0 || b[0] == 3):
				d.ports[off] = b[0]
				if b[0]&0x80 != 0 {
					d.service.ResetAdapter()
				}
			case off == 4 && b[0] == 0xe0:
				d.service.AcknowledgeInterrupt()
			default:
				d.record("io", off, true, b)
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
				d.record("io", off, false, nil)
				return fmt.Errorf("p390: unsupported I/O read +%#x", off)
			}
		}
		d.record("io", off, a.Write, b)
		return nil
	}
	if a.BAR != 1 || (len(b) != 1 && len(b) != 2 && len(b) != 4 && len(b) != 8) || off > uint64(len(d.memory)) || uint64(len(b)) > uint64(len(d.memory))-off {
		return fmt.Errorf("p390: invalid memory transfer offset=%#x size=%d", off, len(b))
	}
	if a.Write {
		d.record("memory", off, true, b)
		if off == 0x20010 && d.service.IOPending && a.Position != nil {
			position, err := a.Position()
			if err != nil {
				return err
			}
			d.channelReplyPC = position
		}
		return d.service.WriteAperture(uint32(off), b)
	}
	if err := d.service.ReadAperture(uint32(off), b); err != nil {
		return err
	}
	d.record("memory", off, false, b)
	return nil
}

func (d *P390PCI) State() any {
	if d == nil {
		return nil
	}
	operations := make([]any, 0, len(d.service.Operations))
	for _, op := range d.service.Operations {
		operations = append(operations, map[string]any{"kind": op.Kind, "command": int(op.Command), "arguments": fmt.Sprintf("%x", op.Arguments), "options": fmt.Sprintf("%x", op.Options)})
	}
	return map[string]any{"cpu_gr": fmt.Sprintf("%08x", d.service.Machine.CPUs[0].GR), "s370_compatibility": d.service.Machine.S370, "io_status_reports": int64(d.service.IOStatusReports), "channel_reply_pc": d.channelReplyPC, "io_pending": d.service.IOPending, "io_instruction": int(d.service.IOInstruction), "io_requests": int64(d.service.IORequests), "io_completions": int64(d.service.IOCompletions), "io_aborted": int64(d.service.IOAborted), "monitor_loads": int64(d.service.MonitorLoads), "interrupt_pending": d.service.InterruptPending, "operations": operations, "config": fmt.Sprintf("%x", d.config[:]), "transfers": int64(d.transfers), "trace": d.trace, "scope": "experimental-hle-host-channel", "cpu_implemented": true, "monitor_initialized": d.service.Initialized, "manual_requests": int64(d.service.ManualCommands), "last_manual": int(d.service.LastManual), "cpu_stopped": d.service.Machine.CPUs[0].Stopped, "cpu_check": d.service.Machine.CPUs[0].Check, "cpu_instructions": int64(d.service.Machine.CPUs[0].Instructions), "cpu_psw": d.service.Machine.CPUs[0].PSW.String(), "run_reason": d.service.RunReason.String(), "monitor_commands": int64(d.service.Commands), "monitor_last_command": int(d.service.LastCommand), "monitor_error": d.service.LastError, "control": fmt.Sprintf("%x", d.memory[0x100:0x120]), "mailbox": fmt.Sprintf("%x", d.memory[0x20000:0x20080])}
}

func (d *P390PCI) Interrupt() (uint32, bool) {
	line := uint32(d.config[0x3c])
	return line, d.service.InterruptPending && d.ports[5]&3 == 3 && line < 16 && line != 0
}

func (d *P390PCI) Poll(now time.Time) error {
	if !d.service.Running() {
		d.nextRun = time.Time{}
		return nil
	}
	if d.nextRun.IsZero() || !now.Before(d.nextRun) {
		d.service.Advance(50000)
		d.nextRun = now.Add(time.Millisecond)
	}
	return nil
}

func (d *P390PCI) Deadline() time.Time {
	if !d.service.Running() {
		return time.Time{}
	}
	return d.nextRun
}

// ReadMemory exposes observational spaces, not a replacement host-channel path.
func (d *P390PCI) ReadBAR(bar uint8, offset uint64, data []byte) error {
	if bar != 1 {
		return fmt.Errorf("p390: BAR%d has no inspection memory", bar)
	}
	return d.ReadMemory("aperture", offset, data)
}
func (d *P390PCI) ReadMemory(space string, address uint64, data []byte) error {
	switch space {
	case "main":
		mem := d.service.Machine.S.Mem
		if address > uint64(len(mem)) || uint64(len(data)) > uint64(len(mem))-address {
			return fmt.Errorf("p390: read exceeds main storage")
		}
		copy(data, mem[address:address+uint64(len(data))])
		return nil
	case "aperture":
		if address > uint64(len(d.memory)) || uint64(len(data)) > uint64(len(d.memory))-address {
			return fmt.Errorf("p390: read exceeds aperture")
		}
		return d.service.ReadAperture(uint32(address), data)
	default:
		return fmt.Errorf("p390: unknown inspection space %q", space)
	}
}

// P390Device describes construction policy and placement. Defaults are recipe
// policy; neither the portable model nor an emulator dispatcher owns a slot.
func P390Device(name string, bdf uint16, compat bool, start time.Time) device.Spec {
	return device.Spec{Name: name, BDF: bdf, New: func() (device.PCI, error) { return NewP390PCI(compat, start), nil }, Check: func(p device.Profile) error {
		if p.Architecture != "i386" || p.CPUs != 1 || p.UEFI {
			return fmt.Errorf("P/390 requires a single i386 BIOS CPU")
		}
		return nil
	}}
}
