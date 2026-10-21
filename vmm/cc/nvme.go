package cc

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

const nvmeAddress = 0xd0000000

// pciNVMe replaces IDE at 00:01.0. One namespace, one I/O queue pair and
// level-triggered INTx are supplied by the shared cc NVMe controller.
type pciNVMe struct {
	config     [256]byte
	controller *hypervisor.NVMeController
	irq        func(uint32, bool) error
	pending    bool
	msi        func(uint64, uint32) error
}

type nvmeDisk struct{ disk vmm.Disk }

func (d nvmeDisk) Size() int64                             { return d.disk.Device.Geometry().Size }
func (d nvmeDisk) ReadAt(b []byte, off int64) (int, error) { return d.disk.Device.ReadAt(b, off) }
func (d nvmeDisk) WriteAt(b []byte, off int64) (int, error) {
	if d.disk.ReadOnly {
		return 0, fmt.Errorf("NVMe disk is read-only")
	}
	w, ok := d.disk.Device.(io.WriterAt)
	if !ok {
		return 0, fmt.Errorf("NVMe disk is not writable")
	}
	return w.WriteAt(b, off)
}

type nvmeMemory struct{ p *pc }

func (m nvmeMemory) SliceIPA(addr uint64, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative NVMe DMA length")
	}
	return m.p.inputMemory(addr, uint64(size))
}
func (m nvmeMemory) ReadIPA(addr uint64, size int) ([]byte, error) {
	b, err := m.SliceIPA(addr, size)
	return append([]byte(nil), b...), err
}
func (m nvmeMemory) ReadIPAInto(addr uint64, dst []byte) error {
	b, err := m.SliceIPA(addr, len(dst))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}
func (m nvmeMemory) WriteIPA(addr uint64, src []byte) error {
	b, err := m.SliceIPA(addr, len(src))
	if err != nil {
		return err
	}
	copy(b, src)
	return nil
}

func newPCINVMe(p *pc) *pciNVMe {
	d := &pciNVMe{irq: p.cpu.SetIRQ}
	binary.LittleEndian.PutUint16(d.config[0:], 0x1b36)
	binary.LittleEndian.PutUint16(d.config[2:], 0x0010)
	d.config[4] = 6 // Firmware enables memory decoding and bus mastering.
	d.config[8], d.config[9], d.config[10], d.config[11] = 0, 2, 8, 1
	binary.LittleEndian.PutUint32(d.config[0x10:], nvmeAddress)
	binary.LittleEndian.PutUint32(d.config[0x2c:], 0x00101b36)
	d.config[0x3c], d.config[0x3d] = 16, 1
	if m, ok := p.cpu.(interface{ SetMSI(uint64, uint32) error }); ok {
		d.msi = m.SetMSI
		d.config[6] = 0x10 // Capabilities list.
		d.config[0x34] = 0x50
		d.config[0x50] = 5 // MSI, one 64-bit message, no per-vector masking.
		d.config[0x52] = 0x80
	}
	d.controller = hypervisor.NewNVMeController(nvmeDisk{p.disk}, nvmeMemory{p}, d, 16)
	return d
}
func (d *pciNVMe) SetMSI(addr uint64, data uint32) error {
	if d.msi == nil {
		return fmt.Errorf("MSI unavailable")
	}
	return d.msi(addr, data)
}
func (d *pciNVMe) syncInterrupt() error {
	enabled := d.config[0x52]&1 != 0
	addr := binary.LittleEndian.Uint64(d.config[0x54:])
	data := uint32(binary.LittleEndian.Uint16(d.config[0x5c:]))
	d.controller.ConfigureMSI(enabled, addr, data)
	return d.irq(16, d.pending && !enabled && d.config[5]&4 == 0)
}
func (d *pciNVMe) SetIRQ(line uint32, high bool) error {
	d.pending = high
	return d.irq(line, high && d.config[5]&4 == 0 && d.config[0x52]&1 == 0)
}
func (d *pciNVMe) write(offset int, value byte) {
	if d.msi != nil {
		switch offset {
		case 0x52:
			d.config[offset] = 0x80 | value&1
		case 0x54:
			d.config[offset] = value & 0xfc
		case 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d:
			d.config[offset] = value
		}
	}
	switch offset {
	case 4:
		d.config[offset] = value & 6
	case 5:
		d.config[offset] = value & 4 // Interrupt Disable.
	case 0x10:
		d.config[offset] = 0
	case 0x11:
		d.config[offset] = value & 0xc0 // 16 KiB 32-bit BAR, including sizing probe.
	case 0x12, 0x13, 0x3c:
		d.config[offset] = value
	}
}
func (d *pciNVMe) base() uint64 { return uint64(binary.LittleEndian.Uint32(d.config[0x10:])) }
func (d *pciNVMe) contains(addr uint64, size uint8) bool {
	return d.config[4]&2 != 0 && addr >= d.base() && addr-d.base() < hypervisor.NVMeMMIOSize && uint64(size) <= hypervisor.NVMeMMIOSize-(addr-d.base())
}
func (d *pciNVMe) mmio(ex hypervisor.X86Exit, cpu hypervisor.X86) error {
	if ex.Write {
		if d.config[4]&4 == 0 {
			return fmt.Errorf("NVMe DMA with bus mastering disabled")
		}
		var raw [8]byte
		copy(raw[:], ex.Data)
		return d.controller.WriteMMIO(ex.Address-d.base(), int(ex.Size), binary.LittleEndian.Uint64(raw[:]))
	}
	v, err := d.controller.ReadMMIO(ex.Address-d.base(), int(ex.Size))
	if err != nil {
		return err
	}
	cpu.CompleteMMIORead(v, uint32(ex.Size))
	return nil
}
