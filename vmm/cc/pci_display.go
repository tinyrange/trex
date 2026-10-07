package cc

import (
	"encoding/binary"
	"github.com/tinyrange/trex/vmm/ramfb"
)

// pciDisplay owns the firmware's fixed shared framebuffer aperture at 00:02.0.
// It is an unaccelerated synthetic display, not an emulated Apple GPU. The
// aperture is firmware-reserved RAM: relocation and decode disabling are not
// supported, and config readback must never claim an unmapped address. BAR0
// nevertheless implements the standard all-ones resource size probe.
type pciDisplay struct {
	config   [256]byte
	barWrite [4]byte
}

func newPCIDisplay() *pciDisplay {
	d := &pciDisplay{}
	binary.LittleEndian.PutUint16(d.config[0:], 0x1234)
	binary.LittleEndian.PutUint16(d.config[2:], 0xcc02)
	d.config[4] = 2                  // Fixed firmware memory aperture; no I/O or bus mastering.
	d.config[8], d.config[11] = 1, 3 // VGA-compatible display class.
	binary.LittleEndian.PutUint32(d.config[0x10:], ramfb.Address)
	binary.LittleEndian.PutUint16(d.config[0x2c:], 0x1234)
	binary.LittleEndian.PutUint16(d.config[0x2e:], 0xcc02)
	d.config[0x3c] = 0xff // No interrupt pin.
	copy(d.barWrite[:], d.config[0x10:0x14])
	return d
}

func (d *pciDisplay) write(offset int, value byte) {
	if offset < 0x10 || offset >= 0x14 {
		return
	}
	d.barWrite[offset-0x10] = value
	bar := uint32(ramfb.Address)
	if binary.LittleEndian.Uint32(d.barWrite[:]) == 0xffffffff {
		bar = ^uint32(ramfb.Size-1) & 0xfffffff0
	}
	binary.LittleEndian.PutUint32(d.config[0x10:], bar)
}
