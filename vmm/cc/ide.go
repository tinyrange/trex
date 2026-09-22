package cc

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

// ide is a primary ATA task file with one PIO disk. All transfers go directly
// through the block abstraction, including a caller-selected memory overlay.
type ideFailure struct {
	command, feature, code byte
	task                   [8]byte
	reason                 string
}

type ide struct {
	disk                     vmm.Disk
	geometry                 vmm.CHSGeometry
	irq                      func(uint32, bool) error
	task                     [8]byte
	control                  byte
	buffer                   [512]byte
	position, remaining      int
	lba                      int64
	write, identify, pending bool
	commands                 uint64
	dmaEnabled, dmaPending   bool
	dmaMode                  byte
	lastCommand, lastFeature byte
	failures                 []ideFailure
	dmaError                 string
}

func newIDE(disk vmm.Disk, g vmm.CHSGeometry, irq func(uint32, bool) error) *ide {
	d := &ide{disk: disk, geometry: g, irq: irq}
	d.reset()
	return d
}
func (d *ide) reset() {
	d.task = [8]byte{0, 1, 1, 1, 0, 0, 0xa0, 0x50}
	d.position = 0
	d.remaining = 0
	d.write = false
	d.identify = false
	d.dmaPending = false
	d.dmaMode = 0xff
}
func (d *ide) signal(level bool) error {
	d.pending = level
	return d.irq(14, level && d.control&2 == 0)
}
func (d *ide) fail(code byte) error {
	if len(d.failures) == 8 {
		copy(d.failures, d.failures[1:])
		d.failures = d.failures[:7]
	}
	d.failures = append(d.failures, ideFailure{d.lastCommand, d.lastFeature, code, d.task, d.dmaError})
	d.task[1] = code
	d.task[7] = 0x51
	d.remaining = 0
	return d.signal(true)
}
func (d *ide) address() (int64, bool) {
	if d.task[6]&0x40 != 0 {
		return int64(d.task[3]) | int64(d.task[4])<<8 | int64(d.task[5])<<16 | int64(d.task[6]&15)<<24, true
	}
	c, h, s := int(d.task[4])|int(d.task[5])<<8, int(d.task[6]&15), int(d.task[3])
	if c >= d.geometry.Cylinders || h >= d.geometry.Heads || s < 1 || s > d.geometry.Sectors {
		return 0, false
	}
	return int64((c*d.geometry.Heads+h)*d.geometry.Sectors + s - 1), true
}
func (d *ide) advance() {
	d.lba++
	d.remaining--
	d.task[2] = byte(d.remaining)
	if d.task[6]&0x40 != 0 {
		d.task[3] = byte(d.lba)
		d.task[4] = byte(d.lba >> 8)
		d.task[5] = byte(d.lba >> 16)
		d.task[6] = (d.task[6] & 0xf0) | byte(d.lba>>24)&15
		return
	}
	c := d.lba / int64(d.geometry.Heads*d.geometry.Sectors)
	h := d.lba / int64(d.geometry.Sectors) % int64(d.geometry.Heads)
	d.task[3] = byte(d.lba%int64(d.geometry.Sectors) + 1)
	d.task[4] = byte(c)
	d.task[5] = byte(c >> 8)
	d.task[6] = (d.task[6] & 0xf0) | byte(h)
}
func (d *ide) readSector() error {
	if _, err := d.disk.Device.ReadAt(d.buffer[:], d.lba*512); err != nil {
		d.dmaError = fmt.Sprintf("PIO read at %#x: %v", d.lba*512, err)
		return d.fail(0x40)
	}
	d.position = 0
	d.task[7] = 0x58
	return d.signal(true)
}
func (d *ide) command(command byte) error {
	d.commands++
	feature := d.task[1]
	d.lastCommand, d.lastFeature = command, feature
	d.dmaError = ""
	if err := d.signal(false); err != nil {
		return err
	}
	d.task[1] = 0
	d.position = 0
	d.identify = false
	d.write = false
	d.dmaPending = false
	if d.task[6]&0x10 != 0 {
		d.task[7] = 0
		return nil
	}
	switch {
	case command == 0xec:
		clear(d.buffer[:])
		word := func(i int, v uint16) { binary.LittleEndian.PutUint16(d.buffer[i*2:], v) }
		word(0, 0x40)
		word(1, uint16(d.geometry.Cylinders))
		word(3, uint16(d.geometry.Heads))
		word(6, uint16(d.geometry.Sectors))
		word(47, 0x8001)
		word(49, 0x200)
		if d.dmaEnabled {
			word(49, 0x300)
			modes := uint16(7)
			if d.dmaMode < 3 {
				modes |= 1 << (8 + d.dmaMode)
			}
			word(63, modes)
		}
		word(53, 1)
		word(54, uint16(d.geometry.Cylinders))
		word(55, uint16(d.geometry.Heads))
		word(56, uint16(d.geometry.Sectors))
		capacity := uint32(d.disk.Device.Geometry().Size / 512)
		word(57, uint16(capacity))
		word(58, uint16(capacity>>16))
		word(60, uint16(capacity))
		word(61, uint16(capacity>>16))
		for i := 54; i < 94; i++ {
			d.buffer[i] = ' '
		}
		model := "TinyRangeX ATA disk"
		for i, c := range []byte(model) {
			d.buffer[54+(i^1)] = c
		}
		d.identify = true
		d.remaining = 1
		d.task[7] = 0x58
		return d.signal(true)
	case command == 0x20 || command == 0x21 || command == 0x30 || command == 0x31 || command == 0x40 || command == 0x41 || command >= 0xc8 && command <= 0xcb:
		if command >= 0xc8 && !d.dmaEnabled {
			return d.fail(4)
		}
		lba, ok := d.address()
		if !ok {
			return d.fail(0x10)
		}
		d.lba = lba
		d.remaining = int(d.task[2])
		if d.remaining == 0 {
			d.remaining = 256
		}
		if lba < 0 || int64(d.remaining) > d.disk.Device.Geometry().Size/512-lba {
			return d.fail(0x10)
		}
		if command == 0x40 || command == 0x41 {
			d.remaining = 0
			d.task[7] = 0x50
			return d.signal(true)
		}
		d.write = command == 0x30 || command == 0x31 || command == 0xca || command == 0xcb
		if d.write {
			if d.disk.ReadOnly {
				return d.fail(4)
			}
			if _, ok := d.disk.Device.(io.WriterAt); !ok {
				return d.fail(4)
			}
		}
		if command >= 0xc8 {
			d.dmaPending = true
			d.task[7] = 0x58
			return nil
		}
		if d.write {
			d.task[7] = 0x58
			return nil
		}
		return d.readSector()
	case command == 0x91:
		heads, sectors := int(d.task[6]&15)+1, int(d.task[2])
		if sectors == 0 || sectors > 63 {
			return d.fail(4)
		}
		d.geometry.Heads, d.geometry.Sectors = heads, sectors
		d.geometry.Cylinders = int(d.disk.Device.Geometry().Size / 512 / int64(heads*sectors))
	case command == 0x90:
		d.task[1] = 1
	case command >= 0x10 && command <= 0x1f, command >= 0x70 && command <= 0x7f:
	case command == 0xef:
		if feature == 3 && d.dmaEnabled {
			mode := d.task[2]
			if mode >= 0x20 && mode <= 0x22 {
				d.dmaMode = mode - 0x20
			} else if mode != 0 && (mode < 8 || mode > 12) {
				return d.fail(4)
			} else {
				d.dmaMode = 0xff
			}
		} else if feature != 2 && feature != 0x82 {
			return d.fail(4)
		}
	case command == 0xe7:
		if flusher, ok := d.disk.Device.(block.Flusher); ok && d.disk.Device.Capabilities().Flush {
			if err := flusher.Flush(); err != nil {
				return d.fail(4)
			}
		}
	default:
		return d.fail(4)
	}
	d.task[7] = 0x50
	return d.signal(true)
}
func (d *ide) io(ex hypervisor.X86Exit) error {
	if ex.Port == 0x3f6 {
		if ex.Write {
			old := d.control
			d.control = ex.Data[0]
			if d.control&4 != 0 {
				d.task[7] = 0x80
				return d.signal(false)
			}
			if old&4 != 0 {
				d.reset()
			}
			return d.irq(14, d.pending && d.control&2 == 0)
		}
		for i := range ex.Data {
			ex.Data[i] = d.status()
		}
		return nil
	}
	reg := int(ex.Port - 0x1f0)
	if reg != 0 {
		if ex.Size != 1 {
			return fmt.Errorf("ATA task register %d requires byte IO", reg)
		}
		for i := range ex.Data {
			if ex.Write {
				if reg == 7 {
					if err := d.command(ex.Data[i]); err != nil {
						return err
					}
				} else {
					d.task[reg] = ex.Data[i]
				}
			} else {
				if reg == 7 {
					ex.Data[i] = d.status()
					if err := d.signal(false); err != nil {
						return err
					}
				} else {
					ex.Data[i] = d.task[reg]
				}
			}
		}
		return nil
	}
	for i := range ex.Data {
		if d.task[7]&8 == 0 || d.remaining == 0 {
			if !ex.Write {
				ex.Data[i] = 0xff
			}
			continue
		}
		if ex.Write != d.write {
			return d.fail(4)
		}
		if ex.Write {
			d.buffer[d.position] = ex.Data[i]
		} else {
			ex.Data[i] = d.buffer[d.position]
		}
		d.position++
		if d.position == 512 {
			if d.identify {
				d.remaining = 0
				d.task[7] = 0x50
				continue
			}
			if d.write {
				if _, err := d.disk.Device.(io.WriterAt).WriteAt(d.buffer[:], d.lba*512); err != nil {
					d.dmaError = fmt.Sprintf("PIO write at %#x: %v", d.lba*512, err)
					return d.fail(0x40)
				}
			}
			d.advance()
			d.position = 0
			if d.remaining == 0 {
				d.task[7] = 0x50
				if d.write {
					if err := d.signal(true); err != nil {
						return err
					}
				}
			} else if d.write {
				d.task[7] = 0x58
				if err := d.signal(true); err != nil {
					return err
				}
			} else {
				if err := d.readSector(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (d *ide) status() byte {
	if d.task[6]&0x10 != 0 {
		return 0
	}
	return d.task[7]
}
