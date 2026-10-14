package cc

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/channel"
)

// appleSimpleStorage implements the sequential-descriptor Apple transport.
// Placement, backing, and device identity are supplied by the platform.
type appleSimpleStorage struct {
	appleQueue
	address   uint64
	disk      block.Device
	transport [4096]byte
	complete  bool
}

func (d *appleSimpleStorage) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x2000 && (n == 4 || n == 8) && a%uint64(n) == 0
}
func (d *appleSimpleStorage) Read(a uint64, n int) (uint64, error) {
	o := a - d.address
	if o == 0x1000 && n == 8 {
		return uint64(d.disk.Geometry().Size / 512), nil
	}
	if o == 0x1014 && n == 4 {
		return 512, nil
	}
	if o == 16 && n == 4 {
		if d.complete {
			return 1, nil
		}
		return 0, nil
	}
	if o == 0 || o == 4 || o == 8 || o == 0x400 || o == 0x404 {
		if n == 8 {
			return binary.LittleEndian.Uint64(d.transport[o:]), nil
		}
		return uint64(binary.LittleEndian.Uint32(d.transport[o:])), nil
	}
	return 0, fmt.Errorf("Apple simple storage: unsupported read%d at %#x", n, o)
}
func (d *appleSimpleStorage) Write(a uint64, n int, v uint64) error {
	o := a - d.address
	if o == 0x408 && n == 8 {
		d.complete = false
		if err := d.submitBlockDevice(v, d.disk); err != nil {
			return err
		}
		d.complete = true
		return nil
	}
	if o == 0x410 && n == 4 && v == 0 {
		return nil
	}
	if o == 0x400 && n == 4 && v == 1 || o == 0x404 && n == 4 && v <= 3 {
		binary.LittleEndian.PutUint32(d.transport[o:], uint32(v))
		return nil
	}
	return fmt.Errorf("Apple simple storage: unsupported write%d at %#x", n, o)
}

type appleSimpleUSB struct {
	appleQueue
	address      uint64
	usbTransport [4096]byte
	usbQueue     uint32
	usbRX        uint64
	usb          channel.ByteChannel
	usbInput     []byte
	usbBusy      [2]bool
	usbTX        []appleDescriptor
	usbOutput    []byte
	emit         func(string, any)
}

func (d *appleSimpleUSB) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x2000 && (n == 4 || n == 8) && a%uint64(n) == 0
}
func (d *appleSimpleUSB) Read(a uint64, n int) (uint64, error) {
	o := a - d.address
	if o == 16 && n == 4 {
		if !d.usbBusy[d.usbQueue] {
			return 1, nil
		}
		return 0, nil
	}
	if o == 0 || o == 4 || o == 8 || o == 0x400 || o == 0x404 {
		if n == 8 {
			return binary.LittleEndian.Uint64(d.usbTransport[o:]), nil
		}
		return uint64(binary.LittleEndian.Uint32(d.usbTransport[o:])), nil
	}
	return 0, fmt.Errorf("Apple simple USB: unsupported read%d at %#x", n, o)
}
func (d *appleSimpleUSB) Write(a uint64, n int, v uint64) error {
	o := a - d.address
	if o == 0x410 && n == 4 && v < 2 {
		d.usbQueue = uint32(v)
		return nil
	}
	if (o == 0x400 && v == 1 || o == 0x404 && v <= 3) && n == 4 {
		if o == 0x400 {
			d.usbRX = 0
			d.usbTX = nil
			d.usbInput = nil
			d.usbOutput = nil
			d.usbBusy = [2]bool{}
			d.usbQueue = 0
		}
		binary.LittleEndian.PutUint32(d.usbTransport[o:], uint32(v))
		return nil
	}
	if o == 0x408 && n == 8 {
		return d.submitUSB(v)
	}
	return fmt.Errorf("Apple simple USB: unsupported write%d at %#x", n, o)
}
func (d *appleSimpleUSB) Poll() error { return d.pollUSB() }
