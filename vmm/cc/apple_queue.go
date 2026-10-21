package cc

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/block"
	"io"
)

type appleQueue struct {
	dmaMemory func(uint64, uint64, bool) ([]byte, error)
}

// Apple virtual queue descriptors are sequential 16-byte records: physical
// address, length, ownership (1 while submitted), then NEXT/WRITE flags.
// These differ from the standard virtio split-ring layout.
type appleDescriptor struct {
	record, data []byte
	flags        uint16
	address      uint64
}

func (d *appleQueue) descriptors(address uint64) ([]appleDescriptor, error) {
	var chain []appleDescriptor
	for i := uint64(0); i < 5; i++ {
		r, err := d.dmaMemory(address+i*16, 16, true)
		if err != nil {
			return nil, err
		}
		length := binary.LittleEndian.Uint32(r[8:])
		if binary.LittleEndian.Uint16(r[12:]) != 1 || length > 8<<20 {
			return nil, fmt.Errorf("apple queue: invalid ownership or length")
		}
		flags := binary.LittleEndian.Uint16(r[14:])
		if flags&^uint16(3) != 0 {
			return nil, fmt.Errorf("apple queue: unsupported flags %#x", flags)
		}
		dataAddress := binary.LittleEndian.Uint64(r)
		data, err := d.dmaMemory(dataAddress, uint64(length), flags&2 != 0)
		if err != nil {
			return nil, err
		}
		chain = append(chain, appleDescriptor{record: r, data: data, flags: flags, address: address + i*16})
		if flags&1 == 0 {
			break
		}
	}
	if len(chain) == 0 || chain[len(chain)-1].flags&1 != 0 {
		return nil, fmt.Errorf("apple queue: unterminated descriptor chain")
	}
	return chain, nil
}

func (d *appleQueue) submitBlockDevice(address uint64, disk block.Device) error {
	chain, err := d.descriptors(address)
	if err != nil {
		return err
	}
	if len(chain) != 3 || chain[0].flags != 1 || chain[2].flags != 2 || len(chain[0].data) != 16 || len(chain[2].data) != 1 {
		return fmt.Errorf("apple queue: unsupported block descriptor chain")
	}
	header := chain[0].data
	kind, sector := binary.LittleEndian.Uint32(header), binary.LittleEndian.Uint64(header[8:])
	if kind > 1 || kind == 0 && chain[1].flags != 3 || kind == 1 && chain[1].flags != 1 {
		return fmt.Errorf("apple queue: unsupported block operation %d", kind)
	}
	if disk == nil {
		return fmt.Errorf("apple queue: no disk attached")
	}
	data := chain[1].data
	if sector > uint64(disk.Geometry().Size)/512 || uint64(len(data)) > uint64(disk.Geometry().Size)-sector*512 {
		return fmt.Errorf("apple queue: block read exceeds disk")
	}
	var n int
	if kind == 0 {
		n, err = disk.ReadAt(data, int64(sector*512))
	} else {
		writer, ok := disk.(block.Writer)
		if !ok || !disk.Capabilities().Writable {
			return fmt.Errorf("apple queue: disk is read-only")
		}
		n, err = writer.WriteAt(data, int64(sector*512))
	}
	if err != nil && err != io.EOF {
		return err
	}
	if n != len(data) {
		return io.ErrUnexpectedEOF
	}
	chain[2].data[0] = 0
	for _, desc := range chain {
		binary.LittleEndian.PutUint16(desc.record[12:], 0)
	}
	return nil
}
