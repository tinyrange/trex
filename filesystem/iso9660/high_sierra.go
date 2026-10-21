package iso9660

import (
	"encoding/binary"
	"fmt"
)

// High Sierra descriptors have a both-endian sector address before the type
// and CDROM identifier. Descriptor sectors are always 2048 bytes; extents use
// the logical block size declared by the primary descriptor.
func (i *isoImage) highSierraDescriptor(p []byte, sector uint32) (bool, error) {
	if string(p[9:14]) != "CDROM" || p[14] != 1 {
		return false, fmt.Errorf("high sierra: invalid volume descriptor")
	}
	address, err := both32(p[:8])
	if err != nil || address != sector {
		return false, fmt.Errorf("high sierra: invalid descriptor sector address")
	}
	switch p[8] {
	case 1:
		blocks, err := both32(p[88:96])
		if err != nil {
			return false, err
		}
		blockSize := binary.LittleEndian.Uint16(p[136:138])
		if blockSize != binary.BigEndian.Uint16(p[138:140]) || blockSize < 512 || blockSize > 2048 || blockSize&(blockSize-1) != 0 {
			return false, fmt.Errorf("high sierra: invalid logical block size")
		}
		i.blockSize = int64(blockSize)
		i.volumeSize = int64(blocks) * i.blockSize
		if blocks == 0 || i.volumeSize > i.file.Size() {
			return false, fmt.Errorf("high sierra: volume exceeds source")
		}
		root, err := i.highSierraRecord(p[180:214])
		if err != nil {
			return false, err
		}
		if !root.isDir() || root.size == 0 {
			return false, fmt.Errorf("high sierra: invalid root directory")
		}
		i.root = root
	case 255:
		if i.root.size == 0 {
			return false, fmt.Errorf("high sierra: primary volume descriptor not found")
		}
		return true, nil
	}
	return false, nil
}

func (i *isoImage) highSierraRecord(raw []byte) (isoDirRecord, error) {
	r, err := parseISODirRecord(raw)
	if err != nil {
		return r, err
	}
	r.extent, err = both32(raw[2:10])
	if err != nil {
		return r, err
	}
	r.size, err = both32(raw[10:18])
	if err != nil {
		return r, err
	}
	// The recording date is six bytes; flags precede a reserved byte, unlike
	// ISO9660's seven-byte date followed by flags.
	r.flags = raw[24]
	start := (int64(r.extent) + int64(raw[1])) * i.blockSize
	if start > i.volumeSize || int64(r.size) > i.volumeSize-start {
		return r, fmt.Errorf("high sierra: file extent exceeds volume")
	}
	if uint64(r.extent)+uint64(raw[1]) > uint64(^uint32(0)) {
		return r, fmt.Errorf("high sierra: extended attribute extent overflows")
	}
	r.extent += uint32(raw[1])
	return r, nil
}
