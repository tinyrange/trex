// Package openbsd reads version-1 OpenBSD disklabels. Layout and checksum
// facts follow OpenBSD sys/sys/disklabel.h and sys/kern/subr_disk.c.
// Partition addresses are absolute disk sectors, not relative to the label.
package openbsd

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/tinyrange/trex/storage"
)

const (
	magic         = 0x82564557
	headerSize    = 148
	partitionSize = 16
	maxPartitions = 52
)

type Partition struct {
	Index                   int
	Name                    string
	Start, Sectors          uint64
	Type                    uint8
	FragmentSize, BlockSize uint32
	CylindersPerGroup       uint16
	Data                    storage.Reader
}

type Label struct {
	SectorSize                    uint32
	Sectors, BoundStart, BoundEnd uint64
	UID                           [8]byte
	TypeName, PackName            string
	Partitions                    []Partition
}

// Open reads a disklabel at an explicit byte offset within the complete disk.
// For amd64 media the label is usually at OpenBSD-partition-offset + 512.
// Sector geometry comes from the label (including 4096-byte sectors). All
// nonempty partition ranges must be present. Empty and overlapping partitions,
// including raw slot c, are retained; data remains a borrowed read-only view.
func Open(source storage.Reader, labelOffset int64) (*Label, error) {
	l, err := readLabel(source, labelOffset)
	if err != nil {
		return nil, err
	}
	if l.Sectors > uint64(source.Size())/uint64(l.SectorSize) {
		return nil, fmt.Errorf("openbsd label: disk extends past input")
	}
	for i := range l.Partitions {
		p := &l.Partitions[i]
		if p.Sectors != 0 {
			p.Data = io.NewSectionReader(source, int64(p.Start)*int64(l.SectorSize), int64(p.Sectors)*int64(l.SectorSize))
		}
	}
	return l, nil
}

// readLabel validates the declared on-disk geometry before requiring the
// complete disk. Auto detection also uses it to distinguish a whole disk from
// a standalone FFS volume that retains its parent's label in the boot area.
func readLabel(source storage.Reader, labelOffset int64) (*Label, error) {
	if source == nil || labelOffset < 0 || source.Size() < headerSize || labelOffset > source.Size()-headerSize {
		return nil, fmt.Errorf("openbsd label: truncated header or invalid offset")
	}
	h := make([]byte, headerSize)
	if _, err := io.ReadFull(io.NewSectionReader(source, labelOffset, headerSize), h); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(h) == magic:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(h) == magic:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("openbsd label: bad magic")
	}
	if order.Uint32(h[132:]) != magic {
		return nil, fmt.Errorf("openbsd label: bad second magic")
	}
	if version := order.Uint16(h[114:]); version != 1 {
		return nil, fmt.Errorf("openbsd label: unsupported version %d", version)
	}
	count := int(order.Uint16(h[138:]))
	if count > maxPartitions {
		return nil, fmt.Errorf("openbsd label: invalid partition count")
	}
	size := headerSize + count*partitionSize
	if int64(size) > source.Size()-labelOffset {
		return nil, fmt.Errorf("openbsd label: truncated partition table")
	}
	raw := make([]byte, size)
	copy(raw, h)
	if _, err := io.ReadFull(io.NewSectionReader(source, labelOffset+headerSize, int64(size-headerSize)), raw[headerSize:]); err != nil {
		return nil, err
	}
	var sum uint16
	for i := 0; i < len(raw); i += 2 {
		sum ^= order.Uint16(raw[i:])
	}
	if sum != 0 {
		return nil, fmt.Errorf("openbsd label: invalid checksum")
	}
	sectorSize := order.Uint32(h[40:])
	if sectorSize < 512 || sectorSize > 65536 || sectorSize&(sectorSize-1) != 0 {
		return nil, fmt.Errorf("openbsd label: invalid sector size")
	}
	l := &Label{
		SectorSize: sectorSize,
		Sectors:    uint64(order.Uint32(h[60:])) | uint64(order.Uint16(h[112:]))<<32,
		BoundStart: uint64(order.Uint32(h[80:])) | uint64(order.Uint16(h[76:]))<<32,
		BoundEnd:   uint64(order.Uint32(h[84:])) | uint64(order.Uint16(h[78:]))<<32,
		TypeName:   strings.TrimRight(string(h[8:24]), "\x00"),
		PackName:   strings.TrimRight(string(h[24:40]), "\x00"),
		Partitions: make([]Partition, count),
	}
	copy(l.UID[:], h[64:72])
	if l.Sectors == 0 || l.Sectors > math.MaxInt64/uint64(sectorSize) || l.BoundStart > l.BoundEnd || l.BoundEnd > l.Sectors {
		return nil, fmt.Errorf("openbsd label: invalid disk geometry")
	}
	if uint64(labelOffset)+uint64(size) > l.Sectors*uint64(sectorSize) {
		return nil, fmt.Errorf("openbsd label: label outside declared disk")
	}
	for i := range l.Partitions {
		b := raw[headerSize+i*partitionSize:]
		name := rune('a' + i)
		if i >= 26 {
			name = rune('A' + i - 26)
		}
		p := Partition{Index: i, Name: string(name),
			Sectors: uint64(order.Uint32(b)) | uint64(order.Uint16(b[10:]))<<32,
			Start:   uint64(order.Uint32(b[4:])) | uint64(order.Uint16(b[8:]))<<32,
			Type:    b[12], CylindersPerGroup: order.Uint16(b[14:]),
		}
		if p.Sectors != 0 && (p.Start > l.Sectors || p.Sectors > l.Sectors-p.Start) {
			return nil, fmt.Errorf("openbsd label: partition %s outside disk", p.Name)
		}
		if p.Type == 7 && b[13] != 0 {
			blockShift, fragShift := uint(b[13]>>3)+12, uint(b[13]&7)
			if blockShift > 16 || fragShift == 0 || fragShift > 4 {
				return nil, fmt.Errorf("openbsd label: invalid FFS geometry in %s", p.Name)
			}
			p.BlockSize = 1 << blockShift
			p.FragmentSize = p.BlockSize >> (fragShift - 1)
			if p.FragmentSize < sectorSize {
				return nil, fmt.Errorf("openbsd label: FFS fragment smaller than sector in %s", p.Name)
			}
		}
		l.Partitions[i] = p
	}
	return l, nil
}
