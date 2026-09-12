// Package apm reads Apple Partition Maps without mounting or copying partitions.
package apm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Partition struct {
	Index                                                     int
	BlockSize                                                 int
	Name, Type, Processor                                     []byte
	Start, Blocks, DataStart, DataBlocks, Status              uint32
	BootStart, BootSize, BootAddress, BootEntry, BootChecksum uint32
	Data                                                      starfile.File
}
type Map struct {
	BlockSize       int
	DeviceBlockSize uint16
	DeviceBlocks    uint32
	Partitions      []Partition
}

// Open reads the explicitly selected logical block-size view. Classic boot CDs
// can contain overlapping 512/2048-byte maps; driver-descriptor geometry must
// not silently choose between them. Fields follow the public APM format facts
// at https://formats.kaitai.io/apm_partition_table/ . No generated parser used.
// Out-of-image Apple_Free descriptors remain metadata with no data view. Every
// allocated partition must fit completely; no missing bytes are synthesized.
func Open(file starfile.File, blockSize, maximumEntries int) (*Map, error) {
	if (blockSize != 512 && blockSize != 1024 && blockSize != 2048) || maximumEntries <= 0 {
		return nil, fmt.Errorf("apm: invalid block size or entry limit")
	}
	var h [512]byte
	if _, err := starfile.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(h[:2]) != "ER" {
		return nil, fmt.Errorf("apm: missing driver descriptor signature")
	}
	m := &Map{BlockSize: blockSize, DeviceBlockSize: be.Uint16(h[2:]), DeviceBlocks: be.Uint32(h[4:])}
	driverCount := int(be.Uint16(h[16:]))
	if driverCount > (len(h)-18)/8 {
		return nil, fmt.Errorf("apm: driver descriptors exceed block zero")
	}
	driverStarts := make(map[uint32]bool, driverCount)
	for i := 0; i < driverCount; i++ {
		driverStarts[be.Uint32(h[18+i*8:])] = true
	}
	if _, err := starfile.ReadFullAt(file, h[:], int64(blockSize)); err != nil {
		return nil, err
	}
	if string(h[:2]) != "PM" {
		return nil, fmt.Errorf("apm: missing partition signature at selected block size")
	}
	count := int64(be.Uint32(h[4:]))
	if count == 0 || count > int64(maximumEntries) || count*int64(blockSize)+512 > file.Size() {
		return nil, fmt.Errorf("apm: partition count outside limits or input")
	}
	type span struct{ start, end int64 }
	var allocated []span
	for i := int64(1); i <= count; i++ {
		if _, err := starfile.ReadFullAt(file, h[:], i*int64(blockSize)); err != nil {
			return nil, err
		}
		if string(h[:2]) != "PM" || int64(be.Uint32(h[4:])) != count {
			return nil, fmt.Errorf("apm: inconsistent partition record %d", i)
		}
		p := Partition{Index: int(i), Name: cstring(h[16:48]), Type: cstring(h[48:80]), Processor: cstring(h[120:136]), Start: be.Uint32(h[8:]), Blocks: be.Uint32(h[12:]), DataStart: be.Uint32(h[80:]), DataBlocks: be.Uint32(h[84:]), Status: be.Uint32(h[88:]), BootStart: be.Uint32(h[92:]), BootSize: be.Uint32(h[96:]), BootAddress: be.Uint32(h[100:]), BootEntry: be.Uint32(h[108:]), BootChecksum: be.Uint32(h[116:])}
		p.BlockSize = blockSize
		// Universal boot CDs can share this record between their 512-byte
		// and 2048-byte maps. The CDvr driver describes device blocks, unlike
		// neighbouring 512-byte HFS/driver records. Require both the specific
		// boot argument tag and an independent block-zero driver descriptor;
		// a type name alone is insufficient to reinterpret geometry.
		if string(p.Type) == "Apple_Driver43_CD" && string(h[136:140]) == "CDvr" {
			if m.DeviceBlockSize != 2048 || !driverStarts[p.Start] {
				return nil, fmt.Errorf("apm: CDvr driver lacks matching 2048-byte device descriptor")
			}
			p.BlockSize = int(m.DeviceBlockSize)
		}
		start, size := int64(p.Start)*int64(p.BlockSize), int64(p.Blocks)*int64(p.BlockSize)
		free := string(p.Type) == "Apple_Free"
		if start > file.Size() || size > file.Size()-start {
			if !free {
				return nil, fmt.Errorf("apm: allocated partition %d exceeds input", i)
			}
		} else {
			p.Data = &starfile.Slice{Base: file, Offset: start, Length: size}
		}
		if !free && size > 0 {
			allocated = append(allocated, span{start, start + size})
		}
		m.Partitions = append(m.Partitions, p)
	}
	sort.Slice(allocated, func(i, j int) bool { return allocated[i].start < allocated[j].start })
	for i := 1; i < len(allocated); i++ {
		if allocated[i].start < allocated[i-1].end {
			return nil, fmt.Errorf("apm: overlapping allocated partitions")
		}
	}
	return m, nil
}
func cstring(b []byte) []byte {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return append([]byte{}, b...)
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	blockSize, maximumEntries := 512, 1000000
	if err := starlark.UnpackArgs("apm", args, kwargs, "file", &value, "block_size?", &blockSize, "maximum_entries?", &maximumEntries); err != nil {
		return nil, err
	}
	f, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("apm: expected file")
	}
	m, err := Open(f, blockSize, maximumEntries)
	if err != nil {
		return nil, err
	}
	parts := make([]starlark.Value, len(m.Partitions))
	for i, p := range m.Partitions {
		var data starlark.Value = starlark.None
		if p.Data != nil {
			data = p.Data
		}
		parts[i] = starfile.NewRecord(starlark.StringDict{
			"block_size": starlark.MakeInt(p.BlockSize),
			"index":      starlark.MakeInt(p.Index), "name": starlark.Bytes(p.Name), "partition_type": starlark.Bytes(p.Type), "processor": starlark.Bytes(p.Processor),
			"start_block": starlark.MakeUint(uint(p.Start)), "blocks": starlark.MakeUint(uint(p.Blocks)), "data_start_block": starlark.MakeUint(uint(p.DataStart)), "data_blocks": starlark.MakeUint(uint(p.DataBlocks)), "status": starlark.MakeUint(uint(p.Status)),
			"boot_start_block": starlark.MakeUint(uint(p.BootStart)), "boot_size": starlark.MakeUint(uint(p.BootSize)), "boot_address": starlark.MakeUint(uint(p.BootAddress)), "boot_entry": starlark.MakeUint(uint(p.BootEntry)), "boot_checksum": starlark.MakeUint(uint(p.BootChecksum)),
			"data": data, "complete": starlark.Bool(p.Data != nil),
		})
	}
	return starfile.NewRecord(starlark.StringDict{"partitions": starlark.NewList(parts), "block_size": starlark.MakeInt(blockSize), "device_block_size": starlark.MakeInt(int(m.DeviceBlockSize)), "device_blocks": starlark.MakeUint(uint(m.DeviceBlocks))}), nil
}
