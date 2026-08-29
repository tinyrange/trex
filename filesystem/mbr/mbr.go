package mbr

import (
	"encoding/binary"
	"fmt"
	"strings"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

const (
	mbrSectorSize       = int64(512)
	mbrPartitionStart   = int64(2048)
	mbrPartitionOffset  = mbrPartitionStart * mbrSectorSize
	mbrNTFSPartitionTyp = 0x07
)

func MBRBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value = starlark.None
	var size int64
	var bootCodeValue starlark.Value = starlark.None
	var chsValue starlark.Value = starlark.None
	diskSignature := uint(0)
	if err := starlark.UnpackArgs("mbr", args, kwargs, "source?", &source, "size?", &size, "boot_code?", &bootCodeValue, "disk_signature?", &diskSignature, "chs?", &chsValue); err != nil {
		return nil, err
	}
	if file, ok := source.(starfile.File); ok {
		if size != 0 || bootCodeValue != starlark.None || diskSignature != 0 || chsValue != starlark.None {
			return nil, fmt.Errorf("mbr: build options are not valid when parsing a file")
		}
		return newMBRVolume(file)
	}
	if source != starlark.None {
		if size != 0 {
			return nil, fmt.Errorf("mbr: specify an integer source or size, not both")
		}
		if err := starlark.AsInt(source, &size); err != nil {
			return nil, fmt.Errorf("mbr: got %s, want file or integer size", source.Type())
		}
	}
	if uint64(diskSignature) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("mbr: disk_signature must fit in 32 bits")
	}
	if size < 2*mbrSectorSize {
		return nil, fmt.Errorf("mbr: size must be at least %d bytes", 2*mbrSectorSize)
	}
	bootCode, err := fsinternal.BootCodeBytes("mbr", bootCodeValue)
	if err != nil {
		return nil, err
	}
	chs, err := fsinternal.CHSGeometry(chsValue)
	if err != nil {
		return nil, fmt.Errorf("mbr: chs: %w", err)
	}
	return &mbrBuilder{size: size, bootCode: bootCode, diskSignature: uint32(diskSignature), chs: chs}, nil
}

type mbrReadPartition struct {
	index     int
	bootable  bool
	kind      byte
	startLBA  int64
	sectors   int64
	partition starfile.File
}

type mbrVolume struct {
	file          starfile.File
	diskSignature uint32
	partitions    []mbrReadPartition
	paths         map[string]starfile.File
	files         *starlark.List
}

func newMBRVolume(file starfile.File) (*mbrVolume, error) {
	if file.Size() < mbrSectorSize {
		return nil, fmt.Errorf("mbr: image is too small")
	}
	sector, err := fsinternal.ReadBytesAt(file, 0, mbrSectorSize)
	if err != nil {
		return nil, fmt.Errorf("mbr: read sector: %w", err)
	}
	if sector[510] != 0x55 || sector[511] != 0xaa {
		return nil, fmt.Errorf("mbr: invalid boot signature")
	}
	volume := &mbrVolume{
		file: file, diskSignature: binary.LittleEndian.Uint32(sector[440:444]), paths: make(map[string]starfile.File),
	}
	fileNames := make([]starlark.Value, 0, 4)
	for slot := 0; slot < 4; slot++ {
		entry := sector[446+slot*16 : 462+slot*16]
		kind := entry[4]
		sectors := int64(binary.LittleEndian.Uint32(entry[12:16]))
		if kind == 0 || sectors == 0 {
			continue
		}
		if entry[0] != 0 && entry[0] != 0x80 {
			return nil, fmt.Errorf("mbr: partition %d has invalid boot flag %#x", slot+1, entry[0])
		}
		startLBA := int64(binary.LittleEndian.Uint32(entry[8:12]))
		offset := startLBA * mbrSectorSize
		partitionSize := sectors * mbrSectorSize
		if offset > file.Size() || partitionSize > file.Size()-offset {
			return nil, fmt.Errorf("mbr: partition %d extends past the image", slot+1)
		}
		partition := &starfile.Slice{
			Name: fmt.Sprintf("%s partition %d", file.String(), slot+1),
			Base: file, Offset: offset, Length: partitionSize,
		}
		path := fmt.Sprintf("/partition%d", slot+1)
		volume.partitions = append(volume.partitions, mbrReadPartition{
			index: slot + 1, bootable: entry[0] == 0x80, kind: kind,
			startLBA: startLBA, sectors: sectors, partition: partition,
		})
		volume.paths[path] = partition
		fileNames = append(fileNames, starlark.String(path))
	}
	volume.files = starlark.NewList(fileNames)
	return volume, nil
}

func (v *mbrVolume) String() string       { return fmt.Sprintf("<mbr partitions=%d>", len(v.partitions)) }
func (v *mbrVolume) Type() string         { return "mbr" }
func (v *mbrVolume) Freeze()              {}
func (v *mbrVolume) Truth() starlark.Bool { return starlark.True }
func (v *mbrVolume) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}
func (v *mbrVolume) AttrNames() []string { return []string{"disk_signature", "files", "partitions"} }
func (v *mbrVolume) Attr(name string) (starlark.Value, error) {
	switch name {
	case "disk_signature":
		return starlark.MakeUint(uint(v.diskSignature)), nil
	case "files":
		return v.files, nil
	case "partitions":
		values := make([]starlark.Value, len(v.partitions))
		for index, partition := range v.partitions {
			values[index] = starfile.NewRecord(starlark.StringDict{
				"bootable":  starlark.Bool(partition.bootable),
				"file":      partition.partition,
				"index":     starlark.MakeInt(partition.index),
				"offset":    starlark.MakeInt64(partition.startLBA * mbrSectorSize),
				"sectors":   starlark.MakeInt64(partition.sectors),
				"size":      starlark.MakeInt64(partition.sectors * mbrSectorSize),
				"start_lba": starlark.MakeInt64(partition.startLBA),
				"type":      starlark.MakeInt(int(partition.kind)),
			})
		}
		return starlark.NewList(values), nil
	}
	return nil, nil
}
func (v *mbrVolume) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("mbr: key is %s, want string", key.Type())
	}
	name = "/" + strings.Trim(strings.ReplaceAll(name, "\\", "/"), "/")
	if name == "/" {
		return v, true, nil
	}
	file, ok := v.paths[name]
	return file, ok, nil
}

type mbrBuilder struct {
	size          int64
	bootCode      []byte
	diskSignature uint32
	chs           *vmm.CHSGeometry
}

func (b *mbrBuilder) String() string       { return fmt.Sprintf("<mbr size=%d>", b.size) }
func (b *mbrBuilder) Type() string         { return "mbr" }
func (b *mbrBuilder) Freeze()              {}
func (b *mbrBuilder) Truth() starlark.Bool { return starlark.True }
func (b *mbrBuilder) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", b.Type())
}
func (b *mbrBuilder) Attr(name string) (starlark.Value, error) {
	switch name {
	case "partition":
		return starlark.NewBuiltin("partition", b.partitionBuiltin), nil
	}
	return nil, nil
}
func (b *mbrBuilder) AttrNames() []string {
	return []string{"partition"}
}

func (b *mbrBuilder) partitionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	bootable := false
	partitionType := mbrNTFSPartitionTyp
	startLBA := int(mbrPartitionStart)
	if err := starlark.UnpackArgs("partition", args, kwargs, "filesystem", &value, "bootable?", &bootable, "type?", &partitionType, "start_lba?", &startLBA); err != nil {
		return nil, err
	}
	if partitionType < 0 || partitionType > 0xff {
		return nil, fmt.Errorf("partition: type must fit in one byte")
	}
	if startLBA < 1 || uint64(startLBA) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("partition: start_lba must be between 1 and %#x", uint32(^uint32(0)))
	}
	partition, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("partition: got %s, want file", value.Type())
	}
	if partition.Size() <= 0 {
		return nil, fmt.Errorf("partition: filesystem must not be empty")
	}
	partitionOffset := int64(startLBA) * mbrSectorSize
	diskSize := b.size
	needed := partitionOffset + partition.Size()
	if diskSize < needed {
		diskSize = fsinternal.Align(needed, 1024*1024)
	}
	if diskSize/mbrSectorSize > 0xffffffff {
		return nil, fmt.Errorf("partition: disk image is too large for an MBR partition table")
	}
	partitionSectors := fsinternal.CeilDiv(partition.Size(), mbrSectorSize)
	if uint64(startLBA)+uint64(partitionSectors) > uint64(^uint32(0))+1 {
		return nil, fmt.Errorf("partition: partition is too large for an MBR partition table")
	}
	extents := []filesystemapi.ExtentSpec{
		{Start: 0, Size: mbrSectorSize, Data: b.mbrSector(bootable, byte(partitionType), uint32(startLBA), uint32(partitionSectors))},
		{Start: partitionOffset, Size: partition.Size(), File: partition},
	}
	return filesystemapi.NewGeneratedImage("mbr.raw", diskSize, extents), nil
}

func (b *mbrBuilder) mbrSector(bootable bool, partitionType byte, startLBA, sectors uint32) []byte {
	sector := make([]byte, mbrSectorSize)
	if len(b.bootCode) > 0 {
		copy(sector[:446], b.bootCode)
	} else {
		copy(sector[:446], defaultMBRBootCode)
	}
	binary.LittleEndian.PutUint32(sector[440:444], b.diskSignature)
	entry := sector[446:462]
	if bootable {
		entry[0] = 0x80
	}
	totalSectors := uint32(fsinternal.CeilDiv(b.size, mbrSectorSize))
	entry[1], entry[2], entry[3] = mbrCHSForGeometry(startLBA, totalSectors, b.chs)
	entry[4] = partitionType
	entry[5], entry[6], entry[7] = mbrCHSForGeometry(startLBA+sectors-1, totalSectors, b.chs)
	binary.LittleEndian.PutUint32(entry[8:12], startLBA)
	binary.LittleEndian.PutUint32(entry[12:16], sectors)
	sector[510] = 0x55
	sector[511] = 0xaa
	return sector
}

// defaultMBRBootCode is a tiny BIOS MBR inspired by the MIT-licensed
// MS-DOS 4.0 FDISK MBR source at v4.0/src/CMD/FDISK/FDBOOT.ASM.
// It preserves the classic behavior of relocating to 0000:0600,
// selecting the active partition, loading its VBR at 0000:7c00,
// checking the 55aa signature, and jumping to it. It uses INT 13h
// extensions first so generated images are not tied to a CHS geometry.
var defaultMBRBootCode = []byte{
	0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c,
	0xfb, 0xfc, 0xbe, 0x00, 0x7c, 0xbf, 0x00, 0x06, 0xb9, 0x00, 0x01, 0xf3,
	0xa5, 0xea, 0x1e, 0x06, 0x00, 0x00, 0xbe, 0xbe, 0x07, 0xb1, 0x04, 0x80,
	0x3c, 0x80, 0x74, 0x0f, 0x80, 0x3c, 0x00, 0x75, 0x78, 0x83, 0xc6, 0x10,
	0xe2, 0xf1, 0xbe, 0xc3, 0x06, 0xeb, 0x7b, 0x89, 0xf7, 0xb4, 0x41, 0xbb,
	0xaa, 0x55, 0xcd, 0x13, 0x72, 0x45, 0x81, 0xfb, 0x55, 0xaa, 0x75, 0x3f,
	0xf7, 0xc1, 0x01, 0x00, 0x74, 0x39, 0xc6, 0x06, 0x30, 0x07, 0x10, 0xc6,
	0x06, 0x31, 0x07, 0x00, 0xc7, 0x06, 0x32, 0x07, 0x01, 0x00, 0xc7, 0x06,
	0x34, 0x07, 0x00, 0x7c, 0xc7, 0x06, 0x36, 0x07, 0x00, 0x00, 0x8b, 0x45,
	0x08, 0xa3, 0x38, 0x07, 0x8b, 0x45, 0x0a, 0xa3, 0x3a, 0x07, 0x31, 0xc0,
	0xa3, 0x3c, 0x07, 0xa3, 0x3e, 0x07, 0xbe, 0x30, 0x07, 0xb4, 0x42, 0xcd,
	0x13, 0x73, 0x0f, 0x8b, 0x15, 0x8b, 0x4d, 0x02, 0xbb, 0x00, 0x7c, 0xb8,
	0x01, 0x02, 0xcd, 0x13, 0x72, 0x14, 0x81, 0x3e, 0xfe, 0x7d, 0x55, 0xaa,
	0x75, 0x11, 0x89, 0xfe, 0xea, 0x00, 0x7c, 0x00, 0x00, 0xbe, 0xd9, 0x06,
	0xeb, 0x08, 0xbe, 0xf3, 0x06, 0xeb, 0x03, 0xbe, 0x14, 0x07, 0xac, 0x84,
	0xc0, 0x74, 0x09, 0xb4, 0x0e, 0xbb, 0x07, 0x00, 0xcd, 0x10, 0xeb, 0xf2,
	0xf4, 0xeb, 0xfd, 0x4e, 0x6f, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65,
	0x20, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x0d, 0x0a,
	0x00, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72,
	0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65,
	0x0d, 0x0a, 0x00, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x6c, 0x6f, 0x61,
	0x64, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6e, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x0d, 0x0a, 0x00,
	0x4d, 0x69, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x0d, 0x0a, 0x00, 0x90,
}

func mbrCHS(lba, totalSectors uint32) (byte, byte, byte) {
	heads, sectors := fsinternal.LegacyBIOSGeometry(totalSectors)
	return encodeMBRCHS(lba, heads, sectors)
}

func mbrCHSForGeometry(lba, totalSectors uint32, geometry *vmm.CHSGeometry) (byte, byte, byte) {
	if geometry == nil {
		return mbrCHS(lba, totalSectors)
	}
	return encodeMBRCHS(lba, uint32(geometry.Heads), uint32(geometry.Sectors))
}

func encodeMBRCHS(lba, heads, sectors uint32) (byte, byte, byte) {
	if lba >= 1024*heads*sectors {
		return 254, 0xff, 0xff
	}
	cylinder := lba / (heads * sectors)
	temp := lba % (heads * sectors)
	head := temp / sectors
	sector := temp%sectors + 1
	return byte(head), byte(sector) | byte((cylinder>>2)&0xc0), byte(cylinder)
}
