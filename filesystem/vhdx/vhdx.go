package vhdx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	vhdxMiB                 = int64(1 << 20)
	vhdxHeaderSize          = 4096
	vhdxRegionTableSize     = 64 << 10
	vhdxMetadataTableSize   = 64 << 10
	vhdxPayloadFullyPresent = 6
)

var (
	vhdxBATRegionGUID       = mustVHDXGUID("{2DC27766-F623-4200-9D64-115E9BFD4A08}")
	vhdxMetadataRegionGUID  = mustVHDXGUID("{8B7CA206-4790-4B9A-B8FE-575F050F886E}")
	vhdxFileParametersGUID  = mustVHDXGUID("{CAA16737-FA36-4D43-B3B6-33F0AA44E76B}")
	vhdxVirtualDiskSizeGUID = mustVHDXGUID("{2FA54224-CD1B-4876-B211-5DBED83BF4B8}")
	vhdxLogicalSectorGUID   = mustVHDXGUID("{8141BF1D-A96F-4709-BA47-F233A8FAAB5F}")
	vhdxPhysicalSectorGUID  = mustVHDXGUID("{CDA348C7-445D-4471-9CC9-E9885251C556}")
	vhdxVirtualDiskIDGUID   = mustVHDXGUID("{BECA12AB-B2E6-4523-93EF-C309E000C746}")
)

type vhdxRegion struct {
	offset int64
	length int64
}

type vhdxMetadataEntry struct {
	offset int64
	length int64
	flags  uint32
}

type vhdxImage struct {
	file          starfile.File
	size          int64
	blockSize     int64
	logicalSector int64
	chunkRatio    int64
	bat           []byte
}

func mustVHDXGUID(value string) [16]byte {
	guid, ok := fsinternal.ParseGUID(value)
	if !ok {
		panic("invalid VHDX GUID constant: " + value)
	}
	return guid
}

func VHDXBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("vhdx", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("vhdx: got %s, want file", value.Type())
	}
	return newVHDXImage(file)
}

func newVHDXImage(file starfile.File) (*vhdxImage, error) {
	identifier, err := readVHDXAt(file, 0, 8)
	if err != nil {
		return nil, fmt.Errorf("vhdx: read identifier: %w", err)
	}
	if string(identifier) != "vhdxfile" {
		return nil, fmt.Errorf("vhdx: invalid file identifier")
	}
	header, err := currentVHDXHeader(file)
	if err != nil {
		return nil, err
	}
	if !zeroBytes(header[48:64]) {
		return nil, fmt.Errorf("vhdx: active log replay is not supported")
	}

	regions, err := readVHDXRegions(file)
	if err != nil {
		return nil, err
	}
	batRegion, ok := regions[vhdxBATRegionGUID]
	if !ok {
		return nil, fmt.Errorf("vhdx: BAT region is missing")
	}
	metadataRegion, ok := regions[vhdxMetadataRegionGUID]
	if !ok {
		return nil, fmt.Errorf("vhdx: metadata region is missing")
	}
	metadata, err := readVHDXMetadata(file, metadataRegion)
	if err != nil {
		return nil, err
	}
	parameters, err := readRequiredVHDXMetadata(file, metadataRegion, metadata, vhdxFileParametersGUID, 8, "file parameters")
	if err != nil {
		return nil, err
	}
	blockSize := int64(binary.LittleEndian.Uint32(parameters[0:4]))
	parameterFlags := binary.LittleEndian.Uint32(parameters[4:8])
	if parameterFlags&2 != 0 {
		return nil, fmt.Errorf("vhdx: differencing disks are not supported")
	}
	if blockSize < vhdxMiB || blockSize > 256*vhdxMiB || blockSize&(blockSize-1) != 0 {
		return nil, fmt.Errorf("vhdx: invalid payload block size %d", blockSize)
	}
	sizeData, err := readRequiredVHDXMetadata(file, metadataRegion, metadata, vhdxVirtualDiskSizeGUID, 8, "virtual disk size")
	if err != nil {
		return nil, err
	}
	size := int64(binary.LittleEndian.Uint64(sizeData))
	sectorData, err := readRequiredVHDXMetadata(file, metadataRegion, metadata, vhdxLogicalSectorGUID, 4, "logical sector size")
	if err != nil {
		return nil, err
	}
	logicalSector := int64(binary.LittleEndian.Uint32(sectorData))
	if logicalSector != 512 && logicalSector != 4096 {
		return nil, fmt.Errorf("vhdx: unsupported logical sector size %d", logicalSector)
	}
	if size <= 0 || size%logicalSector != 0 {
		return nil, fmt.Errorf("vhdx: invalid virtual disk size %d", size)
	}
	chunkRatio := ((int64(1) << 23) * logicalSector) / blockSize
	if chunkRatio <= 0 {
		return nil, fmt.Errorf("vhdx: invalid chunk ratio")
	}
	payloadBlocks := fsinternal.CeilDiv(size, blockSize)
	lastBATIndex := payloadBlocks - 1 + (payloadBlocks-1)/chunkRatio
	if (lastBATIndex+1)*8 > batRegion.length {
		return nil, fmt.Errorf("vhdx: BAT is too small for virtual disk")
	}
	bat, err := readVHDXAt(file, batRegion.offset, batRegion.length)
	if err != nil {
		return nil, fmt.Errorf("vhdx: read BAT: %w", err)
	}
	return &vhdxImage{
		file: file, size: size, blockSize: blockSize,
		logicalSector: logicalSector, chunkRatio: chunkRatio, bat: bat,
	}, nil
}

func currentVHDXHeader(file starfile.File) ([]byte, error) {
	type candidate struct {
		data     []byte
		sequence uint64
	}
	var valid []candidate
	for _, offset := range []int64{64 << 10, 128 << 10} {
		data, err := readVHDXAt(file, offset, vhdxHeaderSize)
		if err != nil || string(data[0:4]) != "head" || !validVHDXChecksum(data, 4) {
			continue
		}
		if binary.LittleEndian.Uint16(data[66:68]) != 1 {
			continue
		}
		valid = append(valid, candidate{data: data, sequence: binary.LittleEndian.Uint64(data[8:16])})
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("vhdx: no valid header")
	}
	current := valid[0]
	for _, item := range valid[1:] {
		if item.sequence > current.sequence {
			current = item
		}
	}
	return current.data, nil
}

func readVHDXRegions(file starfile.File) (map[[16]byte]vhdxRegion, error) {
	var table []byte
	for _, offset := range []int64{192 << 10, 256 << 10} {
		candidate, err := readVHDXAt(file, offset, vhdxRegionTableSize)
		if err == nil && string(candidate[0:4]) == "regi" && validVHDXChecksum(candidate, 4) {
			table = candidate
			break
		}
	}
	if table == nil {
		return nil, fmt.Errorf("vhdx: no valid region table")
	}
	count := int(binary.LittleEndian.Uint32(table[8:12]))
	if count > 2047 || 16+count*32 > len(table) {
		return nil, fmt.Errorf("vhdx: invalid region count %d", count)
	}
	regions := make(map[[16]byte]vhdxRegion, count)
	for index := 0; index < count; index++ {
		entry := table[16+index*32 : 16+(index+1)*32]
		var guid [16]byte
		copy(guid[:], entry[0:16])
		region := vhdxRegion{
			offset: int64(binary.LittleEndian.Uint64(entry[16:24])),
			length: int64(binary.LittleEndian.Uint32(entry[24:28])),
		}
		required := binary.LittleEndian.Uint32(entry[28:32]) == 1
		if region.offset < vhdxMiB || region.offset%vhdxMiB != 0 || region.length <= 0 || region.length%vhdxMiB != 0 || region.offset+region.length > file.Size() {
			return nil, fmt.Errorf("vhdx: invalid region bounds")
		}
		if required && guid != vhdxBATRegionGUID && guid != vhdxMetadataRegionGUID {
			return nil, fmt.Errorf("vhdx: unknown required region %s", fsinternal.FormatGUID(guid))
		}
		if _, exists := regions[guid]; exists {
			return nil, fmt.Errorf("vhdx: duplicate region %s", fsinternal.FormatGUID(guid))
		}
		regions[guid] = region
	}
	return regions, nil
}

func readVHDXMetadata(file starfile.File, region vhdxRegion) (map[[16]byte]vhdxMetadataEntry, error) {
	table, err := readVHDXAt(file, region.offset, vhdxMetadataTableSize)
	if err != nil {
		return nil, fmt.Errorf("vhdx: read metadata table: %w", err)
	}
	if string(table[0:8]) != "metadata" {
		return nil, fmt.Errorf("vhdx: invalid metadata signature")
	}
	count := int(binary.LittleEndian.Uint16(table[10:12]))
	if count > 2047 || 32+count*32 > len(table) {
		return nil, fmt.Errorf("vhdx: invalid metadata count %d", count)
	}
	known := map[[16]byte]bool{
		vhdxFileParametersGUID: true, vhdxVirtualDiskSizeGUID: true,
		vhdxLogicalSectorGUID: true, vhdxPhysicalSectorGUID: true,
		vhdxVirtualDiskIDGUID: true,
	}
	metadata := make(map[[16]byte]vhdxMetadataEntry, count)
	for index := 0; index < count; index++ {
		item := table[32+index*32 : 32+(index+1)*32]
		var guid [16]byte
		copy(guid[:], item[0:16])
		entry := vhdxMetadataEntry{
			offset: int64(binary.LittleEndian.Uint32(item[16:20])),
			length: int64(binary.LittleEndian.Uint32(item[20:24])),
			flags:  binary.LittleEndian.Uint32(item[24:28]),
		}
		if entry.length < 0 || entry.offset < vhdxMetadataTableSize || entry.offset+entry.length > region.length {
			return nil, fmt.Errorf("vhdx: invalid metadata item bounds")
		}
		if entry.flags&4 != 0 && !known[guid] {
			return nil, fmt.Errorf("vhdx: unknown required metadata %s", fsinternal.FormatGUID(guid))
		}
		if _, exists := metadata[guid]; exists {
			return nil, fmt.Errorf("vhdx: duplicate metadata %s", fsinternal.FormatGUID(guid))
		}
		metadata[guid] = entry
	}
	return metadata, nil
}

func readRequiredVHDXMetadata(file starfile.File, region vhdxRegion, metadata map[[16]byte]vhdxMetadataEntry, guid [16]byte, size int64, name string) ([]byte, error) {
	entry, ok := metadata[guid]
	if !ok {
		return nil, fmt.Errorf("vhdx: %s metadata is missing", name)
	}
	if entry.length != size {
		return nil, fmt.Errorf("vhdx: invalid %s metadata length %d", name, entry.length)
	}
	data, err := readVHDXAt(file, region.offset+entry.offset, entry.length)
	if err != nil {
		return nil, fmt.Errorf("vhdx: read %s metadata: %w", name, err)
	}
	return data, nil
}

func validVHDXChecksum(data []byte, checksumOffset int) bool {
	want := binary.LittleEndian.Uint32(data[checksumOffset : checksumOffset+4])
	copyData := append([]byte(nil), data...)
	clear(copyData[checksumOffset : checksumOffset+4])
	return crc32.Checksum(copyData, crc32.MakeTable(crc32.Castagnoli)) == want
}

func readVHDXAt(file starfile.File, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 || offset > file.Size() || size > file.Size()-offset || size > int64(int(^uint(0)>>1)) {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, int(size))
	_, err := io.ReadFull(io.NewSectionReader(file, offset, size), data)
	return data, err
}

func zeroBytes(data []byte) bool { return bytes.Equal(data, make([]byte, len(data))) }

func (v *vhdxImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("vhdx: negative read offset")
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > v.size-off {
		want = int(v.size - off)
	}
	done := 0
	for done < want {
		virtual := off + int64(done)
		blockIndex := virtual / v.blockSize
		within := virtual % v.blockSize
		count := int64(want - done)
		if available := v.blockSize - within; count > available {
			count = available
		}
		batIndex := blockIndex + blockIndex/v.chunkRatio
		entry := binary.LittleEndian.Uint64(v.bat[batIndex*8 : batIndex*8+8])
		state := entry & 7
		switch state {
		case 0, 1, 2, 3:
			clear(p[done : done+int(count)])
		case vhdxPayloadFullyPresent:
			physical := int64(entry>>20)*vhdxMiB + within
			if physical < 0 || physical+count > v.file.Size() {
				return done, fmt.Errorf("vhdx: payload block %d is outside file", blockIndex)
			}
			if _, err := io.ReadFull(io.NewSectionReader(v.file, physical, count), p[done:done+int(count)]); err != nil {
				return done, err
			}
		default:
			return done, fmt.Errorf("vhdx: unsupported payload block state %d", state)
		}
		done += int(count)
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}

func (v *vhdxImage) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("vhdx virtual disk is read-only")
}
func (v *vhdxImage) Size() int64          { return v.size }
func (v *vhdxImage) String() string       { return fmt.Sprintf("<vhdx size=%d>", v.size) }
func (v *vhdxImage) Type() string         { return "file" }
func (v *vhdxImage) Freeze()              {}
func (v *vhdxImage) Truth() starlark.Bool { return starlark.True }
func (v *vhdxImage) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}
func (v *vhdxImage) Attr(name string) (starlark.Value, error) { return starfile.Attr(v, name), nil }
func (v *vhdxImage) AttrNames() []string                      { return starfile.AttrNames() }
