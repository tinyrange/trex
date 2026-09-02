package ntfs

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/compression/lznt1"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

type ntfsDataRun struct {
	start  int64
	length int64
	sparse bool
}

type ntfsReadFile struct {
	name                    string
	volume                  starfile.File
	clusterSize             int64
	size                    int64
	firstVCN                int64
	runs                    []ntfsDataRun
	resident                []byte
	streams                 map[string]*ntfsReadFile
	compressionUnitClusters int64
}

func (f *ntfsReadFile) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if offset >= f.size {
		return 0, io.EOF
	}
	wanted := int64(len(buffer))
	if wanted > f.size-offset {
		wanted = f.size - offset
	}
	if f.resident != nil {
		n := copy(buffer[:wanted], f.resident[offset:offset+wanted])
		if int64(len(buffer)) > wanted {
			return n, io.EOF
		}
		return n, nil
	}
	if f.compressionUnitClusters != 0 {
		return f.readCompressedAt(buffer, offset, wanted)
	}
	read := int64(0)
	logical := int64(0)
	requestOffset := offset
	for _, run := range f.runs {
		runBytes := run.length * f.clusterSize
		if requestOffset >= logical+runBytes {
			logical += runBytes
			continue
		}
		within := max(int64(0), requestOffset+read-logical)
		amount := min(wanted-read, runBytes-within)
		if run.sparse {
			clear(buffer[read : read+amount])
		} else {
			n, err := f.volume.ReadAt(buffer[read:read+amount], run.start*f.clusterSize+within)
			read += int64(n)
			if err != nil && !(err == io.EOF && int64(n) == amount) {
				return int(read), err
			}
			logical += runBytes
			if read == wanted {
				break
			}
			continue
		}
		read += amount
		logical += runBytes
		if read == wanted {
			break
		}
	}
	if read != wanted {
		return int(read), io.ErrUnexpectedEOF
	}
	if int64(len(buffer)) > wanted {
		return int(read), io.EOF
	}
	return int(read), nil
}

func (f *ntfsReadFile) readCompressedAt(buffer []byte, offset, wanted int64) (int, error) {
	unitSize := f.compressionUnitClusters * f.clusterSize
	read := int64(0)
	for read < wanted {
		position := offset + read
		unitIndex := position / unitSize
		unit, err := f.readCompressionUnit(unitIndex)
		if err != nil {
			return int(read), err
		}
		within := position % unitSize
		amount := min(wanted-read, int64(len(unit))-within)
		if amount <= 0 {
			return int(read), io.ErrUnexpectedEOF
		}
		copy(buffer[read:read+amount], unit[within:within+amount])
		read += amount
	}
	if int64(len(buffer)) > wanted {
		return int(read), io.EOF
	}
	return int(read), nil
}

func (f *ntfsReadFile) readCompressionUnit(index int64) ([]byte, error) {
	unitClusters := f.compressionUnitClusters
	unitSize := unitClusters * f.clusterSize
	unitStart := index * unitClusters
	expected := min(unitSize, f.size-index*unitSize)
	if expected <= 0 {
		return nil, io.EOF
	}
	encoded := make([]byte, 0, unitSize)
	logicalCluster := int64(0)
	physicalClusters := int64(0)
	sawSparse := false
	for _, run := range f.runs {
		runStart, runEnd := logicalCluster, logicalCluster+run.length
		logicalCluster = runEnd
		overlapStart := max(runStart, unitStart)
		overlapEnd := min(runEnd, unitStart+unitClusters)
		if overlapStart >= overlapEnd {
			continue
		}
		clusters := overlapEnd - overlapStart
		if run.sparse {
			sawSparse = true
			continue
		}
		if sawSparse {
			return nil, fmt.Errorf("ntfs: compressed unit %d has allocated data after sparse padding", index)
		}
		data := make([]byte, clusters*f.clusterSize)
		volumeOffset := (run.start + overlapStart - runStart) * f.clusterSize
		if _, err := starfile.ReadFullAt(f.volume, data, volumeOffset); err != nil {
			return nil, fmt.Errorf("ntfs: read compressed unit %d: %w", index, err)
		}
		encoded = append(encoded, data...)
		physicalClusters += clusters
	}
	if physicalClusters == 0 {
		return make([]byte, expected), nil
	}
	if physicalClusters == unitClusters && !sawSparse {
		return encoded[:expected], nil
	}
	if physicalClusters >= unitClusters || !sawSparse {
		return nil, fmt.Errorf("ntfs: invalid compressed unit %d allocation (%d of %d clusters)", index, physicalClusters, unitClusters)
	}
	decoded, err := lznt1.Decode(encoded, int(expected))
	if err != nil {
		return nil, fmt.Errorf("ntfs: decompress unit %d: %w", index, err)
	}
	return decoded, nil
}

func (f *ntfsReadFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *ntfsReadFile) Size() int64           { return f.size }
func (f *ntfsReadFile) String() string        { return fmt.Sprintf("<ntfs.file %q size=%d>", f.name, f.size) }
func (f *ntfsReadFile) Type() string          { return "file" }
func (f *ntfsReadFile) Freeze()               {}
func (f *ntfsReadFile) Truth() starlark.Bool  { return starlark.True }
func (f *ntfsReadFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *ntfsReadFile) Attr(name string) (starlark.Value, error) {
	if name == "streams" {
		names := make([]string, 0, len(f.streams))
		for name := range f.streams {
			names = append(names, name)
		}
		sort.Strings(names)
		values := starlark.NewDict(len(names))
		for _, name := range names {
			if err := values.SetKey(starlark.String(name), f.streams[name]); err != nil {
				return nil, err
			}
		}
		return values, nil
	}
	if name == "extents" {
		values := make([]starlark.Value, 0, len(f.runs))
		fileOffset := int64(0)
		for _, run := range f.runs {
			length := run.length * f.clusterSize
			if remaining := f.size - fileOffset; length > remaining {
				length = remaining
			}
			fields := starlark.StringDict{
				"file_offset": starlark.MakeInt64(fileOffset),
				"length":      starlark.MakeInt64(length),
				"sparse":      starlark.Bool(run.sparse),
			}
			if !run.sparse {
				fields["volume_offset"] = starlark.MakeInt64(run.start * f.clusterSize)
			}
			values = append(values, starfile.NewRecord(fields))
			fileOffset += run.length * f.clusterSize
			if fileOffset >= f.size {
				break
			}
		}
		return starlark.NewList(values), nil
	}
	return starfile.Attr(f, name), nil
}

func (f *ntfsReadFile) AttrNames() []string {
	return append(starfile.AttrNames(), "extents", "streams")
}

type ntfsReadNode struct {
	id         uint64
	parent     uint64
	name       string
	path       string
	dir        bool
	securityID uint32
	file       *ntfsReadFile
	streams    map[string]*ntfsReadFile
	links      []ntfsReadLink
	children   []*ntfsReadLink
}

type ntfsReadLink struct {
	node      *ntfsReadNode
	parent    uint64
	name      string
	namespace byte
	path      string
}

type ntfsVolume struct {
	file                starfile.File
	clusterSize         int64
	recordSize          int64
	nodes               map[uint64]*ntfsReadNode
	paths               map[string]*ntfsReadNode
	securityDescriptors map[uint32][]byte
	files               *starlark.List
}

func newNTFSVolume(file starfile.File) (*ntfsVolume, error) {
	boot := make([]byte, 512)
	if _, err := file.ReadAt(boot, 0); err != nil {
		return nil, fmt.Errorf("ntfs: read boot sector: %w", err)
	}
	if string(boot[3:11]) != "NTFS    " || boot[510] != 0x55 || boot[511] != 0xaa {
		return nil, fmt.Errorf("ntfs: invalid boot sector")
	}
	sectorSize := int64(binary.LittleEndian.Uint16(boot[11:13]))
	sectorsPerCluster := int64(boot[13])
	if sectorSize < 256 || sectorSize > 4096 || sectorSize&(sectorSize-1) != 0 || sectorsPerCluster <= 0 || sectorsPerCluster&(sectorsPerCluster-1) != 0 {
		return nil, fmt.Errorf("ntfs: invalid sector or cluster size")
	}
	clusterSize := sectorSize * sectorsPerCluster
	recordCode := int8(boot[64])
	var recordSize int64
	if recordCode < 0 {
		recordSize = int64(1) << uint(-recordCode)
	} else {
		recordSize = int64(recordCode) * clusterSize
	}
	if recordSize < sectorSize || recordSize > 64<<10 || recordSize%sectorSize != 0 {
		return nil, fmt.Errorf("ntfs: invalid MFT record size %d", recordSize)
	}
	mftLCN := int64(binary.LittleEndian.Uint64(boot[48:56]))
	bootstrap := make([]byte, recordSize)
	if _, err := file.ReadAt(bootstrap, mftLCN*clusterSize); err != nil {
		return nil, fmt.Errorf("ntfs: read MFT record: %w", err)
	}
	if err := applyNTFSReadFixup(bootstrap, sectorSize, "MFT"); err != nil {
		return nil, err
	}
	attributes, err := parseNTFSReadAttributes(bootstrap, clusterSize)
	if err != nil {
		return nil, fmt.Errorf("ntfs: parse MFT record: %w", err)
	}
	var mft *ntfsReadAttribute
	for i := range attributes {
		if attributes[i].typ == ntfsAttrData && attributes[i].name == "" {
			mft = &attributes[i]
			break
		}
	}
	if mft == nil || !mft.nonresident || mft.size <= 0 {
		return nil, fmt.Errorf("ntfs: MFT data attribute not found")
	}
	mftFile := &ntfsReadFile{name: "$MFT", volume: file, clusterSize: clusterSize, size: mft.size, runs: mft.runs}
	volume := &ntfsVolume{
		file:                file,
		clusterSize:         clusterSize,
		recordSize:          recordSize,
		nodes:               make(map[uint64]*ntfsReadNode),
		paths:               make(map[string]*ntfsReadNode),
		securityDescriptors: make(map[uint32][]byte),
	}
	if err := volume.scanMFT(mftFile, sectorSize); err != nil {
		return nil, err
	}
	return volume, nil
}

type ntfsReadAttribute struct {
	typ             uint32
	name            string
	nonresident     bool
	value           []byte
	runs            []ntfsDataRun
	size            int64
	firstVCN        int64
	flags           uint16
	compressionUnit uint16
}

func applyNTFSReadFixup(data []byte, sectorSize int64, description string) error {
	if len(data) < 8 {
		return fmt.Errorf("ntfs: truncated %s record", description)
	}
	offset := int(binary.LittleEndian.Uint16(data[4:6]))
	count := int(binary.LittleEndian.Uint16(data[6:8]))
	if count < 2 || offset < 8 || offset+count*2 > len(data) || int64(count-1)*sectorSize > int64(len(data)) {
		return fmt.Errorf("ntfs: invalid %s update sequence", description)
	}
	sequence := binary.LittleEndian.Uint16(data[offset : offset+2])
	for index := 1; index < count; index++ {
		end := index * int(sectorSize)
		if end > len(data) || binary.LittleEndian.Uint16(data[end-2:end]) != sequence {
			return fmt.Errorf("ntfs: invalid %s sector fixup", description)
		}
		copy(data[end-2:end], data[offset+index*2:offset+index*2+2])
	}
	return nil
}

func parseNTFSReadAttributes(record []byte, clusterSize int64) ([]ntfsReadAttribute, error) {
	if len(record) < 24 || string(record[:4]) != "FILE" {
		return nil, fmt.Errorf("invalid FILE record")
	}
	offset := int(binary.LittleEndian.Uint16(record[20:22]))
	used := int(binary.LittleEndian.Uint32(record[24:28]))
	if used <= 0 || used > len(record) {
		used = len(record)
	}
	var attributes []ntfsReadAttribute
	for offset+4 <= used {
		typ := binary.LittleEndian.Uint32(record[offset : offset+4])
		if typ == ntfsAttrEnd {
			return attributes, nil
		}
		if offset+8 > used {
			return nil, fmt.Errorf("truncated attribute header at %#x", offset)
		}
		length := int(binary.LittleEndian.Uint32(record[offset+4 : offset+8]))
		if length < 24 || offset+length > used {
			return nil, fmt.Errorf("invalid attribute at %#x", offset)
		}
		raw := record[offset : offset+length]
		nameLength := int(raw[9])
		nameOffset := int(binary.LittleEndian.Uint16(raw[10:12]))
		name, err := decodeNTFSReadName(raw, nameOffset, nameLength)
		if err != nil {
			return nil, err
		}
		attribute := ntfsReadAttribute{typ: typ, name: name, nonresident: raw[8] != 0, flags: binary.LittleEndian.Uint16(raw[12:14])}
		if !attribute.nonresident {
			valueLength := int(binary.LittleEndian.Uint32(raw[16:20]))
			valueOffset := int(binary.LittleEndian.Uint16(raw[20:22]))
			if valueOffset < 0 || valueLength < 0 || valueOffset+valueLength > len(raw) {
				return nil, fmt.Errorf("invalid resident attribute value")
			}
			attribute.value = append([]byte(nil), raw[valueOffset:valueOffset+valueLength]...)
			attribute.size = int64(valueLength)
		} else {
			if len(raw) < 64 {
				return nil, fmt.Errorf("truncated nonresident attribute")
			}
			runOffset := int(binary.LittleEndian.Uint16(raw[32:34]))
			if runOffset < 0 || runOffset >= len(raw) {
				return nil, fmt.Errorf("invalid data-run offset")
			}
			firstVCN := binary.LittleEndian.Uint64(raw[16:24])
			if firstVCN > 1<<63-1 {
				return nil, fmt.Errorf("invalid nonresident starting VCN")
			}
			attribute.firstVCN = int64(firstVCN)
			attribute.size = int64(binary.LittleEndian.Uint64(raw[48:56]))
			attribute.compressionUnit = binary.LittleEndian.Uint16(raw[34:36])
			if attribute.flags&0x0001 != 0 && (attribute.compressionUnit == 0 || attribute.compressionUnit > 16) {
				return nil, fmt.Errorf("invalid NTFS compression-unit shift %d", attribute.compressionUnit)
			}
			attribute.runs, err = decodeNTFSDataRuns(raw[runOffset:], clusterSize)
			if err != nil {
				return nil, err
			}
		}
		attributes = append(attributes, attribute)
		offset += length
	}
	return nil, fmt.Errorf("attribute list is not terminated")
}

func decodeNTFSReadName(raw []byte, offset, units int) (string, error) {
	if units == 0 {
		return "", nil
	}
	if offset < 0 || units < 0 || offset+units*2 > len(raw) {
		return "", fmt.Errorf("invalid UTF-16 attribute name")
	}
	value := make([]uint16, units)
	for i := range value {
		value[i] = binary.LittleEndian.Uint16(raw[offset+i*2 : offset+i*2+2])
	}
	return string(utf16.Decode(value)), nil
}

func decodeNTFSDataRuns(raw []byte, clusterSize int64) ([]ntfsDataRun, error) {
	var runs []ntfsDataRun
	currentLCN := int64(0)
	for offset := 0; ; {
		if offset >= len(raw) {
			return nil, fmt.Errorf("unterminated data runs")
		}
		header := raw[offset]
		offset++
		if header == 0 {
			return runs, nil
		}
		lengthBytes, offsetBytes := int(header&0x0f), int(header>>4)
		if lengthBytes == 0 || lengthBytes > 8 || offsetBytes > 8 || offset+lengthBytes+offsetBytes > len(raw) {
			return nil, fmt.Errorf("invalid data run header %#x", header)
		}
		length := int64(readNTFSUnsigned(raw[offset : offset+lengthBytes]))
		offset += lengthBytes
		if length <= 0 || length > (1<<63-1)/clusterSize {
			return nil, fmt.Errorf("invalid data run length")
		}
		run := ntfsDataRun{length: length, sparse: offsetBytes == 0}
		if offsetBytes != 0 {
			delta := readNTFSSigned(raw[offset : offset+offsetBytes])
			offset += offsetBytes
			if (delta > 0 && currentLCN > 1<<63-1-delta) || (delta < 0 && currentLCN < -delta) {
				return nil, fmt.Errorf("data run LCN overflow")
			}
			currentLCN += delta
			if currentLCN < 0 {
				return nil, fmt.Errorf("negative data run LCN")
			}
			run.start = currentLCN
		}
		runs = append(runs, run)
	}
}

func readNTFSUnsigned(raw []byte) uint64 {
	var value uint64
	for index := len(raw) - 1; index >= 0; index-- {
		value = value<<8 | uint64(raw[index])
	}
	return value
}

func readNTFSSigned(raw []byte) int64 {
	value := readNTFSUnsigned(raw)
	bits := uint(len(raw) * 8)
	if bits < 64 && value&(uint64(1)<<(bits-1)) != 0 {
		value |= ^uint64(0) << bits
	}
	return int64(value)
}

func (v *ntfsVolume) scanMFT(mft starfile.File, sectorSize int64) error {
	count := mft.Size() / v.recordSize
	extensions := make(map[uint64][]*ntfsReadNode)
	for id := int64(0); id < count; id++ {
		record := make([]byte, v.recordSize)
		if _, err := mft.ReadAt(record, id*v.recordSize); err != nil && err != io.EOF {
			return fmt.Errorf("ntfs: read MFT record %d: %w", id, err)
		}
		if string(record[:4]) != "FILE" {
			continue
		}
		if err := applyNTFSReadFixup(record, sectorSize, fmt.Sprintf("MFT record %d", id)); err != nil {
			continue
		}
		if binary.LittleEndian.Uint16(record[22:24])&ntfsFileInUse == 0 {
			continue
		}
		attributes, err := parseNTFSReadAttributes(record, v.clusterSize)
		if err != nil {
			continue
		}
		node := &ntfsReadNode{id: uint64(id), dir: binary.LittleEndian.Uint16(record[22:24])&ntfsFileDir != 0}
		for _, attribute := range attributes {
			switch attribute.typ {
			case ntfsAttrStandardInformation:
				// NTFS 3.0 and later store the $Secure descriptor ID at
				// offset 52 in the extended $STANDARD_INFORMATION value.
				if len(attribute.value) >= 56 {
					node.securityID = binary.LittleEndian.Uint32(attribute.value[52:56])
				}
			case ntfsAttrFileName:
				if len(attribute.value) < 66 {
					continue
				}
				namespace := attribute.value[65]
				units := int(attribute.value[64])
				name, err := decodeNTFSReadName(attribute.value, 66, units)
				if err != nil {
					continue
				}
				parent := binary.LittleEndian.Uint64(attribute.value[:8]) & 0x0000ffffffffffff
				replaced := false
				for index := range node.links {
					if node.links[index].parent != parent {
						continue
					}
					if ntfsReadNamespaceRank(namespace) > ntfsReadNamespaceRank(node.links[index].namespace) {
						node.links[index] = ntfsReadLink{node: node, parent: parent, name: name, namespace: namespace}
					}
					replaced = true
					break
				}
				if !replaced {
					node.links = append(node.links, ntfsReadLink{node: node, parent: parent, name: name, namespace: namespace})
				}
			case ntfsAttrData:
				file := &ntfsReadFile{name: node.name, volume: v.file, clusterSize: v.clusterSize, size: attribute.size, firstVCN: attribute.firstVCN, resident: attribute.value, runs: attribute.runs}
				if attribute.flags&0x0001 != 0 {
					file.compressionUnitClusters = int64(1) << attribute.compressionUnit
				}
				if attribute.name == "" {
					node.file, err = mergeNTFSReadFileExtents(node.file, file)
					if err != nil {
						return fmt.Errorf("ntfs: merge data extents for record %d: %w", id, err)
					}
				} else {
					if node.streams == nil {
						node.streams = make(map[string]*ntfsReadFile)
					}
					node.streams[attribute.name], err = mergeNTFSReadFileExtents(node.streams[attribute.name], file)
					if err != nil {
						return fmt.Errorf("ntfs: merge %s extents for record %d: %w", attribute.name, id, err)
					}
				}
			}
		}
		if id == 5 {
			node.name, node.parent = "", 5
			node.links = nil
		} else if len(node.links) > 0 {
			node.name, node.parent = node.links[0].name, node.links[0].parent
		}
		base := binary.LittleEndian.Uint64(record[32:40]) & 0x0000ffffffffffff
		if base != 0 {
			extensions[base] = append(extensions[base], node)
			continue
		}
		v.nodes[uint64(id)] = node
	}
	for baseID, records := range extensions {
		base := v.nodes[baseID]
		if base == nil {
			continue
		}
		for _, extension := range records {
			for _, link := range extension.links {
				link.node = base
				mergeNTFSReadLink(base, link)
			}
			if extension.file != nil {
				var err error
				base.file, err = mergeNTFSReadFileExtents(base.file, extension.file)
				if err != nil {
					return fmt.Errorf("ntfs: merge extension record for %d: %w", baseID, err)
				}
			}
			if len(extension.streams) != 0 {
				if base.streams == nil {
					base.streams = make(map[string]*ntfsReadFile)
				}
				for name, stream := range extension.streams {
					var err error
					base.streams[name], err = mergeNTFSReadFileExtents(base.streams[name], stream)
					if err != nil {
						return fmt.Errorf("ntfs: merge extension stream %s for %d: %w", name, baseID, err)
					}
				}
			}
		}
	}
	if secure := v.nodes[9]; secure != nil {
		if stream := secure.streams["$SDS"]; stream != nil {
			if err := v.readSecurityDescriptors(stream); err != nil {
				return fmt.Errorf("ntfs: read $Secure:$SDS: %w", err)
			}
		}
	}
	root := v.nodes[5]
	if root == nil {
		return fmt.Errorf("ntfs: root MFT record not found")
	}
	root.path = "/"
	v.paths["/"] = root
	var paths []string
	for progress := true; progress; {
		progress = false
		for _, node := range v.nodes {
			for index := range node.links {
				link := &node.links[index]
				if link.path != "" {
					continue
				}
				parent := v.nodes[link.parent]
				if parent == nil || parent.path == "" || parent == node {
					continue
				}
				link.path = path.Join(parent.path, link.name)
				v.paths[strings.ToLower(link.path)] = node
				paths = append(paths, link.path)
				parent.children = append(parent.children, link)
				if node.path == "" {
					node.path = link.path
				}
				if node.file != nil && node.file.name == "" {
					node.file.name = link.path
				}
				if node.file != nil {
					node.file.streams = node.streams
					for name, stream := range node.streams {
						stream.name = link.path + ":" + name
					}
				}
				progress = true
			}
		}
	}
	sort.Strings(paths)
	values := make([]starlark.Value, len(paths))
	for i, name := range paths {
		values[i] = starlark.String(name)
	}
	v.files = starlark.NewList(values)
	return nil
}

func mergeNTFSReadFileExtents(existing, added *ntfsReadFile) (*ntfsReadFile, error) {
	if existing == nil {
		return added, nil
	}
	if added == nil {
		return existing, nil
	}
	if existing.resident != nil || added.resident != nil {
		return nil, fmt.Errorf("resident data has multiple extents")
	}
	if existing.clusterSize != added.clusterSize || existing.volume != added.volume || existing.compressionUnitClusters != added.compressionUnitClusters {
		return nil, fmt.Errorf("incompatible nonresident extents")
	}
	existingClusters := ntfsReadRunClusters(existing.runs)
	addedClusters := ntfsReadRunClusters(added.runs)
	existingEnd := existing.firstVCN + existingClusters
	addedEnd := added.firstVCN + addedClusters
	combined := existing
	switch {
	case added.firstVCN >= existingEnd:
		if gap := added.firstVCN - existingEnd; gap != 0 {
			combined.runs = append(combined.runs, ntfsDataRun{length: gap, sparse: true})
		}
		combined.runs = append(combined.runs, added.runs...)
	case existing.firstVCN >= addedEnd:
		runs := append([]ntfsDataRun(nil), added.runs...)
		if gap := existing.firstVCN - addedEnd; gap != 0 {
			runs = append(runs, ntfsDataRun{length: gap, sparse: true})
		}
		combined.runs = append(runs, existing.runs...)
		combined.firstVCN = added.firstVCN
	default:
		return nil, fmt.Errorf("overlapping VCN ranges %#x-%#x and %#x-%#x", existing.firstVCN, existingEnd, added.firstVCN, addedEnd)
	}
	if added.size > combined.size {
		combined.size = added.size
	}
	return combined, nil
}

func ntfsReadRunClusters(runs []ntfsDataRun) int64 {
	var clusters int64
	for _, run := range runs {
		clusters += run.length
	}
	return clusters
}

func (v *ntfsVolume) readSecurityDescriptors(stream *ntfsReadFile) error {
	const headerSize = int64(20)
	for pairBase := int64(0); pairBase < stream.Size(); pairBase += 2 * ntfsSecureMirrorBase {
		segmentEnd := min(pairBase+ntfsSecureMirrorBase, stream.Size())
		for offset := pairBase; offset+headerSize <= segmentEnd; {
			header := make([]byte, headerSize)
			if _, err := starfile.ReadFullAt(stream, header, offset); err != nil {
				return err
			}
			if bytesAllZero(header) {
				break
			}
			securityID := binary.LittleEndian.Uint32(header[4:8])
			storedOffset := binary.LittleEndian.Uint64(header[8:16])
			entryLength := int64(binary.LittleEndian.Uint32(header[16:20]))
			if storedOffset != uint64(offset) || securityID == 0 || entryLength < headerSize || offset+entryLength > segmentEnd {
				// Entries are contiguous within each primary segment. Windows
				// does not necessarily clear the remainder when a security-store
				// transaction shortens it, so stale nonzero tail bytes terminate
				// the live sequence just like an all-zero header.
				break
			}
			descriptor := make([]byte, entryLength-headerSize)
			if _, err := starfile.ReadFullAt(stream, descriptor, offset+headerSize); err != nil {
				return err
			}
			if !isSelfRelativeSecurityDescriptor(descriptor) {
				return fmt.Errorf("invalid security descriptor %#x at %#x", securityID, offset)
			}
			v.securityDescriptors[securityID] = descriptor
			offset += (entryLength + 15) &^ 15
		}
	}
	return nil
}

func bytesAllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func isSelfRelativeSecurityDescriptor(descriptor []byte) bool {
	return len(descriptor) >= 20 && descriptor[0] == 1 && binary.LittleEndian.Uint16(descriptor[2:4])&0x8000 != 0
}

func mergeNTFSReadLink(node *ntfsReadNode, link ntfsReadLink) {
	for index := range node.links {
		if node.links[index].parent != link.parent {
			continue
		}
		if ntfsReadNamespaceRank(link.namespace) > ntfsReadNamespaceRank(node.links[index].namespace) {
			node.links[index] = link
		}
		return
	}
	node.links = append(node.links, link)
}

func ntfsReadNamespaceRank(namespace byte) int {
	switch namespace {
	case 3:
		return 3
	case 1:
		return 2
	case 0:
		return 1
	default:
		return 0
	}
}

func (v *ntfsVolume) String() string        { return fmt.Sprintf("<ntfs files=%d>", v.files.Len()) }
func (v *ntfsVolume) Type() string          { return "ntfs" }
func (v *ntfsVolume) Freeze()               {}
func (v *ntfsVolume) Truth() starlark.Bool  { return starlark.True }
func (v *ntfsVolume) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *ntfsVolume) AttrNames() []string   { return []string{"files", "find", "metadata"} }
func (v *ntfsVolume) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		return v.files, nil
	case "find":
		return starlark.NewBuiltin("find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, found, err := v.Get(starlark.String(name))
			if err != nil || !found {
				return starlark.None, err
			}
			return value, nil
		}), nil
	case "metadata":
		return starlark.NewBuiltin("metadata", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("metadata", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			node := v.lookup(name)
			if node == nil {
				return starlark.None, nil
			}
			descriptor := starlark.Value(starlark.None)
			if raw, ok := v.securityDescriptors[node.securityID]; ok {
				descriptor = starlark.Bytes(raw)
			}
			return starfile.NewRecord(starlark.StringDict{
				"directory":           starlark.Bool(node.dir),
				"path":                starlark.String(node.path),
				"security_descriptor": descriptor,
				"security_id":         starlark.MakeUint64(uint64(node.securityID)),
			}), nil
		}), nil
	}
	return nil, nil
}

func (v *ntfsVolume) lookup(name string) *ntfsReadNode {
	return v.paths[strings.ToLower(path.Clean("/"+strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/")))]
}

func (v *ntfsVolume) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	node := v.lookup(name)
	if node == nil {
		return nil, false, nil
	}
	if node.file != nil && !node.dir {
		return node.file, true, nil
	}
	children := append([]*ntfsReadLink(nil), node.children...)
	sort.Slice(children, func(i, j int) bool { return strings.ToLower(children[i].name) < strings.ToLower(children[j].name) })
	values := make([]starlark.Value, len(children))
	for i, child := range children {
		values[i] = starlark.String(child.path)
	}
	return starfile.NewRecord(starlark.StringDict{"files": starlark.NewList(values), "path": starlark.String(node.path)}), true, nil
}

var _ starlark.Mapping = (*ntfsVolume)(nil)
var _ starfile.File = (*ntfsReadFile)(nil)
