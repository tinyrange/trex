package sevenzip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sync"
	"unicode/utf16"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	sevenZipDefaultMaximumEntries    = 1_000_000
	sevenZipDefaultMaximumMetadata   = int64(64 << 20)
	sevenZipDefaultMaximumDictionary = uint64(256 << 20)
)

var sevenZipSignature = []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}

const (
	sevenZipEnd               = 0x00
	sevenZipHeader            = 0x01
	sevenZipArchiveProperties = 0x02
	sevenZipAdditionalStreams = 0x03
	sevenZipMainStreams       = 0x04
	sevenZipFilesInfo         = 0x05
	sevenZipPackInfo          = 0x06
	sevenZipUnpackInfo        = 0x07
	sevenZipSubStreamsInfo    = 0x08
	sevenZipSize              = 0x09
	sevenZipCRC               = 0x0a
	sevenZipFolderID          = 0x0b
	sevenZipCodersUnpackSize  = 0x0c
	sevenZipNumUnpackStream   = 0x0d
	sevenZipEmptyStream       = 0x0e
	sevenZipEmptyFile         = 0x0f
	sevenZipAnti              = 0x10
	sevenZipName              = 0x11
	sevenZipCreationTime      = 0x12
	sevenZipAccessTime        = 0x13
	sevenZipModifiedTime      = 0x14
	sevenZipWinAttributes     = 0x15
	sevenZipComment           = 0x16
	sevenZipEncodedHeader     = 0x17
	sevenZipStartPosition     = 0x18
	sevenZipDummy             = 0x19
)

type sevenZipDigest struct {
	defined bool
	value   uint32
}

type sevenZipCoder struct {
	method     []byte
	properties []byte
	inputs     uint64
	outputs    uint64
}

type sevenZipBindPair struct {
	input  uint64
	output uint64
}

type sevenZipSubstream struct {
	size uint64
	crc  sevenZipDigest
}

type sevenZipFolder struct {
	coders        []sevenZipCoder
	bindPairs     []sevenZipBindPair
	packedIndices []uint64
	unpackSizes   []uint64
	crc           sevenZipDigest
	substreams    []sevenZipSubstream
}

func (f *sevenZipFolder) unpackSize() (uint64, error) {
	if len(f.unpackSizes) == 0 {
		return 0, fmt.Errorf("7z: folder has no unpack sizes")
	}
	bound := make(map[uint64]bool, len(f.bindPairs))
	for _, pair := range f.bindPairs {
		bound[pair.output] = true
	}
	for index, size := range f.unpackSizes {
		if !bound[uint64(index)] {
			return size, nil
		}
	}
	return 0, fmt.Errorf("7z: folder has no terminal output stream")
}

type sevenZipStreams struct {
	packPosition uint64
	packSizes    []uint64
	packCRCs     []sevenZipDigest
	folders      []sevenZipFolder
}

type sevenZipReader struct {
	data []byte
	off  int
}

func (r *sevenZipReader) remaining() int { return len(r.data) - r.off }

func (r *sevenZipReader) byte() (byte, error) {
	if r.off >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	value := r.data[r.off]
	r.off++
	return value, nil
}

func (r *sevenZipReader) bytes(size uint64) ([]byte, error) {
	if size > uint64(r.remaining()) {
		return nil, io.ErrUnexpectedEOF
	}
	start := r.off
	r.off += int(size)
	return r.data[start:r.off], nil
}

func (r *sevenZipReader) uint64() (uint64, error) {
	first, err := r.byte()
	if err != nil {
		return 0, err
	}
	mask := byte(0x80)
	var value uint64
	for extra := 0; extra < 8; extra++ {
		if first&mask == 0 {
			value |= uint64(first&byte(mask-1)) << (8 * extra)
			return value, nil
		}
		next, err := r.byte()
		if err != nil {
			return 0, err
		}
		value |= uint64(next) << (8 * extra)
		mask >>= 1
	}
	return value, nil
}

func sevenZipBits(data []byte, count int) ([]bool, error) {
	if count < 0 || (count+7)/8 > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	bits := make([]bool, count)
	for i := range bits {
		bits[i] = data[i/8]&(0x80>>uint(i&7)) != 0
	}
	return bits, nil
}

func (r *sevenZipReader) bitSet(count int) ([]bool, error) {
	data, err := r.bytes(uint64((count + 7) / 8))
	if err != nil {
		return nil, err
	}
	return sevenZipBits(data, count)
}

func (r *sevenZipReader) digests(count int) ([]sevenZipDigest, error) {
	allDefined, err := r.byte()
	if err != nil {
		return nil, err
	}
	defined := make([]bool, count)
	if allDefined != 0 {
		for i := range defined {
			defined[i] = true
		}
	} else {
		defined, err = r.bitSet(count)
		if err != nil {
			return nil, err
		}
	}
	result := make([]sevenZipDigest, count)
	for i, present := range defined {
		result[i].defined = present
		if !present {
			continue
		}
		data, err := r.bytes(4)
		if err != nil {
			return nil, err
		}
		result[i].value = binary.LittleEndian.Uint32(data)
	}
	return result, nil
}

func parseSevenZipFolder(r *sevenZipReader) (sevenZipFolder, error) {
	coderCount, err := r.uint64()
	if err != nil {
		return sevenZipFolder{}, err
	}
	if coderCount == 0 || coderCount > 64 {
		return sevenZipFolder{}, fmt.Errorf("7z: invalid folder coder count %d", coderCount)
	}
	folder := sevenZipFolder{coders: make([]sevenZipCoder, int(coderCount))}
	var totalInputs, totalOutputs uint64
	for i := range folder.coders {
		flags, err := r.byte()
		if err != nil {
			return sevenZipFolder{}, err
		}
		methodSize := int(flags & 0x0f)
		if methodSize == 0 || flags&0xc0 != 0 {
			return sevenZipFolder{}, fmt.Errorf("7z: invalid coder flags %#x", flags)
		}
		method, err := r.bytes(uint64(methodSize))
		if err != nil {
			return sevenZipFolder{}, err
		}
		coder := sevenZipCoder{method: append([]byte(nil), method...), inputs: 1, outputs: 1}
		if flags&0x10 != 0 {
			coder.inputs, err = r.uint64()
			if err != nil {
				return sevenZipFolder{}, err
			}
			coder.outputs, err = r.uint64()
			if err != nil {
				return sevenZipFolder{}, err
			}
		}
		if coder.inputs == 0 || coder.outputs == 0 || totalInputs > math.MaxUint64-coder.inputs || totalOutputs > math.MaxUint64-coder.outputs {
			return sevenZipFolder{}, fmt.Errorf("7z: invalid coder stream counts")
		}
		if flags&0x20 != 0 {
			propertySize, err := r.uint64()
			if err != nil {
				return sevenZipFolder{}, err
			}
			properties, err := r.bytes(propertySize)
			if err != nil {
				return sevenZipFolder{}, err
			}
			coder.properties = append([]byte(nil), properties...)
		}
		totalInputs += coder.inputs
		totalOutputs += coder.outputs
		folder.coders[i] = coder
	}
	if totalOutputs == 0 {
		return sevenZipFolder{}, fmt.Errorf("7z: folder has no output streams")
	}
	bindCount := totalOutputs - 1
	if bindCount > totalInputs {
		return sevenZipFolder{}, fmt.Errorf("7z: folder has more bind pairs than inputs")
	}
	folder.bindPairs = make([]sevenZipBindPair, int(bindCount))
	boundInputs := make(map[uint64]bool, len(folder.bindPairs))
	for i := range folder.bindPairs {
		input, err := r.uint64()
		if err != nil {
			return sevenZipFolder{}, err
		}
		output, err := r.uint64()
		if err != nil {
			return sevenZipFolder{}, err
		}
		if input >= totalInputs || output >= totalOutputs || boundInputs[input] {
			return sevenZipFolder{}, fmt.Errorf("7z: invalid folder bind pair %d -> %d", input, output)
		}
		boundInputs[input] = true
		folder.bindPairs[i] = sevenZipBindPair{input: input, output: output}
	}
	packedCount := totalInputs - bindCount
	if packedCount == 0 || packedCount > totalInputs {
		return sevenZipFolder{}, fmt.Errorf("7z: invalid packed stream count %d", packedCount)
	}
	folder.packedIndices = make([]uint64, int(packedCount))
	if packedCount == 1 {
		for input := uint64(0); input < totalInputs; input++ {
			if !boundInputs[input] {
				folder.packedIndices[0] = input
				break
			}
		}
	} else {
		seen := make(map[uint64]bool, packedCount)
		for i := range folder.packedIndices {
			index, err := r.uint64()
			if err != nil {
				return sevenZipFolder{}, err
			}
			if index >= totalInputs || boundInputs[index] || seen[index] {
				return sevenZipFolder{}, fmt.Errorf("7z: invalid packed stream index %d", index)
			}
			seen[index] = true
			folder.packedIndices[i] = index
		}
	}
	return folder, nil
}

func parseSevenZipPackInfo(r *sevenZipReader, streams *sevenZipStreams) error {
	var err error
	streams.packPosition, err = r.uint64()
	if err != nil {
		return err
	}
	count, err := r.uint64()
	if err != nil {
		return err
	}
	if count > 1_000_000 {
		return fmt.Errorf("7z: packed stream count %d is too large", count)
	}
	for {
		property, err := r.byte()
		if err != nil {
			return err
		}
		switch property {
		case sevenZipEnd:
			if len(streams.packSizes) != int(count) {
				return fmt.Errorf("7z: pack info omitted stream sizes")
			}
			if streams.packCRCs == nil {
				streams.packCRCs = make([]sevenZipDigest, int(count))
			}
			return nil
		case sevenZipSize:
			if streams.packSizes != nil {
				return fmt.Errorf("7z: duplicate packed sizes")
			}
			streams.packSizes = make([]uint64, int(count))
			for i := range streams.packSizes {
				streams.packSizes[i], err = r.uint64()
				if err != nil {
					return err
				}
			}
		case sevenZipCRC:
			if streams.packCRCs != nil {
				return fmt.Errorf("7z: duplicate packed CRCs")
			}
			streams.packCRCs, err = r.digests(int(count))
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("7z: unexpected pack-info property %#x", property)
		}
	}
}

func parseSevenZipUnpackInfo(r *sevenZipReader, streams *sevenZipStreams) error {
	property, err := r.byte()
	if err != nil {
		return err
	}
	if property != sevenZipFolderID {
		return fmt.Errorf("7z: unpack info begins with %#x, want folder", property)
	}
	count, err := r.uint64()
	if err != nil {
		return err
	}
	if count > 1_000_000 {
		return fmt.Errorf("7z: folder count %d is too large", count)
	}
	external, err := r.byte()
	if err != nil {
		return err
	}
	if external != 0 {
		return fmt.Errorf("7z: externally stored folders are not supported")
	}
	streams.folders = make([]sevenZipFolder, int(count))
	for i := range streams.folders {
		streams.folders[i], err = parseSevenZipFolder(r)
		if err != nil {
			return fmt.Errorf("7z: parse folder %d: %w", i, err)
		}
	}
	property, err = r.byte()
	if err != nil {
		return err
	}
	if property != sevenZipCodersUnpackSize {
		return fmt.Errorf("7z: folder info omitted coder unpack sizes")
	}
	for folderIndex := range streams.folders {
		outputs := 0
		for _, coder := range streams.folders[folderIndex].coders {
			if coder.outputs > uint64(math.MaxInt-outputs) {
				return fmt.Errorf("7z: folder output count is too large")
			}
			outputs += int(coder.outputs)
		}
		streams.folders[folderIndex].unpackSizes = make([]uint64, outputs)
		for i := range streams.folders[folderIndex].unpackSizes {
			streams.folders[folderIndex].unpackSizes[i], err = r.uint64()
			if err != nil {
				return err
			}
		}
	}
	property, err = r.byte()
	if err != nil {
		return err
	}
	if property == sevenZipCRC {
		digests, err := r.digests(len(streams.folders))
		if err != nil {
			return err
		}
		for i := range streams.folders {
			streams.folders[i].crc = digests[i]
		}
		property, err = r.byte()
		if err != nil {
			return err
		}
	}
	if property != sevenZipEnd {
		return fmt.Errorf("7z: unexpected unpack-info property %#x", property)
	}
	return nil
}

func initializeSevenZipSubstreams(streams *sevenZipStreams) error {
	for i := range streams.folders {
		size, err := streams.folders[i].unpackSize()
		if err != nil {
			return err
		}
		streams.folders[i].substreams = []sevenZipSubstream{{size: size, crc: streams.folders[i].crc}}
	}
	return nil
}

func parseSevenZipSubstreamsInfo(r *sevenZipReader, streams *sevenZipStreams) error {
	counts := make([]int, len(streams.folders))
	for i := range counts {
		counts[i] = 1
	}
	var explicitSizes []uint64
	var explicitDigests []sevenZipDigest
	for {
		property, err := r.byte()
		if err != nil {
			return err
		}
		switch property {
		case sevenZipEnd:
			for i := range streams.folders {
				folderSize, err := streams.folders[i].unpackSize()
				if err != nil {
					return err
				}
				streams.folders[i].substreams = make([]sevenZipSubstream, counts[i])
				var used uint64
				for j := 0; j+1 < counts[i]; j++ {
					if len(explicitSizes) == 0 {
						return fmt.Errorf("7z: substream sizes are truncated")
					}
					size := explicitSizes[0]
					explicitSizes = explicitSizes[1:]
					if size > folderSize-used {
						return fmt.Errorf("7z: substream sizes exceed folder output")
					}
					streams.folders[i].substreams[j].size = size
					used += size
				}
				if counts[i] != 0 {
					streams.folders[i].substreams[counts[i]-1].size = folderSize - used
				}
			}
			if len(explicitSizes) != 0 {
				return fmt.Errorf("7z: substream size count does not match folders")
			}
			digestIndex := 0
			for i := range streams.folders {
				if counts[i] == 1 && streams.folders[i].crc.defined {
					streams.folders[i].substreams[0].crc = streams.folders[i].crc
					continue
				}
				for j := range streams.folders[i].substreams {
					if digestIndex < len(explicitDigests) {
						streams.folders[i].substreams[j].crc = explicitDigests[digestIndex]
					}
					digestIndex++
				}
			}
			if len(explicitDigests) != 0 && digestIndex != len(explicitDigests) {
				return fmt.Errorf("7z: substream CRC count does not match folders")
			}
			return nil
		case sevenZipNumUnpackStream:
			for i := range counts {
				count, err := r.uint64()
				if err != nil {
					return err
				}
				if count > 1_000_000 || count > uint64(math.MaxInt) {
					return fmt.Errorf("7z: substream count %d is too large", count)
				}
				counts[i] = int(count)
			}
		case sevenZipSize:
			if explicitSizes != nil {
				return fmt.Errorf("7z: duplicate substream sizes")
			}
			count := 0
			for _, value := range counts {
				if value > 0 {
					count += value - 1
				}
			}
			explicitSizes = make([]uint64, count)
			for i := range explicitSizes {
				explicitSizes[i], err = r.uint64()
				if err != nil {
					return err
				}
			}
		case sevenZipCRC:
			if explicitDigests != nil {
				return fmt.Errorf("7z: duplicate substream CRCs")
			}
			count := 0
			for i, value := range counts {
				if value == 1 && streams.folders[i].crc.defined {
					continue
				}
				count += value
			}
			explicitDigests, err = r.digests(count)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("7z: unexpected substreams property %#x", property)
		}
	}
}

func parseSevenZipStreams(r *sevenZipReader) (sevenZipStreams, error) {
	var streams sevenZipStreams
	for {
		property, err := r.byte()
		if err != nil {
			return streams, err
		}
		switch property {
		case sevenZipEnd:
			if len(streams.folders) != 0 && streams.folders[0].substreams == nil {
				if err := initializeSevenZipSubstreams(&streams); err != nil {
					return streams, err
				}
			}
			return streams, nil
		case sevenZipPackInfo:
			if err := parseSevenZipPackInfo(r, &streams); err != nil {
				return streams, err
			}
		case sevenZipUnpackInfo:
			if err := parseSevenZipUnpackInfo(r, &streams); err != nil {
				return streams, err
			}
		case sevenZipSubStreamsInfo:
			if err := parseSevenZipSubstreamsInfo(r, &streams); err != nil {
				return streams, err
			}
		default:
			return streams, fmt.Errorf("7z: unexpected streams property %#x", property)
		}
	}
}

type sevenZipFolderData struct {
	base              storage.Reader
	packedOffset      int64
	packedSize        int64
	unpackSize        int64
	coder             sevenZipCoder
	crc               sevenZipDigest
	maximumDictionary uint64

	mu      sync.Mutex
	reader  io.Reader
	data    []byte
	done    bool
	err     error
	entries []*Entry
}

func sevenZipMethodName(method []byte) string {
	switch {
	case bytes.Equal(method, []byte{0x00}):
		return "copy"
	case bytes.Equal(method, []byte{0x03, 0x01, 0x01}):
		return "lzma"
	default:
		return fmt.Sprintf("%x", method)
	}
}

func (f *sevenZipFolderData) initialize() error {
	if f.reader != nil || f.done || f.err != nil {
		return f.err
	}
	section := io.NewSectionReader(f.base, f.packedOffset, f.packedSize)
	switch sevenZipMethodName(f.coder.method) {
	case "copy":
		if f.packedSize != f.unpackSize {
			return fmt.Errorf("7z: copy folder packed size %d differs from output size %d", f.packedSize, f.unpackSize)
		}
		f.reader = section
	case "lzma":
		reader, err := newLZMAReader(section, f.coder.properties, uint64(f.unpackSize), f.maximumDictionary)
		if err != nil {
			return err
		}
		f.reader = reader
	default:
		return fmt.Errorf("7z: unsupported coder method %x", f.coder.method)
	}
	return nil
}

func (f *sevenZipFolderData) ensureLocked(end int64) error {
	if end < 0 || end > f.unpackSize {
		return fmt.Errorf("7z: folder read end %d is outside unpacked size %d", end, f.unpackSize)
	}
	if int64(len(f.data)) >= end {
		return nil
	}
	if f.err != nil {
		return f.err
	}
	if err := f.initialize(); err != nil {
		f.err = err
		return err
	}
	buffer := make([]byte, 128<<10)
	for int64(len(f.data)) < end {
		need := end - int64(len(f.data))
		if need < int64(len(buffer)) {
			buffer = buffer[:need]
		}
		n, err := f.reader.Read(buffer)
		if n > 0 {
			f.data = append(f.data, buffer[:n]...)
		}
		if err != nil && err != io.EOF {
			f.err = fmt.Errorf("7z: decode folder at output offset %d: %w", len(f.data), err)
			return f.err
		}
		if n == 0 {
			f.err = fmt.Errorf("7z: folder ended at %d bytes, want %d", len(f.data), f.unpackSize)
			return f.err
		}
	}
	if int64(len(f.data)) == f.unpackSize && !f.done {
		f.done = true
		if f.crc.defined {
			actual := crc32.ChecksumIEEE(f.data)
			if actual != f.crc.value {
				f.err = fmt.Errorf("7z: folder CRC is %#08x, want %#08x", actual, f.crc.value)
				return f.err
			}
		}
		for _, entry := range f.entries {
			if err := entry.verifyLocked(); err != nil {
				f.err = err
				return err
			}
		}
	}
	return nil
}

func (f *sevenZipFolderData) all() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ensureLocked(f.unpackSize); err != nil {
		return nil, err
	}
	return f.data, nil
}

type Entry struct {
	archive   *Archive
	name      string
	path      string
	size      int64
	offset    int64
	folder    *sevenZipFolderData
	directory bool
	anti      bool
	crc       sevenZipDigest
	verified  bool
}

func (f *Entry) verifyLocked() error {
	if f.verified || !f.crc.defined || f.folder == nil {
		return nil
	}
	end := f.offset + f.size
	if end > int64(len(f.folder.data)) {
		return nil
	}
	actual := crc32.ChecksumIEEE(f.folder.data[f.offset:end])
	if actual != f.crc.value {
		return fmt.Errorf("7z: entry %q CRC is %#08x, want %#08x", f.name, actual, f.crc.value)
	}
	f.verified = true
	return nil
}

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	if f.directory || f.anti {
		return 0, fmt.Errorf("7z: entry %q has no file data", f.name)
	}
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.size {
		return 0, io.EOF
	}
	requested := len(p)
	if int64(len(p)) > f.size-off {
		p = p[:f.size-off]
	}
	if f.folder == nil {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, fmt.Errorf("7z: entry %q has no folder", f.name)
	}
	f.folder.mu.Lock()
	defer f.folder.mu.Unlock()
	if err := f.folder.ensureLocked(f.offset + off + int64(len(p))); err != nil {
		return 0, err
	}
	if err := f.verifyLocked(); err != nil {
		return 0, err
	}
	n := copy(p, f.folder.data[f.offset+off:f.offset+off+int64(len(p))])
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}

func (f *Entry) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("7z entry %q is read-only", f.name)
}
func (f *Entry) Size() int64 { return f.size }
func (f *Entry) String() string {
	kind := "file"
	if f.directory {
		kind = "directory"
	} else if f.anti {
		kind = "anti"
	}
	return fmt.Sprintf("<sevenzip.%s %q size=%d>", kind, f.path, f.size)
}
func (f *Entry) Type() string          { return "file" }
func (f *Entry) Freeze()               {}
func (f *Entry) Truth() starlark.Bool  { return starlark.True }
func (f *Entry) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *Entry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(f.name), nil
	case "path":
		return starlark.String(f.path), nil
	case "entry_type":
		if f.directory {
			return starlark.String("directory"), nil
		}
		if f.anti {
			return starlark.String("anti"), nil
		}
		return starlark.String("file"), nil
	case "crc32":
		if !f.crc.defined {
			return starlark.None, nil
		}
		return starlark.MakeUint64(uint64(f.crc.value)), nil
	}
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return []string{"binary", "bytes", "crc32", "entry_type", "hex", "name", "path", "read", "size", "slice"}
}

type Archive struct {
	entries []*Entry
	index   map[string][]int
}

func (a *Archive) String() string {
	return fmt.Sprintf("<sevenzip entries=%d>", len(a.entries))
}
func (a *Archive) Type() string          { return "sevenzip" }
func (a *Archive) Freeze()               {}
func (a *Archive) Truth() starlark.Bool  { return starlark.True }
func (a *Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", a.Type()) }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	entry, ok := a.lookup(name, 0)
	return entry, ok, nil
}
func (a *Archive) lookup(name string, occurrence int) (*Entry, bool) {
	indices := a.index[storage.CleanPath(name)]
	if occurrence < 0 || occurrence >= len(indices) {
		return nil, false
	}
	return a.entries[indices[occurrence]], true
}
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "entries":
		values := make([]starlark.Value, len(a.entries))
		for i, entry := range a.entries {
			values[i] = entry
		}
		return starlark.NewList(values), nil
	case "files":
		values := make([]starlark.Value, 0, len(a.entries))
		for _, entry := range a.entries {
			if !entry.directory && !entry.anti {
				values = append(values, starlark.String(entry.path))
			}
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("find", a.findBuiltin), nil
	}
	return nil, nil
}
func (a *Archive) AttrNames() []string { return []string{"entries", "files", "find"} }
func (a *Archive) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	occurrence := 0
	if err := starlark.UnpackArgs("find", args, kwargs, "path", &name, "occurrence?", &occurrence); err != nil {
		return nil, err
	}
	if occurrence < 0 {
		return nil, fmt.Errorf("find: occurrence must be non-negative")
	}
	entry, ok := a.lookup(name, occurrence)
	if !ok {
		return starlark.None, nil
	}
	return entry, nil
}

type sevenZipFileMetadata struct {
	name        string
	emptyStream bool
	emptyFile   bool
	anti        bool
}

func parseSevenZipNames(property *sevenZipReader, files []sevenZipFileMetadata) error {
	external, err := property.byte()
	if err != nil {
		return err
	}
	if external != 0 {
		return fmt.Errorf("7z: externally stored filenames are not supported")
	}
	for i := range files {
		var units []uint16
		for {
			data, err := property.bytes(2)
			if err != nil {
				return fmt.Errorf("7z: unterminated filename %d", i)
			}
			unit := binary.LittleEndian.Uint16(data)
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		files[i].name = string(utf16.Decode(units))
	}
	if property.remaining() != 0 {
		return fmt.Errorf("7z: filename property has %d trailing bytes", property.remaining())
	}
	return nil
}

func parseSevenZipFiles(r *sevenZipReader, maximumEntries int, maximumMetadata int64) ([]sevenZipFileMetadata, error) {
	count, err := r.uint64()
	if err != nil {
		return nil, err
	}
	if count > uint64(maximumEntries) || count > uint64(math.MaxInt) {
		return nil, fmt.Errorf("7z: file count %d exceeds maximum_entries %d", count, maximumEntries)
	}
	files := make([]sevenZipFileMetadata, int(count))
	var metadata int64
	for {
		kind, err := r.byte()
		if err != nil {
			return nil, err
		}
		if kind == sevenZipEnd {
			for i, file := range files {
				if file.name == "" {
					return nil, fmt.Errorf("7z: file %d has no name", i)
				}
			}
			return files, nil
		}
		size, err := r.uint64()
		if err != nil {
			return nil, err
		}
		if size > uint64(maximumMetadata-metadata) {
			return nil, fmt.Errorf("7z: file metadata exceeds maximum_metadata %d", maximumMetadata)
		}
		metadata += int64(size)
		data, err := r.bytes(size)
		if err != nil {
			return nil, err
		}
		property := &sevenZipReader{data: data}
		switch kind {
		case sevenZipEmptyStream:
			bits, err := property.bitSet(len(files))
			if err != nil {
				return nil, err
			}
			for i := range files {
				files[i].emptyStream = bits[i]
			}
		case sevenZipEmptyFile, sevenZipAnti:
			emptyCount := 0
			for _, file := range files {
				if file.emptyStream {
					emptyCount++
				}
			}
			bits, err := property.bitSet(emptyCount)
			if err != nil {
				return nil, err
			}
			index := 0
			for i := range files {
				if !files[i].emptyStream {
					continue
				}
				if kind == sevenZipEmptyFile {
					files[i].emptyFile = bits[index]
				} else {
					files[i].anti = bits[index]
				}
				index++
			}
		case sevenZipName:
			if err := parseSevenZipNames(property, files); err != nil {
				return nil, err
			}
		case sevenZipDummy:
			for _, value := range data {
				if value != 0 {
					return nil, fmt.Errorf("7z: dummy property contains nonzero data")
				}
			}
		case sevenZipCreationTime, sevenZipAccessTime, sevenZipModifiedTime, sevenZipWinAttributes,
			sevenZipComment, sevenZipStartPosition:
			// Metadata is retained in the archive and can be exposed later without
			// affecting the portable file views. Validate only the bounded property.
		default:
			// Unknown file properties are length-delimited by the format.
		}
	}
}

func validateSevenZipFolder(folder sevenZipFolder) error {
	if len(folder.coders) != 1 || len(folder.packedIndices) != 1 || len(folder.bindPairs) != 0 {
		return fmt.Errorf("7z: coder graphs are not supported yet (coders=%d packed=%d binds=%d)", len(folder.coders), len(folder.packedIndices), len(folder.bindPairs))
	}
	coder := folder.coders[0]
	if coder.inputs != 1 || coder.outputs != 1 {
		return fmt.Errorf("7z: coder method %x has %d inputs and %d outputs", coder.method, coder.inputs, coder.outputs)
	}
	switch sevenZipMethodName(coder.method) {
	case "copy":
		if len(coder.properties) != 0 {
			return fmt.Errorf("7z: copy coder has properties")
		}
	case "lzma":
		if len(coder.properties) != 5 {
			return fmt.Errorf("7z: LZMA coder has %d property bytes, want 5", len(coder.properties))
		}
	default:
		return fmt.Errorf("7z: unsupported coder method %x", coder.method)
	}
	return nil
}

func sevenZipFolderDataFromStreams(file storage.Reader, streams sevenZipStreams, baseOffset int64, maximumDictionary uint64) ([]*sevenZipFolderData, error) {
	packedIndex := 0
	packedOffset := baseOffset
	if streams.packPosition > uint64(math.MaxInt64-baseOffset) {
		return nil, fmt.Errorf("7z: packed data offset overflows")
	}
	packedOffset += int64(streams.packPosition)
	result := make([]*sevenZipFolderData, len(streams.folders))
	for i, folder := range streams.folders {
		if err := validateSevenZipFolder(folder); err != nil {
			return nil, fmt.Errorf("7z: folder %d: %w", i, err)
		}
		if packedIndex >= len(streams.packSizes) {
			return nil, fmt.Errorf("7z: folder %d has no packed stream", i)
		}
		packedSize := streams.packSizes[packedIndex]
		unpackSize, err := folder.unpackSize()
		if err != nil {
			return nil, err
		}
		if packedSize > math.MaxInt64 || unpackSize > math.MaxInt64 || packedOffset < 0 || int64(packedSize) > file.Size()-packedOffset {
			return nil, fmt.Errorf("7z: folder %d data lies outside archive", i)
		}
		result[i] = &sevenZipFolderData{
			base: file, packedOffset: packedOffset, packedSize: int64(packedSize), unpackSize: int64(unpackSize),
			coder: folder.coders[0], crc: folder.crc, maximumDictionary: maximumDictionary,
		}
		packedOffset += int64(packedSize)
		packedIndex++
	}
	if packedIndex != len(streams.packSizes) {
		return nil, fmt.Errorf("7z: %d packed streams are not connected to folders", len(streams.packSizes)-packedIndex)
	}
	return result, nil
}

func decodeSevenZipHeader(file storage.Reader, streams sevenZipStreams, maximumDictionary uint64, maximumMetadata int64) ([]byte, error) {
	folders, err := sevenZipFolderDataFromStreams(file, streams, 32, maximumDictionary)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, folder := range folders {
		if folder.unpackSize > maximumMetadata-total {
			return nil, fmt.Errorf("7z: decoded header exceeds maximum_metadata %d", maximumMetadata)
		}
		total += folder.unpackSize
	}
	data := make([]byte, 0, total)
	for _, folder := range folders {
		decoded, err := folder.all()
		if err != nil {
			return nil, fmt.Errorf("7z: decode encoded header: %w", err)
		}
		data = append(data, decoded...)
	}
	return data, nil
}

func parseSevenZipHeader(file storage.Reader, data []byte, maximumEntries int, maximumMetadata int64, maximumDictionary uint64) (sevenZipStreams, []sevenZipFileMetadata, error) {
	r := &sevenZipReader{data: data}
	kind, err := r.byte()
	if err != nil {
		return sevenZipStreams{}, nil, err
	}
	if kind == sevenZipEncodedHeader {
		streams, err := parseSevenZipStreams(r)
		if err != nil {
			return sevenZipStreams{}, nil, fmt.Errorf("7z: parse encoded-header streams: %w", err)
		}
		if r.remaining() != 0 {
			return sevenZipStreams{}, nil, fmt.Errorf("7z: encoded-header descriptor has %d trailing bytes", r.remaining())
		}
		decoded, err := decodeSevenZipHeader(file, streams, maximumDictionary, maximumMetadata)
		if err != nil {
			return sevenZipStreams{}, nil, err
		}
		return parseSevenZipHeader(file, decoded, maximumEntries, maximumMetadata, maximumDictionary)
	}
	if kind != sevenZipHeader {
		return sevenZipStreams{}, nil, fmt.Errorf("7z: next header begins with %#x", kind)
	}
	var mainStreams sevenZipStreams
	var files []sevenZipFileMetadata
	for {
		property, err := r.byte()
		if err != nil {
			return sevenZipStreams{}, nil, err
		}
		switch property {
		case sevenZipEnd:
			if r.remaining() != 0 {
				return sevenZipStreams{}, nil, fmt.Errorf("7z: header has %d trailing bytes", r.remaining())
			}
			return mainStreams, files, nil
		case sevenZipArchiveProperties:
			for {
				kind, err := r.byte()
				if err != nil {
					return sevenZipStreams{}, nil, err
				}
				if kind == sevenZipEnd {
					break
				}
				size, err := r.uint64()
				if err != nil {
					return sevenZipStreams{}, nil, err
				}
				if _, err := r.bytes(size); err != nil {
					return sevenZipStreams{}, nil, err
				}
			}
		case sevenZipAdditionalStreams:
			return sevenZipStreams{}, nil, fmt.Errorf("7z: additional metadata streams are not supported")
		case sevenZipMainStreams:
			mainStreams, err = parseSevenZipStreams(r)
			if err != nil {
				return sevenZipStreams{}, nil, err
			}
		case sevenZipFilesInfo:
			files, err = parseSevenZipFiles(r, maximumEntries, maximumMetadata)
			if err != nil {
				return sevenZipStreams{}, nil, err
			}
		default:
			return sevenZipStreams{}, nil, fmt.Errorf("7z: unexpected header property %#x", property)
		}
	}
}

func Open(file storage.Reader, maximumEntries int, maximumMetadata int64, maximumDictionary uint64) (*Archive, error) {
	if maximumEntries <= 0 || maximumMetadata <= 0 || maximumDictionary == 0 {
		return nil, fmt.Errorf("sevenzip: limits must be positive")
	}
	if file.Size() < 32 {
		return nil, fmt.Errorf("7z: file is too small")
	}
	signatureHeader := make([]byte, 32)
	if _, err := file.ReadAt(signatureHeader, 0); err != nil {
		return nil, fmt.Errorf("7z: read signature header: %w", err)
	}
	if !bytes.Equal(signatureHeader[:6], sevenZipSignature) {
		return nil, fmt.Errorf("7z: invalid signature")
	}
	if signatureHeader[6] != 0 {
		return nil, fmt.Errorf("7z: unsupported format major version %d", signatureHeader[6])
	}
	if actual, expected := crc32.ChecksumIEEE(signatureHeader[12:32]), binary.LittleEndian.Uint32(signatureHeader[8:12]); actual != expected {
		return nil, fmt.Errorf("7z: start-header CRC is %#08x, want %#08x", actual, expected)
	}
	nextOffset := binary.LittleEndian.Uint64(signatureHeader[12:20])
	nextSize := binary.LittleEndian.Uint64(signatureHeader[20:28])
	if nextSize > uint64(maximumMetadata) || nextSize > uint64(math.MaxInt) {
		return nil, fmt.Errorf("7z: next header size %d exceeds maximum_metadata %d", nextSize, maximumMetadata)
	}
	if nextOffset > math.MaxInt64-32 || nextSize > math.MaxInt64-(32+nextOffset) {
		return nil, fmt.Errorf("7z: next header offset overflows")
	}
	headerOffset := int64(32 + nextOffset)
	if headerOffset < 32 || int64(nextSize) > file.Size()-headerOffset {
		return nil, fmt.Errorf("7z: next header lies outside archive")
	}
	nextHeader := make([]byte, int(nextSize))
	if _, err := file.ReadAt(nextHeader, headerOffset); err != nil && err != io.EOF {
		return nil, fmt.Errorf("7z: read next header: %w", err)
	}
	if actual, expected := crc32.ChecksumIEEE(nextHeader), binary.LittleEndian.Uint32(signatureHeader[28:32]); actual != expected {
		return nil, fmt.Errorf("7z: next-header CRC is %#08x, want %#08x", actual, expected)
	}
	streams, metadata, err := parseSevenZipHeader(file, nextHeader, maximumEntries, maximumMetadata, maximumDictionary)
	if err != nil {
		return nil, err
	}
	folders, err := sevenZipFolderDataFromStreams(file, streams, 32, maximumDictionary)
	if err != nil {
		return nil, err
	}
	var streamFiles []struct {
		folder *sevenZipFolderData
		offset int64
		size   int64
		crc    sevenZipDigest
	}
	for folderIndex, folder := range streams.folders {
		var offset uint64
		for _, substream := range folder.substreams {
			if substream.size > math.MaxInt64 || offset > math.MaxInt64-substream.size {
				return nil, fmt.Errorf("7z: folder %d substream size overflows", folderIndex)
			}
			streamFiles = append(streamFiles, struct {
				folder *sevenZipFolderData
				offset int64
				size   int64
				crc    sevenZipDigest
			}{folders[folderIndex], int64(offset), int64(substream.size), substream.crc})
			offset += substream.size
		}
	}
	archive := &Archive{index: make(map[string][]int)}
	streamIndex := 0
	for _, item := range metadata {
		entry := &Entry{
			archive: archive, name: item.name, path: storage.CleanPath(item.name),
			directory: item.emptyStream && !item.emptyFile, anti: item.anti,
		}
		if !item.emptyStream {
			if streamIndex >= len(streamFiles) {
				return nil, fmt.Errorf("7z: file %q has no data stream", item.name)
			}
			stream := streamFiles[streamIndex]
			entry.folder, entry.offset, entry.size, entry.crc = stream.folder, stream.offset, stream.size, stream.crc
			entry.folder.entries = append(entry.folder.entries, entry)
			streamIndex++
		}
		archive.index[entry.path] = append(archive.index[entry.path], len(archive.entries))
		archive.entries = append(archive.entries, entry)
	}
	if streamIndex != len(streamFiles) {
		return nil, fmt.Errorf("7z: %d data streams have no file entries", len(streamFiles)-streamIndex)
	}
	return archive, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries := sevenZipDefaultMaximumEntries
	maximumMetadata := sevenZipDefaultMaximumMetadata
	maximumDictionary := int64(sevenZipDefaultMaximumDictionary)
	if err := starlark.UnpackArgs("sevenzip", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_metadata?", &maximumMetadata, "max_dictionary?", &maximumDictionary); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("sevenzip: got %s, want file", value.Type())
	}
	if maximumDictionary <= 0 {
		return nil, fmt.Errorf("sevenzip: max_dictionary must be positive")
	}
	return Open(file, maximumEntries, maximumMetadata, uint64(maximumDictionary))
}

var _ starlark.Mapping = (*Archive)(nil)
