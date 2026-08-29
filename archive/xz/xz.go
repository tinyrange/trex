package xz

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sync"

	rootxz "github.com/therootcompany/xz"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultXZDictionaryLimit = 64 << 20

var xzHeaderMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumDictionary := defaultXZDictionaryLimit
	if err := starlark.UnpackArgs("xz", args, kwargs, "file", &value, "max_dictionary?", &maximumDictionary); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("xz: got %s, want file", value.Type())
	}
	if maximumDictionary <= 0 || uint64(maximumDictionary) > math.MaxUint32 {
		return nil, fmt.Errorf("xz: max_dictionary must be between 1 and %d", uint64(math.MaxUint32))
	}
	return Open(file, uint32(maximumDictionary))
}

type File struct {
	base       storage.Reader
	size       int64
	dictionary uint32

	mu      sync.Mutex
	reader  io.Reader
	offset  int64
	readErr error
}

func Open(file storage.Reader, dictionary uint32) (*File, error) {
	if dictionary == 0 {
		dictionary = defaultXZDictionaryLimit
	}
	size, streams, blocks, err := xzUncompressedSize(file)
	if err != nil {
		return nil, err
	}
	if streams == 0 {
		return nil, fmt.Errorf("xz: no streams")
	}
	_ = blocks // Parsing the count validates every Index record and block boundary.
	return &File{base: file, size: size, dictionary: dictionary, offset: -1}, nil
}
func (f *File) reset() error {
	reader, err := rootxz.NewReader(io.NewSectionReader(f.base, 0, f.base.Size()), f.dictionary)
	if err != nil {
		return fmt.Errorf("xz: initialize decoder: %w", err)
	}
	f.reader = reader
	f.offset = 0
	f.readErr = nil
	return nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		if off > f.size {
			return 0, io.EOF
		}
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}

	requested := len(p)
	if remaining := f.size - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reader == nil || off < f.offset {
		if err := f.reset(); err != nil {
			return 0, err
		}
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	if off > f.offset {
		n, err := io.CopyN(io.Discard, f.reader, off-f.offset)
		f.offset += n
		if err != nil {
			f.readErr = fmt.Errorf("xz: seek to uncompressed offset %d: %w", off, err)
			return 0, f.readErr
		}
	}

	n, err := io.ReadFull(f.reader, p)
	f.offset += int64(n)
	if err != nil {
		f.readErr = fmt.Errorf("xz: decompress at offset %d: %w", off, err)
		return n, f.readErr
	}
	if f.offset == f.size {
		if err := verifyXZEnd(f.reader); err != nil {
			f.readErr = err
			return n, err
		}
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}

func verifyXZEnd(reader io.Reader) error {
	n, err := io.CopyN(io.Discard, reader, 1)
	if n != 0 {
		return fmt.Errorf("xz: decoded data exceeds size declared by stream indexes")
	}
	if err != io.EOF {
		if err == nil {
			return fmt.Errorf("xz: decoder did not terminate at indexed size")
		}
		return fmt.Errorf("xz: verify stream footer: %w", err)
	}
	return nil
}

func (f *File) WriteTo(w io.Writer) (int64, error) {
	reader, err := rootxz.NewReader(io.NewSectionReader(f.base, 0, f.base.Size()), f.dictionary)
	if err != nil {
		return 0, fmt.Errorf("xz: initialize decoder: %w", err)
	}
	n, err := io.CopyN(w, reader, f.size)
	if err != nil {
		return n, fmt.Errorf("xz: decompress: %w", err)
	}
	if err := verifyXZEnd(reader); err != nil {
		return n, err
	}
	return n, nil
}

func (f *File) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("xz file is read-only") }
func (f *File) Size() int64                        { return f.size }
func (f *File) String() string {
	return fmt.Sprintf("<xz.file compressed=%d size=%d>", f.base.Size(), f.size)
}
func (f *File) Type() string          { return "file" }
func (f *File) Freeze()               {}
func (f *File) Truth() starlark.Bool  { return starlark.True }
func (f *File) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *File) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *File) AttrNames() []string { return starfile.AttrNames() }

func xzUncompressedSize(file storage.Reader) (size int64, streamCount int, blockCount uint64, err error) {
	end := file.Size()
	if end < 24 {
		return 0, 0, 0, fmt.Errorf("xz: file is too small")
	}
	var total uint64
	for end > 0 {
		var padding int64
		end, padding, err = trimXZStreamPadding(file, end)
		if err != nil {
			return 0, 0, 0, err
		}
		if padding&3 != 0 {
			return 0, 0, 0, fmt.Errorf("xz: stream padding is not a multiple of four bytes")
		}
		if end == 0 {
			return 0, 0, 0, fmt.Errorf("xz: file contains only stream padding")
		}
		if end < 24 {
			return 0, 0, 0, fmt.Errorf("xz: truncated stream before offset %d", end)
		}

		footerOffset := end - 12
		footer := make([]byte, 12)
		if _, err := file.ReadAt(footer, footerOffset); err != nil {
			return 0, 0, 0, fmt.Errorf("xz: read stream footer: %w", err)
		}
		if string(footer[10:12]) != "YZ" {
			return 0, 0, 0, fmt.Errorf("xz: invalid stream footer magic at offset %d", footerOffset)
		}
		if binary.LittleEndian.Uint32(footer[:4]) != crc32.ChecksumIEEE(footer[4:10]) {
			return 0, 0, 0, fmt.Errorf("xz: invalid stream footer checksum at offset %d", footerOffset)
		}
		indexSize := (uint64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
		if indexSize > uint64(footerOffset) || indexSize < 8 {
			return 0, 0, 0, fmt.Errorf("xz: invalid index size %d", indexSize)
		}
		indexOffset := footerOffset - int64(indexSize)
		uncompressed, paddedBlocks, records, err := parseXZIndex(file, indexOffset, int64(indexSize))
		if err != nil {
			return 0, 0, 0, err
		}
		if paddedBlocks > uint64(indexOffset-12) {
			return 0, 0, 0, fmt.Errorf("xz: block sizes extend before stream header")
		}
		headerOffset := indexOffset - int64(paddedBlocks) - 12
		if headerOffset < 0 {
			return 0, 0, 0, fmt.Errorf("xz: invalid stream start")
		}
		header := make([]byte, 12)
		if _, err := file.ReadAt(header, headerOffset); err != nil {
			return 0, 0, 0, fmt.Errorf("xz: read stream header: %w", err)
		}
		if string(header[:6]) != string(xzHeaderMagic) {
			return 0, 0, 0, fmt.Errorf("xz: invalid stream header magic at offset %d", headerOffset)
		}
		if binary.LittleEndian.Uint32(header[8:12]) != crc32.ChecksumIEEE(header[6:8]) {
			return 0, 0, 0, fmt.Errorf("xz: invalid stream header checksum at offset %d", headerOffset)
		}
		if string(header[6:8]) != string(footer[8:10]) {
			return 0, 0, 0, fmt.Errorf("xz: stream header and footer flags differ")
		}
		if total > math.MaxInt64-uncompressed {
			return 0, 0, 0, fmt.Errorf("xz: uncompressed size overflows 64-bit file size")
		}
		total += uncompressed
		if blockCount > math.MaxUint64-records {
			return 0, 0, 0, fmt.Errorf("xz: block count overflow")
		}
		blockCount += records
		streamCount++
		end = headerOffset
	}
	return int64(total), streamCount, blockCount, nil
}

func trimXZStreamPadding(file storage.Reader, end int64) (int64, int64, error) {
	original := end
	buffer := make([]byte, 4096)
	for end > 0 {
		start := end - int64(len(buffer))
		if start < 0 {
			start = 0
		}
		chunk := buffer[:end-start]
		if _, err := file.ReadAt(chunk, start); err != nil && err != io.EOF {
			return 0, 0, fmt.Errorf("xz: scan stream padding: %w", err)
		}
		i := len(chunk)
		for i > 0 && chunk[i-1] == 0 {
			i--
		}
		end = start + int64(i)
		if i != 0 {
			break
		}
	}
	return end, original - end, nil
}

func parseXZIndex(file storage.Reader, offset, size int64) (uncompressed uint64, paddedBlocks uint64, records uint64, err error) {
	if size < 8 {
		return 0, 0, 0, fmt.Errorf("xz: index at offset %d is too small", offset)
	}
	bodySize := size - 4
	hash := crc32.NewIEEE()
	section := io.NewSectionReader(file, offset, bodySize)
	reader := bufio.NewReaderSize(io.TeeReader(section, hash), 4096)
	indicator, err := reader.ReadByte()
	if err != nil || indicator != 0 {
		return 0, 0, 0, fmt.Errorf("xz: invalid index indicator at offset %d", offset)
	}
	records, err = readXZVLI(reader)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("xz: read index record count: %w", err)
	}
	if records > uint64(bodySize/2) {
		return 0, 0, 0, fmt.Errorf("xz: impossible index record count %d", records)
	}
	for i := uint64(0); i < records; i++ {
		unpadded, err := readXZVLI(reader)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("xz: read block %d unpadded size: %w", i, err)
		}
		blockSize, err := readXZVLI(reader)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("xz: read block %d uncompressed size: %w", i, err)
		}
		if unpadded == 0 || unpadded > math.MaxUint64-3 {
			return 0, 0, 0, fmt.Errorf("xz: invalid block %d unpadded size %d", i, unpadded)
		}
		padded := (unpadded + 3) &^ 3
		if paddedBlocks > math.MaxUint64-padded || uncompressed > math.MaxUint64-blockSize {
			return 0, 0, 0, fmt.Errorf("xz: index size overflow")
		}
		paddedBlocks += padded
		uncompressed += blockSize
	}
	for {
		value, err := reader.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, 0, fmt.Errorf("xz: read index padding: %w", err)
		}
		if value != 0 {
			return 0, 0, 0, fmt.Errorf("xz: non-zero index padding")
		}
	}
	expected := make([]byte, 4)
	if _, err := file.ReadAt(expected, offset+bodySize); err != nil {
		return 0, 0, 0, fmt.Errorf("xz: read index checksum: %w", err)
	}
	if binary.LittleEndian.Uint32(expected) != hash.Sum32() {
		return 0, 0, 0, fmt.Errorf("xz: invalid index checksum at offset %d", offset)
	}
	return uncompressed, paddedBlocks, records, nil
}

func readXZVLI(reader *bufio.Reader) (uint64, error) {
	var value uint64
	for i := 0; i < 9; i++ {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, fmt.Errorf("non-minimal variable-length integer")
			}
			return value, nil
		}
	}
	return 0, fmt.Errorf("variable-length integer exceeds 63 bits")
}
