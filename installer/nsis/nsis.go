// Package nsis decodes payloads and plans bounded declarative installation effects
// without executing installer code.
// It reads the standard NSIS 2 ANSI, non-solid stored/DEFLATE layout. See README.md
// for the format references and the distinction between a listing and a plan.
package nsis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

var (
	ErrNoMatch     = errors.New("nsis: signature not found")
	ErrLimit       = errors.New("nsis: resource limit exceeded")
	ErrUnsupported = errors.New("nsis: unsupported format")
)

const firstHeaderSize = 28

var signature = []byte{0xef, 0xbe, 0xad, 0xde, 'N', 'u', 'l', 'l', 's', 'o', 'f', 't', 'I', 'n', 's', 't'}

// Options bounds input scanning, decoded metadata, listing text and instructions.
// Zero fields select defaults; negative fields are invalid.
type Options struct {
	MaxScanBytes     int64
	MaxMetadataBytes int64
	MaxInstructions  int
}

func (o Options) defaults() (Options, error) {
	if o.MaxScanBytes < 0 || o.MaxMetadataBytes < 0 || o.MaxInstructions < 0 {
		return o, fmt.Errorf("nsis: limits must be nonnegative")
	}
	if o.MaxScanBytes == 0 {
		o.MaxScanBytes = 16 << 20
	}
	if o.MaxMetadataBytes == 0 {
		o.MaxMetadataBytes = 64 << 20
	}
	if o.MaxInstructions == 0 {
		o.MaxInstructions = 1_000_000
	}
	return o, nil
}

// Entry describes one File instruction, not a guaranteed installation action.
// Duplicated names/data references remain separate and instruction order is kept.
type Entry struct {
	Instruction int
	Name        string
	RawName     []byte
	// OutputDirectory is the nearest preceding SetOutPath expression in bytecode
	// order, NOT a control-flow-resolved destination. DirectoryInstruction is -1
	// when no such instruction precedes this entry.
	OutputDirectory      string
	DirectoryInstruction int
	// DataOffset is relative to the data block. Offset addresses the member's
	// four-byte packed-length prefix in the original source.
	DataOffset int64
	Offset     int64
	PackedSize int64
	Compressed bool
	FileTime   uint64
}

// Instruction retains the standard NSIS opcode and six typed-by-opcode operands.
type Instruction struct {
	Opcode   uint32
	Operands [6]int32
}

// Section is a selectable code range, not an already evaluated installation.
type Section struct {
	Name         string
	Flags        uint32
	Start, Count int
}

type Listing struct {
	HeaderOffset      int64
	DataOffset        int64
	HeaderSize        int64
	HeaderCompression string
	Instructions      int
	Entries           []Entry
	Code              []Instruction
	Sections          []Section
	strings           []byte
	ContainerSize     int64
}

func readAt(r storage.Reader, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("nsis: read at %d: %w", off, err)
}

// List reads only metadata and member length prefixes, never member contents.
// CRC verification and payload decompression are deliberately not claimed.
func List(source storage.Reader, options Options) (*Listing, error) {
	o, err := options.defaults()
	if err != nil {
		return nil, err
	}
	if source.Size() < firstHeaderSize {
		return nil, ErrNoMatch
	}
	// Standard NSIS executable stubs place the first header on a 512-byte
	// boundary. Also accept a bare container starting at offset zero.
	var first [firstHeaderSize]byte
	offset := int64(-1)
	scanEnd := min(source.Size(), o.MaxScanBytes)
	for pos := int64(0); pos <= scanEnd-firstHeaderSize; pos += 512 {
		if err := readAt(source, first[:], pos); err != nil {
			return nil, err
		}
		if bytes.Equal(first[4:20], signature) {
			offset = pos
			break
		}
	}
	if offset < 0 {
		if source.Size() > o.MaxScanBytes {
			return nil, fmt.Errorf("%w: signature scan", ErrLimit)
		}
		return nil, ErrNoMatch
	}
	u32 := binary.LittleEndian.Uint32
	flags := u32(first[:4])
	if flags & ^uint32(15) != 0 {
		return nil, fmt.Errorf("%w: first-header flags %#x", ErrUnsupported, flags)
	}
	headerSize := int64(u32(first[20:24]))
	total := int64(u32(first[24:28]))
	if headerSize < 68 {
		return nil, fmt.Errorf("nsis: invalid metadata size %d", headerSize)
	}
	if headerSize > o.MaxMetadataBytes || uint64(headerSize) > uint64(^uint(0)>>1) {
		return nil, ErrLimit
	}
	if total < firstHeaderSize+4 || total > source.Size()-offset {
		return nil, fmt.Errorf("nsis: container length out of bounds")
	}
	end := offset + total
	if flags&4 == 0 {
		end -= 4
	} // exclude optional CRC, not an Authenticode trailer
	block := offset + firstHeaderSize
	if end-block < 4 {
		return nil, fmt.Errorf("nsis: truncated metadata block")
	}
	var length [4]byte
	if err := readAt(source, length[:], block); err != nil {
		return nil, err
	}
	lengthWord := u32(length[:])
	packed := int64(lengthWord & 0x7fffffff)
	if packed > o.MaxMetadataBytes {
		return nil, fmt.Errorf("%w: packed metadata (or unsupported solid stream)", ErrLimit)
	}
	if packed > end-block-4 {
		return nil, fmt.Errorf("%w: solid stream or invalid metadata block length", ErrUnsupported)
	}
	metadata := make([]byte, int(headerSize))
	compression := "stored"
	if lengthWord&0x80000000 == 0 {
		if packed != headerSize {
			return nil, fmt.Errorf("%w: solid stream or mismatched stored metadata size", ErrUnsupported)
		}
		if err := readAt(source, metadata, block+4); err != nil {
			return nil, err
		}
	} else {
		compression = "deflate"
		encoded := make([]byte, int(packed))
		if err := readAt(source, encoded, block+4); err != nil {
			return nil, err
		}
		metadata, err = inflateNSIS(encoded, headerSize)
		if err != nil {
			return nil, fmt.Errorf("nsis: metadata DEFLATE (other codecs are unsupported): %w", err)
		}
		if int64(len(metadata)) != headerSize {
			return nil, fmt.Errorf("nsis: metadata decompressed length mismatch")
		}
	}
	result := &Listing{ContainerSize: total, HeaderOffset: offset, DataOffset: block + 4 + packed, HeaderSize: headerSize, HeaderCompression: compression}
	if err := result.parseMetadata(metadata, source, end, o); err != nil {
		return nil, err
	}
	return result, nil
}

type metadataBlock struct{ offset, count uint32 }

func (l *Listing) parseMetadata(data []byte, source storage.Reader, end int64, o Options) error {
	u32 := binary.LittleEndian.Uint32
	var blocks [8]metadataBlock
	for i := range blocks {
		blocks[i] = metadataBlock{u32(data[4+8*i:]), u32(data[8+8*i:])}
	}
	// NB_DATA refers to the separate payload stream, not a metadata range.
	previous := uint32(68)
	for i, b := range blocks[:7] {
		if b.offset == 0 && b.count == 0 {
			continue
		}
		if b.offset < previous || uint64(b.offset) > uint64(len(data)) {
			return fmt.Errorf("nsis: metadata block %d out of bounds or order", i)
		}
		previous = b.offset
	}
	code, stringsBlock, languages := blocks[2], blocks[3], blocks[4]
	if uint64(code.count) > uint64(o.MaxInstructions) {
		return ErrLimit
	}
	if code.offset < 68 || stringsBlock.offset < code.offset || uint64(code.count)*28 > uint64(stringsBlock.offset-code.offset) {
		return fmt.Errorf("nsis: instruction table out of bounds")
	}
	if stringsBlock.offset < 68 || languages.offset <= stringsBlock.offset || uint64(languages.offset) > uint64(len(data)) {
		return fmt.Errorf("nsis: string table out of bounds")
	}
	table := data[stringsBlock.offset:languages.offset]
	if table[0] != 0 {
		return fmt.Errorf("nsis: missing initial empty string")
	}
	if len(table) > 1 && table[1] == 0 {
		return fmt.Errorf("%w: Unicode strings", ErrUnsupported)
	}
	l.strings = bytes.Clone(table)
	sectionBlock := blocks[1]
	if sectionBlock.offset > code.offset || uint64(sectionBlock.count)*24 > uint64(code.offset-sectionBlock.offset) {
		return fmt.Errorf("nsis: section table out of bounds: offset=%d count=%d code=%d", sectionBlock.offset, sectionBlock.count, code.offset)
	}
	for n := uint32(0); n < sectionBlock.count; n++ {
		record := data[sectionBlock.offset+n*24:][:24]
		start, count := u32(record[12:]), u32(record[16:])
		if uint64(start)+uint64(count) > uint64(code.count) {
			return fmt.Errorf("nsis: section code range out of bounds")
		}
		name, _, err := decodeString(table, int32(u32(record)))
		if err != nil {
			return err
		}
		l.Sections = append(l.Sections, Section{Name: name, Flags: u32(record[8:]), Start: int(start), Count: int(count)})
	}
	l.Instructions = int(code.count)
	directory := "$OUTDIR"
	directoryInstruction := -1
	textBudget := o.MaxMetadataBytes
	for i := 0; i < l.Instructions; i++ {
		instruction := data[int(code.offset)+i*28:][:28]
		opcode := u32(instruction)
		decoded := Instruction{Opcode: opcode}
		for n := range decoded.Operands {
			decoded.Operands[n] = int32(u32(instruction[4+n*4:]))
		}
		l.Code = append(l.Code, decoded)
		operand := func(n int) uint32 { return u32(instruction[4+n*4:]) }
		if opcode == 11 && operand(1) != 0 { // SetOutPath (CreateDirectory with update flag)
			name, _, err := decodeString(table, int32(operand(0)))
			if err != nil {
				return fmt.Errorf("nsis: instruction %d directory: %w", i, err)
			}
			textBudget -= int64(len(name))
			if textBudget < 0 {
				return ErrLimit
			}
			directory, directoryInstruction = name, i
		}
		if opcode != 20 {
			continue
		} // EW_EXTRACTFILE
		name, raw, err := decodeString(table, int32(operand(1)))
		if err != nil {
			return fmt.Errorf("nsis: instruction %d filename: %w", i, err)
		}
		if name == "" {
			return fmt.Errorf("nsis: instruction %d has empty filename", i)
		}
		textBudget -= int64(len(name) + len(raw) + len(directory))
		if textBudget < 0 {
			return ErrLimit
		}
		relative := int64(operand(2))
		if relative > end-l.DataOffset-4 {
			return fmt.Errorf("nsis: instruction %d payload offset out of bounds", i)
		}
		at := l.DataOffset + relative
		var length [4]byte
		if err := readAt(source, length[:], at); err != nil {
			return err
		}
		word := u32(length[:])
		size := int64(word & 0x7fffffff)
		if size > end-at-4 {
			return fmt.Errorf("nsis: instruction %d payload length out of bounds", i)
		}
		l.Entries = append(l.Entries, Entry{
			Instruction: i, Name: name, RawName: bytes.Clone(raw),
			OutputDirectory: directory, DirectoryInstruction: directoryInstruction,
			DataOffset: relative, Offset: at, PackedSize: size, Compressed: word&0x80000000 != 0,
			FileTime: uint64(operand(3)) | uint64(operand(4))<<32,
		})
	}
	return nil
}

// ANSI bytes are retained verbatim; no host code page is inferred. Expressions
// are rendered symbolically, not expanded against the host or an assumed guest.
func decodeString(table []byte, offset int32) (string, []byte, error) {
	if offset < 0 {
		return fmt.Sprintf("${LANG:%d}", -int64(offset)-1), nil, nil
	}
	if int64(offset) >= int64(len(table)) {
		return "", nil, fmt.Errorf("string offset out of bounds")
	}
	src := table[offset:]
	end := bytes.IndexByte(src[:min(len(src), 65537)], 0)
	if end < 0 {
		if len(src) > 65536 {
			return "", nil, ErrLimit
		}
		return "", nil, fmt.Errorf("unterminated string")
	}
	raw := src[:end]
	out := make([]byte, 0, end)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 1 && c <= 4 {
			return "", nil, fmt.Errorf("%w: NSIS 3 string codes", ErrUnsupported)
		}
		if c < 252 {
			if c == '$' {
				out = append(out, '$')
			} // distinguish a literal dollar from an expression
			out = append(out, c)
			continue
		}
		if c == 252 {
			i++
			if i >= len(raw) {
				return "", nil, fmt.Errorf("truncated escaped character")
			}
			if raw[i] == '$' {
				out = append(out, '$')
			}
			out = append(out, raw[i])
			continue
		}
		if i+2 >= len(raw) {
			return "", nil, fmt.Errorf("truncated string code")
		}
		a, b := raw[i+1], raw[i+2]
		i += 2
		n := int(a&127) | int(b&127)<<7
		switch c {
		case 253:
			out = append(out, variable(n)...)
		case 254:
			out = append(out, fmt.Sprintf("${SHELL:%02x,%02x}", a, b)...)
		case 255:
			out = append(out, fmt.Sprintf("${LANG:%d}", n)...)
		}
	}
	return string(out), raw, nil
}

func variable(n int) string {
	if n < 10 {
		return fmt.Sprintf("$%d", n)
	}
	if n < 20 {
		return fmt.Sprintf("$R%d", n-10)
	}
	names := []string{"CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP", "PLUGINSDIR"}
	if n-20 < len(names) {
		return "$" + names[n-20]
	}
	return fmt.Sprintf("${VAR:%d}", n)
}
