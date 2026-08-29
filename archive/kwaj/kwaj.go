package kwaj

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/compression/mszip"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultKWAJLimit = int64(512 << 20)

var kwajSignature = []byte{'K', 'W', 'A', 'J', 0x88, 0xf0, 0x27, 0xd1}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultKWAJLimit
	if err := starlark.UnpackArgs("kwaj", args, kwargs, "file", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("kwaj: got %s, want file", value.Type())
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("kwaj: maximum must be positive")
	}
	header, err := parseKWAJHeader(file, maximum)
	if err != nil {
		return nil, err
	}
	return decodeKWAJHeader(header, maximum)
}

func InfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultKWAJLimit
	if err := starlark.UnpackArgs("kwaj_info", args, kwargs, "file", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("kwaj_info: got %s, want file", value.Type())
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("kwaj_info: maximum must be positive")
	}
	header, err := parseKWAJHeader(file, maximum)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeKWAJHeader(header, maximum)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"file":            decoded,
		"name":            starlark.String(header.name),
		"method":          starlark.MakeUint(uint(header.method)),
		"decoded_size":    starlark.MakeInt64(decoded.Size()),
		"compressed_size": starlark.MakeInt64(file.Size()),
	}), nil
}

type kwajHeader struct {
	data     []byte
	expected int64
	method   uint16
	offset   int
	name     string
}

func decodeKWAJHeader(header *kwajHeader, maximum int64) (File, error) {
	decoded, err := decompressKWAJ(header.data[header.offset:], header.method, header.expected, maximum)
	if err != nil {
		return nil, fmt.Errorf("kwaj: method %d: %w", header.method, err)
	}
	if header.expected >= 0 && int64(len(decoded)) != header.expected {
		return nil, fmt.Errorf("kwaj: decoded %d bytes, want %d", len(decoded), header.expected)
	}
	name := header.name
	if name == "" {
		name = "kwaj.bin"
	}
	return &starfile.Bytes{Name: name, Data: decoded}, nil
}

func readKWAJHeader(file File, maximum int64) ([]byte, int64, uint16, int, error) {
	header, err := parseKWAJHeader(file, maximum)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	return header.data, header.expected, header.method, header.offset, nil
}

func parseKWAJHeader(file File, maximum int64) (*kwajHeader, error) {
	if file.Size() < 14 {
		return nil, fmt.Errorf("kwaj: truncated header")
	}
	if file.Size() > maximum {
		return nil, fmt.Errorf("kwaj: compressed size %d exceeds maximum %d", file.Size(), maximum)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("kwaj: read: %w", err)
	}
	if !bytes.Equal(data[:8], kwajSignature) {
		return nil, fmt.Errorf("kwaj: invalid signature")
	}
	method := binary.LittleEndian.Uint16(data[8:10])
	if method > 4 {
		return nil, fmt.Errorf("kwaj: unsupported compression method %d", method)
	}
	offset := int(binary.LittleEndian.Uint16(data[10:12]))
	flags := binary.LittleEndian.Uint16(data[12:14])
	if flags&^uint16(0x3f) != 0 {
		return nil, fmt.Errorf("kwaj: unsupported header flags %#x", flags)
	}
	if offset < 14 || offset > len(data) {
		return nil, fmt.Errorf("kwaj: invalid data offset %d", offset)
	}
	expected, name, err := parseKWAJExtensions(data, flags, offset)
	if err != nil {
		return nil, err
	}
	if expected > maximum {
		return nil, fmt.Errorf("kwaj: decoded size %d exceeds maximum %d", expected, maximum)
	}
	return &kwajHeader{data: data, expected: expected, method: method, offset: offset, name: name}, nil
}

func parseKWAJExtensions(data []byte, flags uint16, dataOffset int) (int64, string, error) {
	cursor := 14
	expected := int64(-1)
	nameParts := make([]string, 0, 2)
	take := func(size int) ([]byte, error) {
		if size < 0 || cursor > dataOffset || size > dataOffset-cursor {
			return nil, fmt.Errorf("kwaj: header extensions overlap compressed data")
		}
		value := data[cursor : cursor+size]
		cursor += size
		return value, nil
	}
	if flags&1 != 0 {
		value, err := take(4)
		if err != nil {
			return 0, "", err
		}
		expected = int64(binary.LittleEndian.Uint32(value))
	}
	if flags&2 != 0 {
		if _, err := take(2); err != nil {
			return 0, "", err
		}
	}
	if flags&4 != 0 {
		value, err := take(2)
		if err != nil {
			return 0, "", err
		}
		if _, err := take(int(binary.LittleEndian.Uint16(value))); err != nil {
			return 0, "", err
		}
	}
	for _, extension := range []struct {
		flag uint16
		max  int
	}{{8, 9}, {16, 4}} {
		if flags&extension.flag == 0 {
			continue
		}
		terminated := false
		part := make([]byte, 0, extension.max-1)
		for count := 0; count < extension.max; count++ {
			value, err := take(1)
			if err != nil {
				return 0, "", err
			}
			if value[0] == 0 {
				terminated = true
				break
			}
			part = append(part, value[0])
		}
		if !terminated {
			return 0, "", fmt.Errorf("kwaj: unterminated name header")
		}
		nameParts = append(nameParts, string(part))
	}
	if flags&32 != 0 {
		value, err := take(2)
		if err != nil {
			return 0, "", err
		}
		if _, err := take(int(binary.LittleEndian.Uint16(value))); err != nil {
			return 0, "", err
		}
	}
	name := ""
	if len(nameParts) > 0 {
		name = nameParts[0]
	}
	if len(nameParts) > 1 && nameParts[1] != "" {
		name += "." + nameParts[1]
	}
	return expected, name, nil
}

func decompressKWAJ(data []byte, method uint16, expected, maximum int64) ([]byte, error) {
	switch method {
	case 0, 1:
		if int64(len(data)) > maximum {
			return nil, fmt.Errorf("output exceeds maximum %d", maximum)
		}
		out := append([]byte(nil), data...)
		if method == 1 {
			for index := range out {
				out[index] ^= 0xff
			}
		}
		return out, nil
	case 2:
		return decompressKWAJLZSS(data, expected, maximum)
	case 3:
		return decompressKWAJLZH(data, expected, maximum)
	case 4:
		return decompressKWAJMSZIP(data, expected, maximum)
	default:
		return nil, fmt.Errorf("unsupported compression method %d", method)
	}
}

func decompressKWAJLZSS(data []byte, expected, maximum int64) ([]byte, error) {
	window := [4096]byte{}
	for index := range window {
		window[index] = ' '
	}
	position := 4096 - 18
	out := make([]byte, 0, kwajOutputCapacity(expected, len(data), maximum))
	input := 0
	appendByte := func(value byte) error {
		if int64(len(out)) >= maximum || expected >= 0 && int64(len(out)) >= expected {
			return fmt.Errorf("decoded output exceeds declared size or maximum")
		}
		window[position] = value
		out = append(out, value)
		position = (position + 1) & 4095
		return nil
	}
	for input < len(data) && (expected < 0 || int64(len(out)) < expected) {
		control := data[input]
		input++
		for mask := byte(1); mask != 0 && (expected < 0 || int64(len(out)) < expected); mask <<= 1 {
			if control&mask != 0 {
				if input >= len(data) {
					return nil, io.ErrUnexpectedEOF
				}
				value := data[input]
				input++
				if err := appendByte(value); err != nil {
					return nil, err
				}
				continue
			}
			if input+2 > len(data) {
				if expected < 0 {
					return out, nil
				}
				return nil, io.ErrUnexpectedEOF
			}
			match := int(data[input]) | int(data[input+1]&0xf0)<<4
			length := int(data[input+1]&0x0f) + 3
			input += 2
			for count := 0; count < length && (expected < 0 || int64(len(out)) < expected); count++ {
				value := window[match]
				match = (match + 1) & 4095
				if err := appendByte(value); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

type kwajBitReader struct {
	data []byte
	bit  int
}

func (r *kwajBitReader) read(count int) (uint32, error) {
	if count < 0 || count > 24 || count > len(r.data)*8-r.bit {
		return 0, io.ErrUnexpectedEOF
	}
	var value uint32
	for index := 0; index < count; index++ {
		value = value<<1 | uint32((r.data[r.bit/8]>>(7-(r.bit%8)))&1)
		r.bit++
	}
	return value, nil
}

type kwajHuffman struct {
	byLength []map[uint32]int
	maximum  int
}

func newKWAJHuffman(lengths []byte) (*kwajHuffman, error) {
	counts := make([]int, 16)
	maximum := 0
	for _, length := range lengths {
		if length > 15 {
			return nil, fmt.Errorf("invalid Huffman code length %d", length)
		}
		if length != 0 {
			counts[length]++
			maximum = max(maximum, int(length))
		}
	}
	if maximum == 0 {
		return nil, fmt.Errorf("empty Huffman tree")
	}
	left := 1
	for bits := 1; bits <= maximum; bits++ {
		left = left*2 - counts[bits]
		if left < 0 {
			return nil, fmt.Errorf("oversubscribed Huffman tree")
		}
	}
	next := make([]uint32, maximum+1)
	var code uint32
	for bits := 1; bits <= maximum; bits++ {
		code = (code + uint32(counts[bits-1])) << 1
		next[bits] = code
	}
	tree := &kwajHuffman{byLength: make([]map[uint32]int, maximum+1), maximum: maximum}
	for symbol, length := range lengths {
		if length == 0 {
			continue
		}
		if tree.byLength[length] == nil {
			tree.byLength[length] = make(map[uint32]int)
		}
		tree.byLength[length][next[length]] = symbol
		next[length]++
	}
	return tree, nil
}

func (h *kwajHuffman) decode(reader *kwajBitReader) (int, error) {
	var code uint32
	for length := 1; length <= h.maximum; length++ {
		bit, err := reader.read(1)
		if err != nil {
			return 0, err
		}
		code = code<<1 | bit
		if table := h.byLength[length]; table != nil {
			if symbol, ok := table[code]; ok {
				return symbol, nil
			}
		}
	}
	return 0, fmt.Errorf("invalid Huffman code")
}

func readKWAJCodeLengths(reader *kwajBitReader, encoding, symbols int) ([]byte, error) {
	lengths := make([]byte, symbols)
	if encoding == 0 {
		fixed := map[int]byte{16: 4, 32: 5, 64: 6, 256: 8}[symbols]
		if fixed == 0 {
			return nil, fmt.Errorf("unsupported fixed Huffman tree size %d", symbols)
		}
		for index := range lengths {
			lengths[index] = fixed
		}
		return lengths, nil
	}
	if encoding < 1 || encoding > 3 {
		return nil, fmt.Errorf("invalid code-length encoding %d", encoding)
	}
	current := 0
	for index := 0; index < symbols; index++ {
		if encoding == 3 || index == 0 {
			value, err := reader.read(4)
			if err != nil {
				return nil, err
			}
			current = int(value)
		} else if encoding == 1 {
			same, err := reader.read(1)
			if err != nil {
				return nil, err
			}
			if same != 0 {
				increment, err := reader.read(1)
				if err != nil {
					return nil, err
				}
				if increment == 0 {
					current++
				} else {
					value, err := reader.read(4)
					if err != nil {
						return nil, err
					}
					current = int(value)
				}
			}
		} else {
			selector, err := reader.read(2)
			if err != nil {
				return nil, err
			}
			if selector == 3 {
				value, err := reader.read(4)
				if err != nil {
					return nil, err
				}
				current = int(value)
			} else {
				current += int(selector) - 1
			}
		}
		if current < 0 || current > 15 {
			return nil, fmt.Errorf("invalid Huffman code length %d", current)
		}
		lengths[index] = byte(current)
	}
	return lengths, nil
}

func decompressKWAJLZH(data []byte, expected, maximum int64) ([]byte, error) {
	reader := &kwajBitReader{data: data}
	types := make([]int, 6)
	for index := range types {
		value, err := reader.read(4)
		if err != nil {
			return nil, err
		}
		types[index] = int(value)
	}
	sizes := []int{16, 16, 32, 64, 256}
	trees := make([]*kwajHuffman, len(sizes))
	for index, size := range sizes {
		lengths, err := readKWAJCodeLengths(reader, types[index], size)
		if err != nil {
			return nil, fmt.Errorf("Huffman tree %d: %w", index, err)
		}
		trees[index], err = newKWAJHuffman(lengths)
		if err != nil {
			return nil, fmt.Errorf("Huffman tree %d: %w", index, err)
		}
	}
	window := [4096]byte{}
	for index := range window {
		window[index] = ' '
	}
	position := 0
	literalRun := false
	out := make([]byte, 0, kwajOutputCapacity(expected, len(data), maximum))
	appendByte := func(value byte) error {
		if int64(len(out)) >= maximum || expected >= 0 && int64(len(out)) >= expected {
			return fmt.Errorf("decoded output exceeds declared size or maximum")
		}
		window[position] = value
		out = append(out, value)
		position = (position + 1) & 4095
		return nil
	}
	for expected < 0 || int64(len(out)) < expected {
		matchTree := trees[0]
		if literalRun {
			matchTree = trees[1]
		}
		length, err := matchTree.decode(reader)
		if err != nil {
			if expected < 0 && err == io.ErrUnexpectedEOF {
				break
			}
			return nil, err
		}
		if length > 0 {
			literalRun = false
			upper, err := trees[3].decode(reader)
			if err != nil {
				return nil, err
			}
			lower, err := reader.read(6)
			if err != nil {
				return nil, err
			}
			offset := upper<<6 | int(lower)
			for count := 0; count < length+2; count++ {
				if expected >= 0 && int64(len(out)) >= expected {
					return nil, fmt.Errorf("match exceeds declared size")
				}
				if err := appendByte(window[(position+4096-offset)&4095]); err != nil {
					return nil, err
				}
			}
			continue
		}
		length, err = trees[2].decode(reader)
		if err != nil {
			return nil, err
		}
		literalRun = length != 31
		for count := 0; count < length+1; count++ {
			if expected >= 0 && int64(len(out)) >= expected {
				return nil, fmt.Errorf("literal run exceeds declared size")
			}
			literal, err := trees[4].decode(reader)
			if err != nil {
				return nil, err
			}
			if err := appendByte(byte(literal)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func decompressKWAJMSZIP(data []byte, expected, maximum int64) ([]byte, error) {
	var out []byte
	for offset := 0; ; {
		if offset+2 > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if length == 0 {
			break
		}
		if length < 2 || offset+length > len(data) || string(data[offset:offset+2]) != "CK" {
			return nil, fmt.Errorf("invalid MSZIP block")
		}
		blockExpected := 1 << 15
		if expected >= 0 {
			remaining := expected - int64(len(out))
			if remaining <= 0 {
				return nil, fmt.Errorf("MSZIP data exceeds declared size")
			}
			blockExpected = int(min(int64(blockExpected), remaining))
		}
		history := out
		if len(history) > 1<<15 {
			history = history[len(history)-(1<<15):]
		}
		decoded, err := decodeKWAJMSZIPBlock(data[offset+2:offset+length], history, blockExpected, expected >= 0, maximum-int64(len(out)))
		if err != nil {
			return nil, err
		}
		if int64(len(out)+len(decoded)) > maximum {
			return nil, fmt.Errorf("decoded output exceeds maximum %d", maximum)
		}
		out = append(out, decoded...)
		offset += length
	}
	return out, nil
}

func decodeKWAJMSZIPBlock(compressed, history []byte, expected int, sized bool, maximum int64) ([]byte, error) {
	if sized {
		return mszip.Decode(compressed, history, expected)
	}
	var reader io.ReadCloser
	if len(history) == 0 {
		reader = flate.NewReader(bytes.NewReader(compressed))
	} else {
		reader = flate.NewReaderDict(bytes.NewReader(compressed), history)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, min(maximum, 1<<15)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(decoded) > 1<<15 || int64(len(decoded)) > maximum {
		return nil, fmt.Errorf("MSZIP block exceeds its output limit")
	}
	return decoded, nil
}

func kwajOutputCapacity(expected int64, compressed int, maximum int64) int {
	if expected >= 0 {
		return int(expected)
	}
	return int(min(int64(compressed)*4, maximum))
}
