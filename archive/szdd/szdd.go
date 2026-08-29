package szdd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultSZDDLimit = int64(512 << 20)

var szddSignature = []byte{'S', 'Z', 'D', 'D', 0x88, 0xf0, 0x27, 0x33}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultSZDDLimit
	if err := starlark.UnpackArgs("szdd", args, kwargs, "file", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("szdd: got %s, want file", value.Type())
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("szdd: maximum must be positive")
	}
	decoded, err := decodeSZDD(file, maximum)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "szdd.bin", Data: decoded}, nil
}

func decodeSZDD(file File, maximum int64) ([]byte, error) {
	if file.Size() < 14 {
		return nil, fmt.Errorf("szdd: truncated header")
	}
	if file.Size() > maximum {
		return nil, fmt.Errorf("szdd: compressed size %d exceeds maximum %d", file.Size(), maximum)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("szdd: read: %w", err)
	}
	if !bytes.Equal(data[:8], szddSignature) {
		return nil, fmt.Errorf("szdd: invalid signature")
	}
	if data[8] != 'A' || data[9] != 0 {
		return nil, fmt.Errorf("szdd: unsupported mode %#x or reserved byte %#x", data[8], data[9])
	}
	expected := int64(binary.LittleEndian.Uint32(data[10:14]))
	if expected > maximum {
		return nil, fmt.Errorf("szdd: decoded size %d exceeds maximum %d", expected, maximum)
	}
	return decompressSZDDLZSS(data[14:], expected)
}

func decompressSZDDLZSS(data []byte, expected int64) ([]byte, error) {
	window := [4096]byte{}
	for index := range window {
		window[index] = ' '
	}
	position := 4096 - 16
	out := make([]byte, 0, expected)
	input := 0
	appendByte := func(value byte) {
		out = append(out, value)
		window[position] = value
		position = (position + 1) & 4095
	}
	for int64(len(out)) < expected {
		if input >= len(data) {
			return nil, fmt.Errorf("szdd: decoded %d bytes, want %d: %w", len(out), expected, io.ErrUnexpectedEOF)
		}
		control := data[input]
		input++
		for mask := byte(1); mask != 0 && int64(len(out)) < expected; mask <<= 1 {
			if control&mask != 0 {
				if input >= len(data) {
					return nil, fmt.Errorf("szdd: decoded %d bytes, want %d: %w", len(out), expected, io.ErrUnexpectedEOF)
				}
				appendByte(data[input])
				input++
				continue
			}
			if input+2 > len(data) {
				return nil, fmt.Errorf("szdd: decoded %d bytes, want %d: %w", len(out), expected, io.ErrUnexpectedEOF)
			}
			match := int(data[input]) | int(data[input+1]&0xf0)<<4
			length := int(data[input+1]&0x0f) + 3
			input += 2
			for count := 0; count < length && int64(len(out)) < expected; count++ {
				value := window[match]
				match = (match + 1) & 4095
				appendByte(value)
			}
		}
	}
	return out, nil
}
