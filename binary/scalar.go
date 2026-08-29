// Package binary provides portable helpers shared by binary-format frontends.
package binary

import (
	bytespkg "bytes"
	encodingbinary "encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const DefaultValueLimit = int64(512 << 20)

func BytesForValue(value starlark.Value) ([]byte, error) {
	return starfile.BytesForValue(value, DefaultValueLimit)
}

type ScalarCodec struct {
	Name   string
	Width  int
	Order  encodingbinary.ByteOrder
	Signed bool
	Float  bool
}

var ScalarCodecs = []ScalarCodec{
	{Name: "u8", Width: 1, Order: encodingbinary.LittleEndian}, {Name: "i8", Width: 1, Order: encodingbinary.LittleEndian, Signed: true},
	{Name: "u16le", Width: 2, Order: encodingbinary.LittleEndian}, {Name: "u16be", Width: 2, Order: encodingbinary.BigEndian},
	{Name: "i16le", Width: 2, Order: encodingbinary.LittleEndian, Signed: true}, {Name: "i16be", Width: 2, Order: encodingbinary.BigEndian, Signed: true},
	{Name: "u32le", Width: 4, Order: encodingbinary.LittleEndian}, {Name: "u32be", Width: 4, Order: encodingbinary.BigEndian},
	{Name: "i32le", Width: 4, Order: encodingbinary.LittleEndian, Signed: true}, {Name: "i32be", Width: 4, Order: encodingbinary.BigEndian, Signed: true},
	{Name: "u64le", Width: 8, Order: encodingbinary.LittleEndian}, {Name: "u64be", Width: 8, Order: encodingbinary.BigEndian},
	{Name: "i64le", Width: 8, Order: encodingbinary.LittleEndian, Signed: true}, {Name: "i64be", Width: 8, Order: encodingbinary.BigEndian, Signed: true},
	{Name: "f32le", Width: 4, Order: encodingbinary.LittleEndian, Float: true}, {Name: "f32be", Width: 4, Order: encodingbinary.BigEndian, Float: true},
	{Name: "f64le", Width: 8, Order: encodingbinary.LittleEndian, Float: true}, {Name: "f64be", Width: 8, Order: encodingbinary.BigEndian, Float: true},
}

func ScalarCodecNamed(name string) (ScalarCodec, bool) {
	for _, codec := range ScalarCodecs {
		if codec.Name == name {
			return codec, true
		}
	}
	return ScalarCodec{}, false
}

func (codec ScalarCodec) Encode(value starlark.Value) ([]byte, error) {
	data := make([]byte, codec.Width)
	if codec.Float {
		floating, ok := value.(starlark.Float)
		if !ok {
			return nil, fmt.Errorf("got %s, want float", value.Type())
		}
		if codec.Width == 4 {
			codec.Order.PutUint32(data, math.Float32bits(float32(floating)))
		} else {
			codec.Order.PutUint64(data, math.Float64bits(float64(floating)))
		}
		return data, nil
	}
	integer, ok := value.(starlark.Int)
	if !ok {
		return nil, fmt.Errorf("got %s, want int", value.Type())
	}
	var bits uint64
	if codec.Signed {
		n, ok := integer.Int64()
		if !ok || codec.Width < 8 && (n < -(int64(1)<<(codec.Width*8-1)) || n >= int64(1)<<(codec.Width*8-1)) {
			return nil, fmt.Errorf("value does not fit in signed %d bits", codec.Width*8)
		}
		bits = uint64(n)
	} else {
		n, ok := integer.Uint64()
		if !ok || codec.Width < 8 && n >= uint64(1)<<(codec.Width*8) {
			return nil, fmt.Errorf("value does not fit in unsigned %d bits", codec.Width*8)
		}
		bits = n
	}
	switch codec.Width {
	case 1:
		data[0] = byte(bits)
	case 2:
		codec.Order.PutUint16(data, uint16(bits))
	case 4:
		codec.Order.PutUint32(data, uint32(bits))
	case 8:
		codec.Order.PutUint64(data, bits)
	}
	return data, nil
}

func (codec ScalarCodec) Decode(data []byte) starlark.Value {
	var bits uint64
	switch codec.Width {
	case 1:
		bits = uint64(data[0])
	case 2:
		bits = uint64(codec.Order.Uint16(data))
	case 4:
		bits = uint64(codec.Order.Uint32(data))
	case 8:
		bits = codec.Order.Uint64(data)
	}
	if codec.Float {
		if codec.Width == 4 {
			return starlark.Float(math.Float32frombits(uint32(bits)))
		}
		return starlark.Float(math.Float64frombits(bits))
	}
	if codec.Signed {
		switch codec.Width {
		case 1:
			return starlark.MakeInt(int(int8(bits)))
		case 2:
			return starlark.MakeInt(int(int16(bits)))
		case 4:
			return starlark.MakeInt64(int64(int32(bits)))
		case 8:
			return starlark.MakeInt64(int64(bits))
		}
	}
	return starlark.MakeUint64(bits)
}

func DecodeText(data []byte, encoding string, nul bool) (string, error) {
	switch strings.ToLower(strings.ReplaceAll(encoding, "-", "")) {
	case "ascii":
		if nul {
			if end := bytespkg.IndexByte(data, 0); end >= 0 {
				data = data[:end]
			}
		}
		for _, value := range data {
			if value > 0x7f {
				return "", fmt.Errorf("input is not ASCII")
			}
		}
		return string(data), nil
	case "utf8":
		if nul {
			if end := bytespkg.IndexByte(data, 0); end >= 0 {
				data = data[:end]
			}
		}
		if !utf8.Valid(data) {
			return "", fmt.Errorf("input is not valid UTF-8")
		}
		return string(data), nil
	case "utf16le", "utf16be":
		if len(data)%2 != 0 {
			return "", fmt.Errorf("UTF-16 input has odd size")
		}
		var order encodingbinary.ByteOrder = encodingbinary.LittleEndian
		if strings.Contains(strings.ToLower(encoding), "be") {
			order = encodingbinary.BigEndian
		}
		units := make([]uint16, 0, len(data)/2)
		for offset := 0; offset < len(data); offset += 2 {
			unit := order.Uint16(data[offset : offset+2])
			if nul && unit == 0 {
				break
			}
			units = append(units, unit)
		}
		return string(utf16.Decode(units)), nil
	default:
		return "", fmt.Errorf("unsupported encoding %q", encoding)
	}
}
