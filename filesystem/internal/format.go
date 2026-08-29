// Package internal contains implementation helpers shared by filesystem
// format packages. It is not part of trex's public API.
package internal

import (
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	windowsguid "github.com/tinyrange/trex/windows/guid"
	"go.starlark.net/starlark"
)

func BootCodeBytes(name string, value starlark.Value) ([]byte, error) {
	if value == nil || value == starlark.None {
		return nil, nil
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("%s: got %s for boot_code, want file", name, value.Type())
	}
	if file.Size() <= 0 {
		return nil, fmt.Errorf("%s: boot_code must not be empty", name)
	}
	if file.Size() > 64*1024 {
		return nil, fmt.Errorf("%s: boot_code is too large", name)
	}
	return starfile.ReadAll(file)
}

func CHSGeometry(value starlark.Value) (*vmm.CHSGeometry, error) {
	if value == starlark.None {
		return nil, nil
	}
	var values []starlark.Value
	switch value := value.(type) {
	case starlark.Tuple:
		values = []starlark.Value(value)
	case *starlark.List:
		values = make([]starlark.Value, value.Len())
		for index := range values {
			values[index] = value.Index(index)
		}
	default:
		return nil, fmt.Errorf("got %s, want a three-item tuple or list", value.Type())
	}
	if len(values) != 3 {
		return nil, fmt.Errorf("got %d values, want cylinders, heads, and sectors", len(values))
	}
	decoded := [3]int{}
	for index, item := range values {
		integer, err := starlark.AsInt32(item)
		if err != nil {
			return nil, fmt.Errorf("value %d is %s, want int", index, item.Type())
		}
		decoded[index] = integer
	}
	geometry := &vmm.CHSGeometry{Cylinders: decoded[0], Heads: decoded[1], Sectors: decoded[2]}
	if geometry.Cylinders < 1 || geometry.Cylinders > 1024 || geometry.Heads < 1 || geometry.Heads > 255 || geometry.Sectors < 1 || geometry.Sectors > 63 {
		return nil, fmt.Errorf("cylinders, heads, and sectors must be within 1..1024, 1..255, and 1..63")
	}
	return geometry, nil
}

func LegacyBIOSGeometry(totalSectors uint32) (heads, sectors uint32) {
	const sectorsPerTrack = uint32(63)
	for _, heads := range []uint32{16, 32, 64, 128} {
		if totalSectors <= 1024*heads*sectorsPerTrack {
			return heads, sectorsPerTrack
		}
	}
	return 255, sectorsPerTrack
}

func ReadBytesAt(file starfile.File, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 || offset > file.Size() || size > file.Size()-offset || size > int64(int(^uint(0)>>1)) {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, int(size))
	_, err := io.ReadFull(io.NewSectionReader(file, offset, size), data)
	return data, err
}

func StringList(list *starlark.List, name string) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	values := make([]string, 0, list.Len())
	iterator := list.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		text, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("%s: got %s, want string", name, value.Type())
		}
		values = append(values, text)
	}
	return values, nil
}

func CeilDiv(value, quantum int64) int64 {
	if value <= 0 {
		return 0
	}
	return (value + quantum - 1) / quantum
}
func Align(value, alignment int64) int64 { return CeilDiv(value, alignment) * alignment }

func ParseGUID(value string) ([16]byte, bool) { return windowsguid.Parse(value) }
func FormatGUID(value [16]byte) string        { return windowsguid.Format(value) }
func ZeroGUID(value [16]byte) bool            { return value == [16]byte{} }
