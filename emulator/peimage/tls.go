package peimage

import (
	"encoding/binary"
	"fmt"
)

// TLS is the loader's native-width static TLS declaration. The template is
// copied, so consumers cannot mutate the mapped PE through the returned slice.
type TLS struct {
	IndexAddress uint64
	Template     []byte
	ZeroFill     uint32
	Callbacks    []uint64
}

func (image *Image) TLS() (TLS, error) {
	var result TLS
	directory := image.Directories[9]
	if directory.VirtualAddress == 0 && directory.Size == 0 {
		return result, nil
	}
	width := image.Architecture.PointerSize
	size := width*4 + 8
	if (width != 4 && width != 8) || directory.Size < uint32(size) || uint64(directory.VirtualAddress)+uint64(directory.Size) > uint64(len(image.Data)) {
		return result, fmt.Errorf("PE: invalid TLS directory")
	}
	readPointer := func(data []byte) uint64 {
		if width == 4 {
			return uint64(binary.LittleEndian.Uint32(data))
		}
		return binary.LittleEndian.Uint64(data)
	}
	data := image.Data[directory.VirtualAddress:]
	start, end := readPointer(data), readPointer(data[width:])
	result.IndexAddress = readPointer(data[2*width:])
	callbacks := readPointer(data[3*width:])
	result.ZeroFill = binary.LittleEndian.Uint32(data[4*width:])
	span := func(address, length uint64) ([]byte, error) {
		if address < image.Base || address-image.Base > uint64(len(image.Data)) || length > uint64(len(image.Data))-(address-image.Base) {
			return nil, fmt.Errorf("PE: TLS range outside image at %#x", address)
		}
		return image.Data[address-image.Base : address-image.Base+length], nil
	}
	if start != 0 || end != 0 {
		if end < start {
			return TLS{}, fmt.Errorf("PE: reversed TLS template range")
		}
		template, err := span(start, end-start)
		if err != nil {
			return TLS{}, err
		}
		result.Template = append([]byte(nil), template...)
	}
	if result.IndexAddress != 0 {
		if _, err := span(result.IndexAddress, 4); err != nil {
			return TLS{}, err
		}
	}
	if callbacks != 0 {
		for count := 0; count <= 1024; count++ {
			value, err := span(callbacks, uint64(width))
			if err != nil {
				return TLS{}, err
			}
			callback := readPointer(value)
			if callback == 0 {
				return result, nil
			}
			if count == 1024 {
				return TLS{}, fmt.Errorf("PE: TLS callback list exceeds limit")
			}
			result.Callbacks = append(result.Callbacks, callback)
			if callbacks > ^uint64(0)-uint64(width) {
				return TLS{}, fmt.Errorf("PE: TLS callback pointer overflows")
			}
			callbacks += uint64(width)
		}
	}
	return result, nil
}
