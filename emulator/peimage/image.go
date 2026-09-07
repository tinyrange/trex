// Package peimage constructs an in-memory PE image for an emulator. Both PE32
// and PE32+ retain their native pointer widths; no host loader is involved.
package peimage

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/emulator/cpu"
)

type Image struct {
	Architecture  cpu.Architecture
	PreferredBase uint64
	Base          uint64
	EntryRVA      uint32
	Data          []byte
	Directories   [16]pe.DataDirectory
}

// SectionData permits omitted raw-file alignment padding only when all bytes
// contributing to the section's virtual contents are available.
func SectionData(data []byte, section *pe.Section) ([]byte, error) {
	if section.Size == 0 {
		return nil, nil
	}
	start := uint64(section.Offset)
	if start > uint64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	available := min(uint64(section.Size), uint64(len(data))-start)
	required := uint64(section.Size)
	if section.VirtualSize != 0 {
		required = min(required, uint64(section.VirtualSize))
	}
	if available < required {
		return nil, io.ErrUnexpectedEOF
	}
	return data[start : start+available], nil
}

// Parse maps section bytes at RVAs but does not resolve imports or invoke code.
// The size budget is checked before allocating the virtual image.
func Parse(data []byte, memoryLimit uint64) (*Image, error) {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	image := &Image{}
	var imageSize, headerSize uint32
	switch optional := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if file.Machine != pe.IMAGE_FILE_MACHINE_I386 {
			return nil, fmt.Errorf("PE32 machine %#x is not i386", file.Machine)
		}
		image.Architecture = cpu.Architecture{Name: "x86", PointerSize: 4}
		image.PreferredBase = uint64(optional.ImageBase)
		image.EntryRVA = optional.AddressOfEntryPoint
		image.Directories = optional.DataDirectory
		imageSize, headerSize = optional.SizeOfImage, optional.SizeOfHeaders
	case *pe.OptionalHeader64:
		if file.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
			return nil, fmt.Errorf("PE32+ machine %#x is not AMD64", file.Machine)
		}
		image.Architecture = cpu.Architecture{Name: "amd64", PointerSize: 8}
		image.PreferredBase = optional.ImageBase
		image.EntryRVA = optional.AddressOfEntryPoint
		image.Directories = optional.DataDirectory
		imageSize, headerSize = optional.SizeOfImage, optional.SizeOfHeaders
	default:
		return nil, fmt.Errorf("PE image has no supported optional header")
	}
	if imageSize == 0 || uint64(imageSize) > memoryLimit || uint64(imageSize) > uint64(math.MaxInt) {
		return nil, fmt.Errorf("PE image size %d exceeds budget", imageSize)
	}
	if image.EntryRVA >= imageSize || uint64(headerSize) > uint64(len(data)) || headerSize > imageSize {
		return nil, fmt.Errorf("PE entry or headers exceed image bounds")
	}
	if image.PreferredBase > math.MaxUint64-uint64(imageSize-1) || (image.Architecture.PointerSize == 4 && image.PreferredBase+uint64(imageSize)-1 > math.MaxUint32) {
		return nil, fmt.Errorf("PE preferred image range overflows")
	}
	image.Data = make([]byte, int(imageSize))
	copy(image.Data, data[:headerSize])
	for _, section := range file.Sections {
		content, err := SectionData(data, section)
		if err != nil {
			return nil, fmt.Errorf("PE section %s: %w", section.Name, err)
		}
		start := uint64(section.VirtualAddress)
		if start+uint64(len(content)) > uint64(imageSize) || start+uint64(section.VirtualSize) > uint64(imageSize) {
			return nil, fmt.Errorf("PE section %s exceeds image bounds", section.Name)
		}
		copy(image.Data[start:], content)
	}
	image.Base = image.PreferredBase
	return image, nil
}

// Relocate applies HIGHLOW (i386) or DIR64 (AMD64) relocation entries. It
// validates every entry before modifying bytes, so malformed input is atomic.
func Relocate(mapped []byte, directory pe.DataDirectory, preferred, base uint64, pointerSize int) error {
	if pointerSize != 4 && pointerSize != 8 {
		return fmt.Errorf("PE: unsupported pointer size %d", pointerSize)
	}
	if len(mapped) == 0 || base > math.MaxUint64-uint64(len(mapped)-1) || (pointerSize == 4 && base+uint64(len(mapped)-1) > math.MaxUint32) {
		return fmt.Errorf("PE: relocated image range overflows")
	}
	if base == preferred {
		return nil
	}
	if directory.VirtualAddress == 0 || directory.Size < 8 {
		return fmt.Errorf("image at preferred base %#x cannot be relocated to %#x", preferred, base)
	}
	start, end := uint64(directory.VirtualAddress), uint64(directory.VirtualAddress)+uint64(directory.Size)
	if end > uint64(len(mapped)) {
		return fmt.Errorf("base relocation directory exceeds virtual image")
	}
	var targets []uint64
	for cursor := start; cursor < end; {
		if end-cursor < 8 {
			return fmt.Errorf("truncated base relocation block")
		}
		page := binary.LittleEndian.Uint32(mapped[cursor:])
		size := uint64(binary.LittleEndian.Uint32(mapped[cursor+4:]))
		if size < 8 || size > end-cursor || (size-8)%2 != 0 {
			return fmt.Errorf("invalid base relocation block size %d", size)
		}
		for pos := cursor + 8; pos < cursor+size; pos += 2 {
			entry := binary.LittleEndian.Uint16(mapped[pos:])
			kind := entry >> 12
			if kind == 0 {
				continue
			}
			if !(pointerSize == 4 && kind == 3 || pointerSize == 8 && kind == 10) {
				return fmt.Errorf("unsupported PE%d base relocation type %d", pointerSize*8, kind)
			}
			target := uint64(page) + uint64(entry&0xfff)
			if target+uint64(pointerSize) > uint64(len(mapped)) {
				return fmt.Errorf("base relocation target %#x exceeds virtual image", target)
			}
			targets = append(targets, target)
		}
		cursor += size
	}
	delta := base - preferred
	for _, target := range targets {
		if pointerSize == 8 {
			binary.LittleEndian.PutUint64(mapped[target:], binary.LittleEndian.Uint64(mapped[target:])+delta)
		} else {
			binary.LittleEndian.PutUint32(mapped[target:], binary.LittleEndian.Uint32(mapped[target:])+uint32(delta))
		}
	}
	return nil
}

func (i *Image) Rebase(base uint64) error {
	if err := Relocate(i.Data, i.Directories[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC], i.Base, base, i.Architecture.PointerSize); err != nil {
		return err
	}
	i.Base = base
	return nil
}
