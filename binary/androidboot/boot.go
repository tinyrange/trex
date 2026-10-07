// Package androidboot reads Android boot and vendor_boot headers v3/v4.
// Layout follows AOSP system/tools/mkbootimg/include/bootimg/bootimg.h.
// Sections are borrowed portable files; this reader does not verify AVB.
package androidboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

type Section struct {
	Name         string
	Offset, Size int64
	Data         storage.Reader
}
type Fragment struct {
	Name    string
	Type    uint32
	BoardID [16]uint32
	Section Section
}
type Image struct {
	Kind, Name, CommandLine      string
	Version, PageSize, OSVersion uint32
	Sections                     []Section
	Fragments                    []Fragment
}

var le = binary.LittleEndian

func text(b []byte) string {
	if at := bytes.IndexByte(b, 0); at >= 0 {
		b = b[:at]
	}
	return string(b)
}
func read(s storage.Reader, off, size int64) ([]byte, error) {
	if off < 0 || size < 0 || size > s.Size()-off {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, size)
	_, err := io.ReadFull(io.NewSectionReader(s, off, size), b)
	return b, err
}

func Open(source storage.Reader) (*Image, error) {
	if source == nil || source.Size() < 44 {
		return nil, fmt.Errorf("android boot: truncated header")
	}
	h, err := read(source, 0, 44)
	if err != nil {
		return nil, err
	}
	i := &Image{}
	var headerSize, expected uint32
	switch string(h[:8]) {
	case "ANDROID!":
		i.Kind = "boot"
		i.Version = le.Uint32(h[40:])
		i.PageSize = 4096
		i.OSVersion = le.Uint32(h[16:])
		headerSize = le.Uint32(h[20:])
		expected = 1580
		if i.Version == 4 {
			expected = 1584
		}
	case "VNDRBOOT":
		i.Kind = "vendor_boot"
		i.Version = le.Uint32(h[8:])
		i.PageSize = le.Uint32(h[12:])
		expected = 2112
		if i.Version == 4 {
			expected = 2128
		}
	default:
		return nil, fmt.Errorf("android boot: invalid magic")
	}
	if i.Version != 3 && i.Version != 4 {
		return nil, fmt.Errorf("android boot: unsupported %s version %d", i.Kind, i.Version)
	}
	if i.PageSize < 512 || i.PageSize > 65536 || i.PageSize&(i.PageSize-1) != 0 {
		return nil, fmt.Errorf("android boot: invalid page size")
	}
	h, err = read(source, 0, int64(expected))
	if err != nil {
		return nil, err
	}
	if i.Kind == "vendor_boot" {
		headerSize = le.Uint32(h[2096:])
		i.Name = text(h[2080:2096])
		i.CommandLine = text(h[28:2076])
	} else {
		i.CommandLine = text(h[44:1580])
	}
	if headerSize != expected {
		return nil, fmt.Errorf("android boot: invalid header size %d", headerSize)
	}
	position := storage.Align(int64(headerSize), int64(i.PageSize))
	add := func(name string, size uint32) error {
		if position > source.Size() || int64(size) > source.Size()-position {
			return fmt.Errorf("android boot: %s exceeds input", name)
		}
		i.Sections = append(i.Sections, Section{name, position, int64(size), io.NewSectionReader(source, position, int64(size))})
		position += storage.Align(int64(size), int64(i.PageSize))
		return nil
	}
	if i.Kind == "boot" {
		if err := add("kernel", le.Uint32(h[8:])); err != nil {
			return nil, err
		}
		if err := add("ramdisk", le.Uint32(h[12:])); err != nil {
			return nil, err
		}
		if i.Version == 4 {
			if err := add("signature", le.Uint32(h[1580:])); err != nil {
				return nil, err
			}
		}
	} else {
		if err := add("ramdisk", le.Uint32(h[24:])); err != nil {
			return nil, err
		}
		if err := add("dtb", le.Uint32(h[2100:])); err != nil {
			return nil, err
		}
		if i.Version == 4 {
			ts, count, stride := le.Uint32(h[2112:]), le.Uint32(h[2116:]), le.Uint32(h[2120:])
			if ts > 16<<20 || stride < 108 || uint64(count)*uint64(stride) != uint64(ts) {
				return nil, fmt.Errorf("android boot: invalid ramdisk table geometry")
			}
			if err := add("ramdisk_table", ts); err != nil {
				return nil, err
			}
			if err := add("bootconfig", le.Uint32(h[2124:])); err != nil {
				return nil, err
			}
			table, err := read(source, i.Sections[2].Offset, int64(ts))
			if err != nil {
				return nil, err
			}
			seen := map[string]bool{}
			for index := uint32(0); index < count; index++ {
				row := table[index*stride : (index+1)*stride]
				size, off := int64(le.Uint32(row)), int64(le.Uint32(row[4:]))
				f := Fragment{Name: text(row[12:44]), Type: le.Uint32(row[8:])}
				if off > i.Sections[0].Size || size > i.Sections[0].Size-off || seen[f.Name] {
					return nil, fmt.Errorf("android boot: invalid ramdisk fragment")
				}
				seen[f.Name] = true
				for j := range f.BoardID {
					f.BoardID[j] = le.Uint32(row[44+j*4:])
				}
				f.Section = Section{f.Name, i.Sections[0].Offset + off, size, io.NewSectionReader(source, i.Sections[0].Offset+off, size)}
				i.Fragments = append(i.Fragments, f)
			}
		}
	}
	return i, nil
}
