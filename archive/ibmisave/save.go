// Package ibmisave reads IBM i optical save-stream descriptors and stored sections.
package ibmisave

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
)

const pageSize = 4096

var descriptor = []byte{0xd3, 0x61, 0xc4, 0x40, 0xd6, 0xc2, 0xd1, 0xc5, 0xc3, 0xe3, 0x40, 0xc4, 0xc5, 0xe2, 0xc3, 0xd9, 0xc9, 0xd7, 0xe3, 0xd6, 0xd9, 0x40, 0x40, 0x40}
var catalogName = []byte{0xd8, 0xe2, 0xd9, 0xc4, 0xe2, 0xe2, 0xd7, 0xc3, 0x4b, 0xf1}

type Section struct {
	LogicalSize uint32
	Address     uint64
	Data        starfile.File
}
type Object struct {
	Name                         string
	RawName                      []byte
	Group                        int
	Offset                       int64
	Type, Release, TargetRelease uint16
	DeclaredDataBlocks           uint32
	Header, Data, Trailer        starfile.File
	Sections                     []Section
}
type Archive struct {
	Objects []Object
	Padding []starfile.File
	Groups  int
}

// Names use the invariant EBCDIC identifier alphabet. Unrecognized bytes are
// escaped, not silently mapped through an assumed national CCSID.
func identifier(raw []byte) string {
	raw = bytes.TrimRight(raw, "\x40\x00")
	var b strings.Builder
	for _, c := range raw {
		switch {
		case c >= 0xc1 && c <= 0xc9:
			b.WriteByte('A' + c - 0xc1)
		case c >= 0xd1 && c <= 0xd9:
			b.WriteByte('J' + c - 0xd1)
		case c >= 0xe2 && c <= 0xe9:
			b.WriteByte('S' + c - 0xe2)
		case c >= 0x81 && c <= 0x89:
			b.WriteByte('a' + c - 0x81)
		case c >= 0x91 && c <= 0x99:
			b.WriteByte('j' + c - 0x91)
		case c >= 0xa2 && c <= 0xa9:
			b.WriteByte('s' + c - 0xa2)
		case c >= 0xf0 && c <= 0xf9:
			b.WriteByte('0' + c - 0xf0)
		case c == 0x4b:
			b.WriteByte('.')
		case c == 0x60:
			b.WriteByte('-')
		case c == 0x6d:
			b.WriteByte('_')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// Open checks descriptor framing and section extents, never restoring objects
// or materializing their bodies. This is the 4096-byte optical descriptor form,
// not the 528-byte checksummed transport used by standalone SAVF files.
func Open(file starfile.File, maximum int) (*Archive, error) {
	if maximum < 1 || file.Size() < pageSize || file.Size()%pageSize != 0 {
		return nil, fmt.Errorf("ibmi_save: invalid optical stream size or limit")
	}
	a := &Archive{}
	be := binary.BigEndian
	view := func(off, n int64) starfile.File { return &starfile.Slice{Base: file, Offset: off, Length: n} }
	var h [pageSize]byte
	needCatalog := true
	sections := 0
	for off := int64(0); off < file.Size(); {
		if _, err := starfile.ReadFullAt(file, h[:], off); err != nil {
			return nil, err
		}
		if h[0] == 0x40 {
			if len(a.Padding) >= maximum {
				return nil, fmt.Errorf("ibmi_save: padding limit")
			}
			if !bytes.Equal(h[:], bytes.Repeat([]byte{0x40}, pageSize)) {
				return nil, fmt.Errorf("ibmi_save: invalid padding at %d", off)
			}
			a.Padding = append(a.Padding, view(off, pageSize))
			off += pageSize
			needCatalog = true
			continue
		}
		if be.Uint32(h[:]) != 0xffffffff || !bytes.Equal(h[0x96:0xae], descriptor) {
			return nil, fmt.Errorf("ibmi_save: invalid descriptor at %d", off)
		}
		if needCatalog {
			if !bytes.HasPrefix(h[4:34], catalogName) || be.Uint16(h[34:]) != 0x19db {
				return nil, fmt.Errorf("ibmi_save: expected save-group catalog at %d", off)
			}
			a.Groups++
			needCatalog = false
		}
		if len(a.Objects) >= maximum {
			return nil, fmt.Errorf("ibmi_save: object limit")
		}
		// Only the independently inspected release layout is selected here.
		if be.Uint16(h[0x52:]) != 0x4705 || be.Uint16(h[0x54:]) != 0x4705 {
			return nil, fmt.Errorf("ibmi_save: unsupported descriptor release at %d", off)
		}
		blocks := int64(be.Uint32(h[0xcc:]))
		length := blocks * 512
		if length < pageSize || length%pageSize != 0 || length > file.Size()-off {
			return nil, fmt.Errorf("ibmi_save: object extent outside stream at %d", off)
		}
		count := int64(be.Uint32(h[0x64:]))
		table := int64(be.Uint64(h[0x108:])&0xffffff) - pageSize
		if count < 1 || count > int64(maximum-sections) || table < 0x280 || table > pageSize || count*16 > pageSize-table {
			return nil, fmt.Errorf("ibmi_save: invalid section table at %d", off)
		}
		obj := Object{Name: identifier(h[4:34]), RawName: bytes.Clone(h[4:34]), Group: a.Groups, Offset: off, Type: be.Uint16(h[34:]), Release: be.Uint16(h[0x52:]), TargetRelease: be.Uint16(h[0x54:]), DeclaredDataBlocks: be.Uint32(h[0xd4:]), Header: view(off, pageSize), Data: view(off+pageSize, length-pageSize)}
		pos := int64(pageSize)
		for j := int64(0); j < count; j++ {
			row := h[table+j*16 : table+(j+1)*16]
			n := int64(be.Uint32(row[4:]))
			logical := be.Uint32(row)
			if n%pageSize != 0 || n > length-pos || uint64(n) > uint64(logical) {
				return nil, fmt.Errorf("ibmi_save: invalid section extent at %d", off)
			}
			obj.Sections = append(obj.Sections, Section{LogicalSize: logical, Address: be.Uint64(row[8:]), Data: view(off+pos, n)})
			pos += n
		}
		// Some original optical objects carry additional page-aligned bytes
		// outside their section table. Preserve these without interpreting them.
		obj.Trailer = view(off+pos, length-pos)
		sections += int(count)
		a.Objects = append(a.Objects, obj)
		off += length
	}
	if len(a.Objects) == 0 {
		return nil, fmt.Errorf("ibmi_save: no objects")
	}
	return a, nil
}
