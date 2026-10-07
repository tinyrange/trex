// Package macho provides bounded, read-only inspection of 64-bit Mach-O images.
// Segment contents are borrowed storage views; this is not a linker or loader.
package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

const AMD64 uint32 = 0x01000007
const maxCommands = 1 << 20
const maxSymbols = 1 << 20
const maxStrings = 64 << 20

type Segment struct {
	Name                            string
	Address, Size, Offset, FileSize uint64
	Flags                           uint32
	Data                            storage.Reader
}
type Symbol struct {
	Name          string
	Address       uint64
	Type, Section byte
	Description   uint16
}
type Image struct {
	CPU, Type uint32
	Source    storage.Reader
	Segments  []Segment
	Symbols   []Symbol
}
type view struct {
	storage.Reader
	offset, size int64
}

func (v view) Size() int64 { return v.size }
func (v view) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("macho: negative read offset")
	}
	if off >= v.size {
		return 0, io.EOF
	}
	size := len(b)
	if int64(size) > v.size-off {
		b = b[:v.size-off]
	}
	n, err := v.Reader.ReadAt(b, v.offset+off)
	if n < size && err == nil {
		err = io.EOF
	}
	return n, err
}
func read(r storage.Reader, off, size uint64) ([]byte, error) {
	if off > uint64(r.Size()) || size > uint64(r.Size())-off {
		return nil, fmt.Errorf("macho: range outside image")
	}
	b := make([]byte, size)
	_, err := io.ReadFull(io.NewSectionReader(r, int64(off), int64(size)), b)
	return b, err
}
func span(r storage.Reader, off, size uint64) (storage.Reader, error) {
	if off > uint64(r.Size()) || size > uint64(r.Size())-off {
		return nil, fmt.Errorf("macho: range outside image")
	}
	return view{r, int64(off), int64(size)}, nil
}

// Open selects the requested CPU from a universal image, or validates a thin
// image of that CPU. It accepts little-endian 64-bit images and fat32/fat64
// big-endian containers. Load commands and symbol allocations are bounded.
func Open(r storage.Reader, cpu uint32) (*Image, error) {
	if r == nil || r.Size() < 32 {
		return nil, fmt.Errorf("macho: truncated header")
	}
	h, err := read(r, 0, 32)
	if err != nil {
		return nil, err
	}
	magic := binary.BigEndian.Uint32(h)
	if magic == 0xcafebabe || magic == 0xcafebabf {
		count := binary.BigEndian.Uint32(h[4:])
		width := uint64(20)
		if magic == 0xcafebabf {
			width = 32
		}
		if count == 0 || count > 64 {
			return nil, fmt.Errorf("macho: invalid architecture count")
		}
		table, err := read(r, 8, uint64(count)*width)
		if err != nil {
			return nil, err
		}
		var selected storage.Reader
		for i := uint32(0); i < count; i++ {
			a := table[uint64(i)*width:]
			off, size := uint64(binary.BigEndian.Uint32(a[8:])), uint64(binary.BigEndian.Uint32(a[12:]))
			align := binary.BigEndian.Uint32(a[16:])
			if width == 32 {
				off, size = binary.BigEndian.Uint64(a[8:]), binary.BigEndian.Uint64(a[16:])
				align = binary.BigEndian.Uint32(a[24:])
			}
			if align > 63 || off < 8+uint64(count)*width || off&((uint64(1)<<align)-1) != 0 {
				return nil, fmt.Errorf("macho: invalid architecture extent")
			}
			v, err := span(r, off, size)
			if err != nil {
				return nil, err
			}
			if binary.BigEndian.Uint32(a) == cpu {
				if selected != nil {
					return nil, fmt.Errorf("macho: duplicate architecture")
				}
				selected = v
			}
		}
		if selected == nil {
			return nil, fmt.Errorf("macho: CPU not present")
		}
		r = selected
		h, err = read(r, 0, 32)
		if err != nil {
			return nil, err
		}
	}
	u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	if u32(h) != 0xfeedfacf || u32(h[4:]) != cpu {
		return nil, fmt.Errorf("macho: expected selected little-endian 64-bit CPU")
	}
	count, size := u32(h[16:]), u32(h[20:])
	if count > 4096 || size > maxCommands || uint64(count)*8 > uint64(size) {
		return nil, fmt.Errorf("macho: invalid load command bounds")
	}
	commands, err := read(r, 32, uint64(size))
	if err != nil {
		return nil, err
	}
	image := &Image{CPU: cpu, Type: u32(h[12:]), Source: r}
	var symtab []byte
	for i := uint32(0); i < count; i++ {
		if len(commands) < 8 {
			return nil, fmt.Errorf("macho: truncated command")
		}
		kind, length := u32(commands), u32(commands[4:])
		if length < 8 || length%8 != 0 || uint64(length) > uint64(len(commands)) {
			return nil, fmt.Errorf("macho: invalid command length")
		}
		c := commands[:length]
		commands = commands[length:]
		switch kind {
		case 0x19:
			if length < 72 || uint64(u32(c[64:]))*80+72 != uint64(length) {
				return nil, fmt.Errorf("macho: invalid segment command")
			}
			s := Segment{Name: string(bytes.TrimRight(c[8:24], "\x00")), Address: u64(c[24:]), Size: u64(c[32:]), Offset: u64(c[40:]), FileSize: u64(c[48:]), Flags: u32(c[68:])}
			if s.Size > ^uint64(0)-s.Address {
				return nil, fmt.Errorf("macho: wrapping virtual segment")
			}
			// Zero-VM-size metadata segments (e.g. __CTF) may still have file data.
			s.Data, err = span(r, s.Offset, s.FileSize)
			if err != nil {
				return nil, err
			}
			image.Segments = append(image.Segments, s)
		case 2:
			if length != 24 || symtab != nil {
				return nil, fmt.Errorf("macho: invalid symbol command")
			}
			symtab = c
		}
	}
	if len(commands) != 0 {
		return nil, fmt.Errorf("macho: unconsumed load commands")
	}
	if symtab != nil {
		count, stringsSize := u32(symtab[12:]), u32(symtab[20:])
		if count > maxSymbols || stringsSize > maxStrings {
			return nil, fmt.Errorf("macho: symbol resource limit")
		}
		symbols, err := read(r, uint64(u32(symtab[8:])), uint64(count)*16)
		if err != nil {
			return nil, err
		}
		strings, err := read(r, uint64(u32(symtab[16:])), uint64(stringsSize))
		if err != nil {
			return nil, err
		}
		// Duplicate string indices share a single name allocation. Distinct
		// overlapping suffixes must not amplify a bounded table into unbounded
		// copied names (or repeatedly scan a huge duplicate name).
		names := map[uint32]string{}
		nameBytes := 0
		for i := uint32(0); i < count; i++ {
			s := symbols[i*16 : (i+1)*16]
			index := u32(s)
			if index >= stringsSize {
				return nil, fmt.Errorf("macho: symbol name outside string table")
			}
			name, exists := names[index]
			if !exists {
				end := bytes.IndexByte(strings[index:], 0)
				if end < 0 {
					return nil, fmt.Errorf("macho: unterminated symbol name")
				}
				if end > maxStrings-nameBytes {
					return nil, fmt.Errorf("macho: aggregate symbol name resource limit")
				}
				nameBytes += end
				name = string(strings[index : uint64(index)+uint64(end)])
				names[index] = name
			}
			image.Symbols = append(image.Symbols, Symbol{name, u64(s[8:]), s[4], s[5], binary.LittleEndian.Uint16(s[6:])})
		}
	}
	return image, nil
}

// At returns a borrowed view of file-backed virtual bytes. It does not fabricate
// zero-fill contents, perform relocations, or resolve overlapping segments.
func (i *Image) At(address, size uint64) (storage.Reader, error) {
	if size > ^uint64(0)-address {
		return nil, fmt.Errorf("macho: wrapping address range")
	}
	var found storage.Reader
	for _, s := range i.Segments {
		if address < s.Address || address-s.Address > s.FileSize || size > s.FileSize-(address-s.Address) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("macho: ambiguous virtual range")
		}
		var err error
		found, err = span(s.Data, address-s.Address, size)
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, fmt.Errorf("macho: range not file-backed")
	}
	return found, nil
}
