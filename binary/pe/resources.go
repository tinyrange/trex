package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"strings"
	"unicode/utf16"
)

// Resource is an immutable, bounded view of a PE resource. Path contains the
// type, name and language, with numeric IDs prefixed by '#'.
type Resource struct {
	Path string
	Data storage.Reader
}

// Resources enumerates a bounded resource tree without loading its payloads.
func Resources(file storage.Reader, maximum int) ([]Resource, error) {
	if file == nil || file.Size() < 0 || maximum <= 0 {
		return nil, fmt.Errorf("pe resources: invalid input or limit")
	}
	parsed, err := pe.NewFile(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, err
	}
	defer parsed.Close()
	var rva, size uint32
	switch h := parsed.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		rva, size = h.DataDirectory[2].VirtualAddress, h.DataDirectory[2].Size
	case *pe.OptionalHeader64:
		rva, size = h.DataDirectory[2].VirtualAddress, h.DataDirectory[2].Size
	}
	if rva == 0 || size < 16 {
		return nil, nil
	}
	base, err := rvaOffset(parsed, rva)
	if err != nil {
		return nil, err
	}
	if uint64(base)+uint64(size) > uint64(file.Size()) {
		return nil, fmt.Errorf("pe resources: directory outside image")
	}
	r := numericResourceReader{file: file, parsed: parsed, baseRVA: rva, baseOffset: base, directorySize: size}
	var result []Resource
	seen := map[uint32]bool{}
	budget := maximum * 4
	if budget/4 != maximum {
		return nil, fmt.Errorf("pe resources: excessive limit")
	}
	var walk func(uint32, []string) error
	walk = func(dir uint32, path []string) error {
		if len(path) >= 3 || seen[dir] {
			return fmt.Errorf("pe resources: deep or cyclic tree")
		}
		seen[dir] = true
		entries, err := r.entries(dir)
		if err != nil {
			return err
		}
		budget -= len(entries)
		if budget < 0 {
			return fmt.Errorf("pe resources: entry limit")
		}
		for _, e := range entries {
			name := fmt.Sprintf("#%d", e.name)
			if e.name&0x80000000 != 0 {
				at := e.name & 0x7fffffff
				if at > size-2 {
					return fmt.Errorf("pe resources: name outside directory")
				}
				var n [2]byte
				if _, err = file.ReadAt(n[:], int64(base)+int64(at)); err != nil {
					return err
				}
				count := uint32(binary.LittleEndian.Uint16(n[:]))
				if count > (size-at-2)/2 {
					return fmt.Errorf("pe resources: name outside directory")
				}
				b := make([]byte, count*2)
				if _, err = file.ReadAt(b, int64(base)+int64(at)+2); err != nil {
					return err
				}
				u := make([]uint16, count)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(b[i*2:])
				}
				name = string(utf16.Decode(u))
				name = strings.ReplaceAll(strings.ReplaceAll(name, "%", "%25"), "/", "%2F")
			}
			p := append(append([]string(nil), path...), name)
			if e.value&0x80000000 != 0 {
				if err := walk(e.value&0x7fffffff, p); err != nil {
					return err
				}
				continue
			}
			if e.value > size-16 || len(result) >= maximum {
				return fmt.Errorf("pe resources: data offset or entry limit")
			}
			var raw [16]byte
			if _, err = file.ReadAt(raw[:], int64(base)+int64(e.value)); err != nil {
				return err
			}
			rv, n := binary.LittleEndian.Uint32(raw[:]), binary.LittleEndian.Uint32(raw[4:])
			off, err := rvaOffset(parsed, rv)
			if err != nil {
				return err
			}
			valid := false
			for _, s := range parsed.Sections {
				if rv >= s.VirtualAddress && uint64(rv-s.VirtualAddress)+uint64(n) <= uint64(s.Size) {
					valid = true
					break
				}
			}
			if !valid || uint64(off)+uint64(n) > uint64(file.Size()) {
				return fmt.Errorf("pe resources: payload outside raw section")
			}
			result = append(result, Resource{Path: strings.Join(p, "/"), Data: io.NewSectionReader(file, int64(off), int64(n))})
		}
		return nil
	}
	if err := walk(0, nil); err != nil {
		return nil, err
	}
	return result, nil
}
