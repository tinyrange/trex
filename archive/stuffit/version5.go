package stuffit

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/archive/arsenic"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Layout and CRC coverage were established by independent Starlark probes of
// the original StuffIt5 media. No installer or self-extractor code runs.
func check5CRC(b []byte, at int) bool {
	want := binary.BigEndian.Uint16(b[at:])
	x, y := b[at], b[at+1]
	b[at], b[at+1] = 0, 0
	got := crc16(b)
	b[at], b[at+1] = x, y
	return got == want
}
func open5(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	be := binary.BigEndian
	read := func(offset int64, length int) ([]byte, error) {
		if offset < 0 || int64(length) > file.Size()-offset {
			return nil, fmt.Errorf("stuffit5: record outside archive")
		}
		b := make([]byte, length)
		_, err := starfile.ReadFullAt(file, b, offset)
		return b, err
	}
	h, err := read(0, 114)
	if err != nil {
		return nil, err
	}
	if h[82] != 5 || h[80] != 0x1a || int64(be.Uint32(h[84:])) != file.Size() || !check5CRC(h, 98) {
		return nil, fmt.Errorf("stuffit5: invalid archive header")
	}
	offset := int64(be.Uint32(h[88:]))
	if offset != 114 || be.Uint32(h[94:]) != uint32(offset) {
		return nil, fmt.Errorf("stuffit5: unsupported catalog placement")
	}
	a := &Archive{Version: 5, Signature: "StuffIt5", DeclaredCount: int(be.Uint16(h[92:])), RootCountVerified: true}
	type directory struct {
		offset         uint32
		path           string
		children, want int
	}
	stack := []directory{{}}
	seen := map[string]bool{}
	previous := uint32(0)
	remaining := maximumBytes
	for records := 0; offset < file.Size(); records++ {
		if int64(records) >= int64(maximumEntries)*2 {
			return nil, fmt.Errorf("stuffit5: record limit")
		}
		start := offset
		b, err := read(offset, 48)
		if err != nil {
			return nil, err
		}
		length := int(be.Uint16(b[6:]))
		namesize := int(be.Uint16(b[30:]))
		if be.Uint32(b) != 0xa5a5a5a5 || b[4] != 1 || b[5] != 0 || length != 48+namesize {
			return nil, fmt.Errorf("stuffit5: unsupported record header")
		}
		b, err = read(offset, length)
		if err != nil {
			return nil, err
		}
		if !check5CRC(b, 32) || be.Uint32(b[18:]) != previous {
			return nil, fmt.Errorf("stuffit5: record CRC or previous link mismatch")
		}
		previous = uint32(start)
		offset += int64(length)
		flags := be.Uint16(b[8:])
		parent := &stack[len(stack)-1]
		if flags & ^uint16(0x50) != 0 || be.Uint32(b[26:]) != parent.offset {
			return nil, fmt.Errorf("stuffit5: unsupported flags or parent link")
		}
		if flags&0x40 != 0 && namesize == 0 {
			if len(stack) == 1 || be.Uint32(b[34:]) != 0xffffffff || parent.children != parent.want {
				return nil, fmt.Errorf("stuffit5: invalid directory end/count")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if namesize == 0 || len(a.Entries) >= maximumEntries {
			return nil, fmt.Errorf("stuffit5: empty name or entry limit")
		}
		e := Entry{Name: append([]byte(nil), b[48:]...), Directory: flags&0x40 != 0, Created: be.Uint32(b[10:]), Modified: be.Uint32(b[14:]), Occurrence: 1}
		e.Path = parent.path + "/" + component(e.Name)
		if seen[e.Path] {
			return nil, fmt.Errorf("stuffit5: duplicate path")
		}
		seen[e.Path] = true
		parent.children++
		meta, err := read(offset, 36)
		if err != nil {
			return nil, err
		}
		metaFlags := be.Uint16(meta)
		if metaFlags & ^uint16(1) != 0 {
			return nil, fmt.Errorf("stuffit5: unsupported metadata flags")
		}
		if metaFlags&1 != 0 {
			meta, err = read(offset, 50)
			if err != nil {
				return nil, err
			}
		}
		if !check5CRC(meta, 2) {
			return nil, fmt.Errorf("stuffit5: metadata CRC mismatch")
		}
		offset += int64(len(meta))
		if e.Directory {
			if metaFlags != 0 || int64(be.Uint32(b[34:])) != offset {
				return nil, fmt.Errorf("stuffit5: directory child pointer")
			}
			stack = append(stack, directory{offset: uint32(start), path: e.Path, want: int(be.Uint16(b[46:]))})
		} else {
			copy(e.Type[:], meta[4:8])
			copy(e.Creator[:], meta[8:12])
			e.FinderFlags = be.Uint16(meta[12:])
			e.DeclaredSizes[1] = be.Uint32(b[34:])
			e.Methods[1] = b[46]
			stored := [2]uint32{0, be.Uint32(b[38:])}
			if b[47] != 0 {
				return nil, fmt.Errorf("stuffit5: unsupported fork flags")
			}
			if metaFlags&1 != 0 {
				e.DeclaredSizes[0] = be.Uint32(meta[36:])
				stored[0] = be.Uint32(meta[40:])
				e.Methods[0] = meta[48]
				if meta[49] != 0 {
					return nil, fmt.Errorf("stuffit5: unsupported resource flags")
				}
			}
			for i := 0; i < 2; i++ {
				size, n := int64(e.DeclaredSizes[i]), int64(stored[i])
				if size > remaining || n > maximumBytes || n > file.Size()-offset || int64(int(size)) != size {
					return nil, fmt.Errorf("stuffit5: fork size limit")
				}
				view := &starfile.Slice{Base: file, Offset: offset, Length: n}
				offset += n
				var decoded []byte
				if n != 0 || size != 0 {
					if e.Methods[i] != 15 {
						return nil, fmt.Errorf("stuffit5: unsupported fork method %d", e.Methods[i])
					}
					input, err := starfile.ReadAll(view)
					if err != nil {
						return nil, err
					}
					decoded, err = arsenic.Decode(input, int(size), 16<<20)
					if err != nil {
						return nil, err
					}
					if int64(len(decoded)) != size {
						return nil, fmt.Errorf("stuffit5: decoded fork length mismatch")
					}
				}
				value := &starfile.Bytes{Name: e.Path, Data: decoded}
				if i == 0 {
					e.Resource, e.StoredResource = value, view
				} else {
					e.Data, e.StoredData = value, view
				}
				remaining -= size
			}
			if int64(be.Uint32(b[22:])) != offset {
				return nil, fmt.Errorf("stuffit5: next file link mismatch")
			}
		}
		a.Entries = append(a.Entries, e)
	}
	if len(stack) != 1 || stack[0].children != a.DeclaredCount {
		return nil, fmt.Errorf("stuffit5: root count or directory nesting mismatch")
	}
	a.TopLevelCount = stack[0].children
	return a, nil
}
