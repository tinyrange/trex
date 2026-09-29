package hfs

import (
	"fmt"
	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"unicode/utf16"
)

// HFS+ structures follow Apple's TN1150: 64-bit fork sizes, 32-bit allocation
// extents and UTF-16 catalog keys. Leaf enumeration avoids collation assumptions
// and works for both HFS+ and case-sensitive HFSX catalogs.
type plusExtent struct{ start, count uint32 }
type plusKey struct {
	id      uint32
	kind    byte
	logical uint32
}
type plusReader struct {
	file     starfile.File
	block    int64
	blocks   uint32
	overflow map[plusKey][]plusExtent
}

func plusExtents(b []byte) []plusExtent {
	out := make([]plusExtent, 8)
	for i := range out {
		out[i] = plusExtent{be.Uint32(b[i*8:]), be.Uint32(b[i*8+4:])}
	}
	return out
}
func (r *plusReader) fork(id uint32, kind byte, desc []byte) (starfile.File, error) {
	size := be.Uint64(desc)
	allocated := uint64(be.Uint32(desc[12:]))
	capacity := uint64(r.blocks) * uint64(r.block)
	if size > capacity || allocated > uint64(r.blocks) || size > allocated*uint64(r.block) {
		return nil, fmt.Errorf("hfs+: invalid fork size for %d", id)
	}
	records := plusExtents(desc[16:])
	logical := uint64(0)
	specs := []filesystem.ExtentSpec{}
	for {
		before := logical
		ended := false
		for _, e := range records {
			if e.count == 0 {
				ended = true
				continue
			}
			if ended || uint64(e.start)+uint64(e.count) > uint64(r.blocks) || logical+uint64(e.count) > allocated {
				return nil, fmt.Errorf("hfs+: invalid extent for %d", id)
			}
			offset := logical * uint64(r.block)
			length := uint64(e.count) * uint64(r.block)
			if offset < size {
				specs = append(specs, filesystem.ExtentSpec{Start: int64(offset), Size: int64(min(length, size-offset)), File: r.file, Offset: int64(e.start) * r.block})
			}
			logical += uint64(e.count)
		}
		if logical >= allocated {
			break
		}
		if logical == before || logical > uint64(^uint32(0)) {
			return nil, fmt.Errorf("hfs+: incomplete fork for %d", id)
		}
		var ok bool
		records, ok = r.overflow[plusKey{id, kind, uint32(logical)}]
		if !ok {
			return nil, fmt.Errorf("hfs+: missing overflow for %d/%d at %d", id, kind, logical)
		}
	}
	return filesystem.NewGeneratedImage(fmt.Sprintf("hfs+ fork %d/%d", id, kind), int64(size), specs), nil
}
func unicodeName(b []byte) ([]byte, error) {
	if len(b)%2 != 0 {
		return nil, fmt.Errorf("hfs+: odd UTF-16 name")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = be.Uint16(b[2*i:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return nil, fmt.Errorf("hfs+: invalid UTF-16 surrogate")
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return nil, fmt.Errorf("hfs+: unpaired UTF-16 surrogate")
		}
	}
	return []byte(string(utf16.Decode(u))), nil
}
func plusComponent(b []byte) string {
	var out strings.Builder
	for _, c := range string(b) {
		if c < 32 || c == '/' || c == '\\' || c == '%' || c == 127 {
			fmt.Fprintf(&out, "%%%02X", c)
		} else {
			out.WriteRune(c)
		}
	}
	s := out.String()
	if s == "." {
		return "%2E"
	}
	if s == ".." {
		return "%2E%2E"
	}
	return s
}
func openPlus(file starfile.File, maximum int) (*Volume, error) {
	var h [512]byte
	if _, err := starfile.ReadFullAt(file, h[:], 1024); err != nil {
		return nil, err
	}
	sig, version := be.Uint16(h[:]), be.Uint16(h[2:])
	if !((sig == 0x482b && version == 4) || (sig == 0x4858 && version == 5)) {
		return nil, fmt.Errorf("hfs+: invalid signature/version")
	}
	r := plusReader{file: file, block: int64(be.Uint32(h[40:])), blocks: be.Uint32(h[44:]), overflow: map[plusKey][]plusExtent{}}
	if r.block < 512 || r.block&(r.block-1) != 0 || r.blocks == 0 || int64(r.blocks) > file.Size()/r.block {
		return nil, fmt.Errorf("hfs+: invalid volume geometry")
	}
	overflow, err := r.fork(3, 0, h[192:272])
	if err != nil {
		return nil, err
	}
	if overflow.Size() > 0 {
		err = leafRecords(overflow, maximum*3, func(b []byte) error {
			if len(b) != 76 || be.Uint16(b) != 10 || (b[2] != 0 && b[2] != 255) {
				return fmt.Errorf("hfs+: invalid overflow record")
			}
			key := plusKey{be.Uint32(b[4:]), b[2], be.Uint32(b[8:])}
			if _, ok := r.overflow[key]; ok {
				return fmt.Errorf("hfs+: duplicate overflow key")
			}
			r.overflow[key] = plusExtents(b[12:])
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	catalog, err := r.fork(4, 0, h[272:352])
	if err != nil {
		return nil, err
	}
	v := &Volume{}
	ids := map[uint32]int{}
	err = leafRecords(catalog, maximum*3, func(b []byte) error {
		if len(b) < 10 {
			return fmt.Errorf("hfs+: truncated catalog key")
		}
		keySize := int(be.Uint16(b))
		n := int(be.Uint16(b[6:]))
		dataOffset := 2 + keySize
		if keySize != 6+2*n || n > 255 || dataOffset+2 > len(b) {
			return fmt.Errorf("hfs+: invalid catalog key")
		}
		data := b[dataOffset:]
		kind := be.Uint16(data)
		if kind == 3 || kind == 4 {
			if len(data) < 10 || int(be.Uint16(data[8:]))*2 > len(data)-10 {
				return fmt.Errorf("hfs+: truncated catalog thread")
			}
			return nil
		}
		if n == 0 || len(v.Entries) >= maximum {
			return fmt.Errorf("hfs+: empty name or entry limit")
		}
		name, err := unicodeName(b[8:dataOffset])
		if err != nil {
			return err
		}
		e := Entry{Name: name, Parent: be.Uint32(b[2:])}
		if (kind == 1 && len(data) < 88) || (kind == 2 && len(data) < 248) {
			return fmt.Errorf("hfs+: truncated catalog value")
		}
		if kind != 1 && kind != 2 {
			return fmt.Errorf("hfs+: unknown catalog kind %d", kind)
		}
		e.ID = be.Uint32(data[8:])
		e.Flags = be.Uint16(data[2:])
		e.Created = be.Uint32(data[12:])
		e.Modified = be.Uint32(data[16:])
		e.Backup = be.Uint32(data[28:])
		e.FinderInfo = append([]byte(nil), data[48:80]...)
		if kind == 1 {
			e.Kind = "directory"
		} else {
			e.Kind = "file"
			e.Data, err = r.fork(e.ID, 0, data[88:168])
			if err != nil {
				return err
			}
			e.Resource, err = r.fork(e.ID, 255, data[168:248])
			if err != nil {
				return err
			}
		}
		if _, ok := ids[e.ID]; ok {
			return fmt.Errorf("hfs+: duplicate catalog ID")
		}
		ids[e.ID] = len(v.Entries)
		v.Entries = append(v.Entries, e)
		if e.ID == 2 {
			v.Name = append([]byte(nil), name...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return finishPaths(v, ids, plusComponent)
}
