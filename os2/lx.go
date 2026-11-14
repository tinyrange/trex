package os2

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// LXObject contains an unrelocated object image. It is not executable state.
type LXObject struct {
	Base, Flags uint32
	Data        []byte
}
type LXResource struct {
	Type, ID, Object uint16
	Offset, Size     uint32
}
type LXImage struct {
	Objects   []LXObject
	Resources []LXResource
}

// DecodeLX validates all tables and expands bounded LX object pages without
// applying fixups, resolving imports, or executing module initialization.
func DecodeLX(data []byte, maximum uint64) (*LXImage, error) {
	bad := func(s string) (*LXImage, error) { return nil, fmt.Errorf("LX: %s", s) }
	span := func(o, n uint64) bool { return o <= uint64(len(data)) && n <= uint64(len(data))-o }
	var h uint64
	if len(data) >= 64 && string(data[:2]) == "MZ" {
		h = uint64(binary.LittleEndian.Uint32(data[60:]))
	}
	if !span(h, 0xac) || string(data[h:h+2]) != "LX" {
		return bad("missing/truncated header")
	}
	u32 := func(o uint64) uint64 { return uint64(binary.LittleEndian.Uint32(data[h+o:])) }
	if data[h+2] != 0 || data[h+3] != 0 || u32(4) != 0 {
		return bad("unsupported byte order/version")
	}
	pages, pageSize, shift := u32(0x14), u32(0x28), u32(0x2c)
	if maximum == 0 || pageSize != 4096 || shift > 31 {
		return bad("unsupported geometry or expansion limit")
	}
	ot, count, pt := h+u32(0x40), u32(0x44), h+u32(0x48)
	rt, rc := h+u32(0x50), u32(0x54)
	if count > 65535 || rc > 1<<20 || !span(ot, count*24) || !span(pt, pages*8) || !span(rt, rc*14) {
		return bad("table bounds")
	}
	img := &LXImage{}
	var total uint64
	for i := uint64(0); i < count; i++ {
		row := data[ot+i*24 : ot+(i+1)*24]
		size := uint64(binary.LittleEndian.Uint32(row))
		first, n := uint64(binary.LittleEndian.Uint32(row[12:])), uint64(binary.LittleEndian.Uint32(row[16:]))
		if size > uint64(^uint(0)>>1) || size > maximum-total || (n != 0 && (first == 0 || first-1 > pages || n > pages-(first-1))) || n > (size+pageSize-1)/pageSize {
			return bad("object size/page bounds")
		}
		total += size
		obj := LXObject{Base: binary.LittleEndian.Uint32(row[4:]), Flags: binary.LittleEndian.Uint32(row[8:]), Data: make([]byte, int(size))}
		for j := uint64(0); j < n; j++ {
			p := data[pt+(first-1+j)*8 : pt+(first+j)*8]
			off := u32(0x80) + (uint64(binary.LittleEndian.Uint32(p)) << shift)
			length := uint64(binary.LittleEndian.Uint16(p[4:]))
			flag := binary.LittleEndian.Uint16(p[6:])
			start := j * pageSize
			end := start + pageSize
			if end > size {
				end = size
			}
			dest := obj.Data[start:end]
			if flag == 3 {
				continue
			}
			if !span(off, length) {
				return bad("page data bounds")
			}
			packed := data[off : off+length]
			var expanded []byte
			var err error
			switch flag {
			case 0:
				if length > pageSize {
					return bad("raw page too large")
				}
				expanded = packed
			case 1:
				expanded, err = expandLXIterated(packed, int(pageSize))
			case 5:
				expanded, err = expandLXPack2(packed, int(pageSize))
			default:
				return bad(fmt.Sprintf("unsupported page type %d", flag))
			}
			if err != nil {
				return bad(fmt.Sprintf("object %d page %d: %v", i+1, j, err))
			}
			copy(dest, expanded)
		}
		img.Objects = append(img.Objects, obj)
	}
	for i := uint64(0); i < rc; i++ {
		r := data[rt+i*14 : rt+(i+1)*14]
		v := LXResource{Type: binary.LittleEndian.Uint16(r), ID: binary.LittleEndian.Uint16(r[2:]), Size: binary.LittleEndian.Uint32(r[4:]), Object: binary.LittleEndian.Uint16(r[8:]), Offset: binary.LittleEndian.Uint32(r[10:])}
		if v.Object == 0 || int(v.Object) > len(img.Objects) {
			return bad("resource object index")
		}
		d := img.Objects[v.Object-1].Data
		if uint64(v.Offset)+uint64(v.Size) > uint64(len(d)) {
			return bad("resource bounds")
		}
		img.Resources = append(img.Resources, v)
	}
	return img, nil
}

func expandLXIterated(src []byte, limit int) ([]byte, error) {
	out := make([]byte, 0, limit)
	for len(src) > 0 {
		if len(src) < 4 {
			return nil, fmt.Errorf("truncated iterated record")
		}
		count, n := int(binary.LittleEndian.Uint16(src)), int(binary.LittleEndian.Uint16(src[2:]))
		src = src[4:]
		if n > len(src) || count*n > limit-len(out) {
			return nil, fmt.Errorf("iterated bounds")
		}
		for i := 0; i < count; i++ {
			out = append(out, src[:n]...)
		}
		src = src[n:]
	}
	return out, nil
}

// EXEPACK2 commands have two low tag bits. Match distances are relative to
// output after each command's literal prefix, and overlapping copies advance
// byte-by-byte. An optional zero/zero command terminates a short zero-pad page.
func expandLXPack2(src []byte, limit int) ([]byte, error) {
	out := make([]byte, 0, limit)
	for len(src) > 0 {
		b := int(src[0])
		literals, match, distance, header := 0, 0, 0, 1
		switch b & 3 {
		case 0:
			if b == 0 {
				if len(src) < 2 {
					return nil, fmt.Errorf("truncated run")
				}
				n := int(src[1])
				if n == 0 {
					if len(src) != 2 {
						return nil, fmt.Errorf("trailing data after terminator")
					}
					return out, nil
				}
				if len(src) < 3 || n > limit-len(out) {
					return nil, fmt.Errorf("run bounds")
				}
				for i := 0; i < n; i++ {
					out = append(out, src[2])
				}
				src = src[3:]
				continue
			}
			literals = b >> 2
		case 1:
			if len(src) < 2 {
				return nil, fmt.Errorf("truncated match1")
			}
			header = 2
			literals = (b >> 2) & 3
			match = ((b >> 4) & 7) + 3
			distance = int(binary.LittleEndian.Uint16(src)) >> 7
		case 2:
			if len(src) < 2 {
				return nil, fmt.Errorf("truncated match2")
			}
			header = 2
			match = ((b >> 2) & 3) + 3
			distance = int(binary.LittleEndian.Uint16(src)) >> 4
		case 3:
			if len(src) < 3 {
				return nil, fmt.Errorf("truncated match3")
			}
			header = 3
			literals = (b >> 2) & 15
			match = (int(binary.LittleEndian.Uint16(src)) >> 6) & 63
			distance = int(binary.LittleEndian.Uint16(src[1:])) >> 4
		}
		if literals > len(src)-header || literals+match > limit-len(out) {
			return nil, fmt.Errorf("literal/output bounds")
		}
		out = append(out, src[header:header+literals]...)
		src = src[header+literals:]
		if match > 0 && (distance == 0 || distance > len(out)) {
			return nil, fmt.Errorf("invalid match distance")
		}
		for i := 0; i < match; i++ {
			out = append(out, out[len(out)-distance])
		}
	}
	return out, nil
}

func LinearExecutableBuiltin(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := uint64(64 << 20)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "source", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	var data []byte
	switch v := value.(type) {
	case starlark.Bytes:
		data = []byte(v)
	case starfile.File:
		if v.Size() < 0 || uint64(v.Size()) > maximum {
			return nil, fmt.Errorf("LX: input exceeds maximum")
		}
		var err error
		data, err = starfile.ReadAll(v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("LX: source must be file or bytes")
	}
	if uint64(len(data)) > maximum {
		return nil, fmt.Errorf("LX: input exceeds maximum")
	}
	img, err := DecodeLX(data, maximum)
	if err != nil {
		return nil, err
	}
	objects, resources := []starlark.Value{}, []starlark.Value{}
	for i, o := range img.Objects {
		objects = append(objects, starfile.NewRecord(starlark.StringDict{"number": starlark.MakeInt(i + 1), "base": starlark.MakeUint(uint(o.Base)), "flags": starlark.MakeUint(uint(o.Flags)), "file": &starfile.Bytes{Data: o.Data}}))
	}
	for _, r := range img.Resources {
		d := img.Objects[r.Object-1].Data
		resources = append(resources, starfile.NewRecord(starlark.StringDict{"type": starlark.MakeUint(uint(r.Type)), "id": starlark.MakeUint(uint(r.ID)), "object": starlark.MakeUint(uint(r.Object)), "offset": starlark.MakeUint(uint(r.Offset)), "file": &starfile.Bytes{Data: d[r.Offset : uint64(r.Offset)+uint64(r.Size)]}}))
	}
	return starfile.NewRecord(starlark.StringDict{"objects": starlark.NewList(objects), "resources": starlark.NewList(resources)}), nil
}
