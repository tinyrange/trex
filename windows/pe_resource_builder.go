package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func (p *windowsPE) withResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	if err := starlark.UnpackArgs("with_resources", args, kwargs, "resources", &values); err != nil {
		return nil, err
	}
	var resources []peResource
	for i := 0; i < values.Len(); i++ {
		d, ok := values.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("resource must be a dictionary")
		}
		var names [3]string
		for j, key := range []string{"type", "name", "lang"} {
			v, found, err := d.Get(starlark.String(key))
			if err != nil || !found {
				return nil, fmt.Errorf("resource missing %s", key)
			}
			if names[j], ok = starlark.AsString(v); !ok {
				return nil, fmt.Errorf("resource %s must be a string", key)
			}
		}
		v, found, err := d.Get(starlark.String("data"))
		if err != nil || !found {
			return nil, fmt.Errorf("resource missing data")
		}
		data, err := binaryapi.BytesForValue(v)
		if err != nil {
			return nil, err
		}
		resources = append(resources, peResource{typ: names[0], name: names[1], lang: names[2], data: data})
	}
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	data, err := peReadSnapshotData(source)
	if err != nil {
		return nil, err
	}
	output, err := peWithResources(data, resources)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "PE with resources", Data: output}, nil
}

type resourceNode struct {
	children map[string]*resourceNode
	data     []byte
	leaf     bool
}

// peResourceSection builds the three-level PE resource tree with directory-
// relative names/children and image-relative data addresses. No source RVAs
// survive the transformation.
func peResourceSection(resources []peResource, rva uint32) ([]byte, error) {
	root := &resourceNode{children: map[string]*resourceNode{}}
	total := 0
	for _, resource := range resources {
		total += len(resource.data)
		if total > defaultBinaryBuilderLimit || len(resources) > 65535 {
			return nil, fmt.Errorf("resource size limit exceeded")
		}
		n := root
		for _, name := range []string{resource.typ, resource.name, resource.lang} {
			total += len(name)*2 + 32
			if total > defaultBinaryBuilderLimit {
				return nil, fmt.Errorf("resource directory size limit exceeded")
			}
			if strings.HasPrefix(name, "#") {
				id, err := strconv.ParseUint(name[1:], 10, 31)
				if err != nil || strconv.FormatUint(id, 10) != name[1:] {
					return nil, fmt.Errorf("invalid resource identifier %q", name)
				}
			}
			if len(utf16.Encode([]rune(name))) > 65535 {
				return nil, fmt.Errorf("resource name too long")
			}
			if n.children[name] == nil {
				n.children[name] = &resourceNode{children: map[string]*resourceNode{}}
			}
			n = n.children[name]
		}
		if n.leaf {
			return nil, fmt.Errorf("duplicate resource")
		}
		n.leaf, n.data = true, resource.data
	}
	var out []byte
	reserve := func(size int) int { at := len(out); out = append(out, make([]byte, size)...); return at }
	put := func(at int, value uint32) { binary.LittleEndian.PutUint32(out[at:], value) }
	align := func() {
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
	}
	var emit func(*resourceNode) uint32
	emit = func(n *resourceNode) uint32 {
		align()
		if n.leaf {
			at := reserve(16)
			put(at, rva+uint32(len(out)))
			put(at+4, uint32(len(n.data)))
			out = append(out, n.data...)
			return uint32(at)
		}
		keys := make([]string, 0, len(n.children))
		for key := range n.children {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			ai, bi := strings.HasPrefix(a, "#"), strings.HasPrefix(b, "#")
			if ai != bi {
				return !ai
			}
			if ai {
				av, _ := strconv.ParseUint(a[1:], 10, 31)
				bv, _ := strconv.ParseUint(b[1:], 10, 31)
				return av < bv
			}
			au, bu := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
			for k := 0; k < len(au) && k < len(bu); k++ {
				if au[k] != bu[k] {
					return au[k] < bu[k]
				}
			}
			return len(au) < len(bu)
		})
		at := reserve(16 + 8*len(keys))
		named := 0
		for i, key := range keys {
			entry := at + 16 + i*8
			if strings.HasPrefix(key, "#") {
				id, _ := strconv.ParseUint(key[1:], 10, 31)
				put(entry, uint32(id))
			} else {
				named++
				name := utf16.Encode([]rune(key))
				align()
				offset := reserve(2 + 2*len(name))
				put(entry, uint32(offset)|0x80000000)
				binary.LittleEndian.PutUint16(out[offset:], uint16(len(name)))
				for j, ch := range name {
					binary.LittleEndian.PutUint16(out[offset+2+j*2:], ch)
				}
			}
			child := n.children[key]
			offset := emit(child)
			if !child.leaf {
				offset |= 0x80000000
			}
			put(entry+4, offset)
		}
		binary.LittleEndian.PutUint16(out[at+12:], uint16(named))
		binary.LittleEndian.PutUint16(out[at+14:], uint16(len(keys)-named))
		return uint32(at)
	}
	emit(root)
	if len(out) > defaultBinaryBuilderLimit || uint64(rva)+uint64(len(out)) > 0xffffffff {
		return nil, fmt.Errorf("resource image too large")
	}
	return out, nil
}

// Adds a resource section to a PE with spare section-header capacity. Code,
// imports and relocations retain their addresses; any old resource directory
// is superseded. Signed inputs must be resigned after this transformation.
func peWithResources(source []byte, resources []peResource) ([]byte, error) {
	f, err := pe.NewFile(bytes.NewReader(source))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var alignment, fileAlignment, headers, directoryOffset uint32
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		alignment, fileAlignment, headers, directoryOffset = h.SectionAlignment, h.FileAlignment, h.SizeOfHeaders, 96
	case *pe.OptionalHeader64:
		alignment, fileAlignment, headers, directoryOffset = h.SectionAlignment, h.FileAlignment, h.SizeOfHeaders, 112
	default:
		return nil, fmt.Errorf("unsupported PE optional header")
	}
	if alignment == 0 || fileAlignment == 0 || alignment&(alignment-1) != 0 || fileAlignment&(fileAlignment-1) != 0 {
		return nil, fmt.Errorf("invalid PE alignment")
	}
	peAt := 0
	if len(source) >= 64 && bytes.Equal(source[:2], []byte("MZ")) {
		peAt = int(binary.LittleEndian.Uint32(source[60:]))
	}
	opt := peAt + 24
	if peAt < 0 || opt < peAt || opt+int(f.SizeOfOptionalHeader) > len(source) || len(f.Sections) >= 65535 {
		return nil, fmt.Errorf("invalid PE header bounds")
	}
	sectionAt := opt + int(f.SizeOfOptionalHeader) + 40*len(f.Sections)
	if uint64(sectionAt+40) > uint64(headers) || sectionAt+40 > len(source) {
		return nil, fmt.Errorf("PE has no spare section header")
	}
	end := uint64(headers)
	for _, s := range f.Sections {
		if s.Offset != 0 && uint64(sectionAt+40) > uint64(s.Offset) {
			return nil, fmt.Errorf("section header overlaps data")
		}
		end = max(end, uint64(s.VirtualAddress)+uint64(max(s.VirtualSize, s.Size)))
	}
	align := func(v uint64, a uint32) uint64 { return (v + uint64(a) - 1) & ^(uint64(a) - 1) }
	rva := align(end, alignment)
	if rva > 0xffffffff {
		return nil, fmt.Errorf("PE address overflow")
	}
	section, err := peResourceSection(resources, uint32(rva))
	if err != nil {
		return nil, err
	}
	raw := align(uint64(len(source)), fileAlignment)
	rawSize := align(uint64(len(section)), fileAlignment)
	imageSize := align(rva+uint64(len(section)), alignment)
	if raw+rawSize > defaultBinaryBuilderLimit || imageSize > 0xffffffff {
		return nil, fmt.Errorf("PE size limit exceeded")
	}
	out := make([]byte, int(raw+rawSize))
	copy(out, source)
	copy(out[int(raw):], section)
	put := func(at int, v uint32) { binary.LittleEndian.PutUint32(out[at:], v) }
	clear(out[sectionAt : sectionAt+40])
	copy(out[sectionAt:], ".rsrc")
	put(sectionAt+8, uint32(len(section)))
	put(sectionAt+12, uint32(rva))
	put(sectionAt+16, uint32(rawSize))
	put(sectionAt+20, uint32(raw))
	put(sectionAt+36, 0x40000040)
	binary.LittleEndian.PutUint16(out[peAt+6:], uint16(len(f.Sections)+1))
	put(opt+56, uint32(imageSize))
	put(opt+int(directoryOffset)-4, max(3, binary.LittleEndian.Uint32(out[opt+int(directoryOffset)-4:])))
	put(opt+8, binary.LittleEndian.Uint32(out[opt+8:])+uint32(rawSize))
	put(opt+int(directoryOffset)+16, uint32(rva))
	put(opt+int(directoryOffset)+20, uint32(len(section)))
	_, checksum, err := peChecksums(out)
	if err != nil {
		return nil, err
	}
	put(opt+64, checksum)
	return out, nil
}
