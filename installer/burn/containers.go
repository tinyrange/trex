// Package burn reads WiX v3 Burn attached-container directories without running
// the bootstrapper. Container contents remain slices of the portable input.
package burn

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Containers returns UX first, then attached containers. Detached/truncated
// bundles and non-CAB container formats are rejected. Layout follows WiX v3
// src/burn/engine/section.cpp (BURN_SECTION_HEADER version 2).
func Containers(file starfile.File) ([]starfile.File, error) {
	p, err := pe.NewFile(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, fmt.Errorf("burn: PE: %w", err)
	}
	defer p.Close()
	var section *pe.Section
	for _, s := range p.Sections {
		if s.Name == ".wixburn" {
			if section != nil {
				return nil, fmt.Errorf("burn: duplicate section")
			}
			section = s
		}
	}
	if section == nil || section.Size < 52 || int64(section.Offset)+int64(section.Size) > file.Size() {
		return nil, fmt.Errorf("burn: missing or truncated section")
	}
	var security pe.DataDirectory
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		security = h.DataDirectory[4]
	case *pe.OptionalHeader64:
		security = h.DataDirectory[4]
	default:
		return nil, fmt.Errorf("burn: missing optional header")
	}
	header := make([]byte, 48)
	if _, err = io.ReadFull(io.NewSectionReader(file, int64(section.Offset), 48), header); err != nil {
		return nil, err
	}
	return containers(file, header, int64(section.Offset)+48, int64(section.Size)-48, security)
}

func containers(file starfile.File, h []byte, sizesOffset, sizesLength int64, security pe.DataDirectory) ([]starfile.File, error) {
	u := binary.LittleEndian.Uint32
	if len(h) != 48 || u(h[:4]) != 0x00f14300 || u(h[4:8]) != 2 || u(h[40:44]) != 1 {
		return nil, fmt.Errorf("burn: unsupported section header or container format")
	}
	count := int64(u(h[44:48]))
	if count == 0 || count > sizesLength/4 || count > 4096 {
		return nil, fmt.Errorf("burn: invalid container count")
	}
	sizes := make([]byte, count*4)
	if _, err := io.ReadFull(io.NewSectionReader(file, sizesOffset, int64(len(sizes))), sizes); err != nil {
		return nil, err
	}
	stub := int64(u(h[24:28]))
	engine := stub + int64(u(sizes[:4]))
	sigOffset, sigSize := int64(u(h[32:36])), int64(u(h[36:40]))
	if sigOffset != 0 {
		engine = sigOffset + sigSize
	} else if security.VirtualAddress != 0 {
		engine = int64(security.VirtualAddress) + int64(security.Size)
	}
	if stub < sizesOffset+count*4 || engine < stub+int64(u(sizes[:4])) || engine > file.Size() {
		return nil, fmt.Errorf("burn: invalid engine boundary")
	}
	result := make([]starfile.File, 0, count)
	offset := stub
	for i := int64(0); i < count; i++ {
		if i == 1 {
			offset = engine
		}
		size := int64(u(sizes[i*4 : i*4+4]))
		if size < 36 || offset > file.Size() || size > file.Size()-offset {
			return nil, fmt.Errorf("burn: container %d absent or truncated", i)
		}
		var cab [12]byte
		if _, err := io.ReadFull(io.NewSectionReader(file, offset, 12), cab[:]); err != nil {
			return nil, err
		}
		if string(cab[:4]) != "MSCF" || int64(u(cab[8:12])) != size {
			return nil, fmt.Errorf("burn: container %d CAB size/signature mismatch", i)
		}
		result = append(result, &starfile.Slice{Name: fmt.Sprintf("burn-container-%d", i), Base: file, Offset: offset, Length: size})
		offset += size
	}
	return result, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("burn_containers", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	files, err := Containers(file)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(files))
	for i, f := range files {
		values[i] = f
	}
	return starlark.NewList(values), nil
}
