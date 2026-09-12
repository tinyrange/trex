// Package sgi reads the SGI disk volume header and exposes bounded partitions
// and boot-directory entries. All sector addresses in the header are basic
// 512-byte blocks, including on 2048-byte CD media.
package sgi

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
)

type Partition struct {
	Index         int
	Type          uint32
	Start, Blocks uint32
	Data          starfile.File
	Complete      bool
}
type BootFile struct {
	Name string
	Data starfile.File
}
type Header struct {
	Partitions []Partition
	Files      []BootFile
}

func Open(file starfile.File) (*Header, error) {
	var b [512]byte
	if _, err := starfile.ReadFullAt(file, b[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(b[:]) != 0x0be5a941 {
		return nil, fmt.Errorf("sgi: invalid volume-header magic")
	}
	var sum uint32
	for i := 0; i < len(b); i += 4 {
		sum += be.Uint32(b[i:])
	}
	if sum != 0 {
		return nil, fmt.Errorf("sgi: invalid volume-header checksum")
	}
	h := &Header{}
	view := func(name string, start, size int64) (starfile.File, error) {
		if start < 0 || size < 0 || start > file.Size() || size > file.Size()-start {
			return nil, fmt.Errorf("sgi: %s outside image", name)
		}
		return &starfile.Slice{Name: name, Base: file, Offset: start, Length: size}, nil
	}
	for i := 0; i < 16; i++ {
		p := b[312+i*12:]
		blocks, start, kind := be.Uint32(p), be.Uint32(p[4:]), be.Uint32(p[8:])
		if blocks == 0 {
			continue
		}
		length := int64(blocks) * 512
		complete := true
		// Type 6 is a whole-volume descriptor, not another filesystem.
		// CD images can omit its final unused sectors while retaining every
		// real partition. Preserve the declared count and expose only bytes
		// actually supplied, explicitly marking that view incomplete.
		if kind == 6 && start == 0 && length > file.Size() {
			length = file.Size()
			complete = false
		}
		data, err := view(fmt.Sprintf("partition %d", i), int64(start)*512, length)
		if err != nil {
			return nil, err
		}
		h.Partitions = append(h.Partitions, Partition{Index: i, Type: kind, Start: start, Blocks: blocks, Data: data, Complete: complete})
	}
	for i := 0; i < 15; i++ {
		p := b[72+i*16:]
		name := strings.TrimRight(string(p[:8]), "\x00")
		size := be.Uint32(p[12:])
		if size == 0 {
			continue
		}
		data, err := view(name, int64(be.Uint32(p[8:]))*512, int64(size))
		if err != nil {
			return nil, err
		}
		h.Files = append(h.Files, BootFile{Name: name, Data: data})
	}
	return h, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("sgi", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	f, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("sgi: expected file")
	}
	h, err := Open(f)
	if err != nil {
		return nil, err
	}
	partitions := make([]starlark.Value, len(h.Partitions))
	for i, p := range h.Partitions {
		partitions[i] = starfile.NewRecord(starlark.StringDict{"index": starlark.MakeInt(p.Index), "partition_type": starlark.MakeUint(uint(p.Type)), "start_block": starlark.MakeUint(uint(p.Start)), "blocks": starlark.MakeUint(uint(p.Blocks)), "data": p.Data, "complete": starlark.Bool(p.Complete)})
	}
	files := make([]starlark.Value, len(h.Files))
	for i, f := range h.Files {
		files[i] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(f.Name), "data": f.Data})
	}
	return starfile.NewRecord(starlark.StringDict{"partitions": starlark.NewList(partitions), "files": starlark.NewList(files)}), nil
}
