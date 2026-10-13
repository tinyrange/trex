package irix

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("irix_executable", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix_executable: expected file")
	}
	im, err := Open(file)
	if err != nil {
		return nil, err
	}
	record := func(fields starlark.StringDict) starlark.Value { return starfile.NewRecord(fields) }
	sections := []starlark.Value{}
	for _, s := range im.Sections {
		var data starlark.Value = starlark.None
		if s.Data != nil {
			data = s.Data
		}
		sections = append(sections, record(starlark.StringDict{"name": starlark.String(s.Name), "type": starlark.MakeUint(uint(s.Type)), "flags": starlark.MakeUint64(s.Flags), "address": starlark.MakeUint64(s.Address), "offset": starlark.MakeUint64(s.Offset), "size": starlark.MakeUint64(s.Size), "link": starlark.MakeUint(uint(s.Link)), "info": starlark.MakeUint(uint(s.Info)), "data": data}))
	}
	segments := []starlark.Value{}
	for _, s := range im.Segments {
		segments = append(segments, record(starlark.StringDict{"type": starlark.MakeUint(uint(s.Type)), "flags": starlark.MakeUint(uint(s.Flags)), "address": starlark.MakeUint64(s.Address), "offset": starlark.MakeUint64(s.Offset), "size": starlark.MakeUint64(s.Size), "memory_size": starlark.MakeUint64(s.MemorySize), "data": s.Data}))
	}
	symbols := []starlark.Value{}
	for _, s := range im.Symbols {
		symbols = append(symbols, record(starlark.StringDict{"name": starlark.String(s.Name), "table": starlark.String(s.Table), "value": starlark.MakeUint64(s.Value), "size": starlark.MakeUint64(s.Size), "section": starlark.MakeUint(uint(s.Section)), "binding": starlark.MakeInt(int(s.Binding)), "type": starlark.MakeInt(int(s.Type)), "visibility": starlark.MakeInt(int(s.Visibility))}))
	}
	relocations := []starlark.Value{}
	for _, s := range im.Relocations {
		types := []starlark.Value{}
		for _, t := range s.Types {
			types = append(types, starlark.MakeInt(int(t)))
		}
		relocations = append(relocations, record(starlark.StringDict{"section": starlark.String(s.Section), "offset": starlark.MakeUint64(s.Offset), "symbol": starlark.MakeUint(uint(s.Symbol)), "types": starlark.NewList(types), "special_symbol": starlark.MakeInt(int(s.SpecialSymbol)), "addend": starlark.MakeInt64(s.Addend), "has_addend": starlark.Bool(s.HasAddend), "external": starlark.Bool(s.External), "raw_info": starlark.MakeUint64(s.RawInfo)}))
	}
	libs := []starlark.Value{}
	for _, s := range im.Libraries {
		libs = append(libs, starlark.String(s))
	}
	dynamic := []starlark.Value{}
	for _, s := range im.Dynamic {
		dynamic = append(dynamic, record(starlark.StringDict{"tag": starlark.MakeInt64(s.Tag), "value": starlark.MakeUint64(s.Value)}))
	}
	options := []starlark.Value{}
	for _, o := range im.Options {
		options = append(options, record(starlark.StringDict{"kind": starlark.MakeInt(int(o.Kind)), "section": starlark.MakeInt(int(o.Section)), "info": starlark.MakeUint(uint(o.Info))}))
	}
	var abiFlags starlark.Value = starlark.None
	if a := im.ABIFlags; a != nil {
		abiFlags = record(starlark.StringDict{"isa_level": starlark.MakeInt(int(a.ISALevel)), "isa_revision": starlark.MakeInt(int(a.ISARevision)), "gpr_size": starlark.MakeInt(int(a.GPRSize)), "cpr1_size": starlark.MakeInt(int(a.CPR1Size)), "cpr2_size": starlark.MakeInt(int(a.CPR2Size)), "fp_abi": starlark.MakeInt(int(a.FPABI)), "isa_extension": starlark.MakeUint(uint(a.ISAExtension)), "ases": starlark.MakeUint(uint(a.ASEs)), "flags1": starlark.MakeUint(uint(a.Flags1)), "flags2": starlark.MakeUint(uint(a.Flags2))})
	}
	return record(starlark.StringDict{"mips_options": starlark.NewList(options), "abi_flags": abiFlags, "format": starlark.String(im.Format), "class": starlark.MakeInt(im.Class), "endian": starlark.String(im.Endian), "abi": starlark.String(im.ABI), "isa": starlark.String(im.ISA), "type": starlark.MakeUint(uint(im.Type)), "flags": starlark.MakeUint(uint(im.Flags)), "entry": starlark.MakeUint64(im.Entry), "gp": starlark.MakeUint64(im.GP), "interpreter": starlark.String(im.Interpreter), "sections": starlark.NewList(sections), "segments": starlark.NewList(segments), "symbols": starlark.NewList(symbols), "relocations": starlark.NewList(relocations), "libraries": starlark.NewList(libs), "dynamic": starlark.NewList(dynamic)}), nil
}
