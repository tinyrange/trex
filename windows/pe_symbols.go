package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// symbolize resolves self-samples, not caller stacks. Public symbols have no
// length: only accept them inside the same AMD64 runtime-function interval,
// or at an exact address. Never extend a preceding symbol across a gap.
func (p *windowsPE) symbolizeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var symbols *pdbValue
	var rvas *starlark.List
	var timestamp, size, checksum uint32
	if err := starlark.UnpackArgs("symbolize", args, kwargs, "pdb", &symbols, "rvas", &rvas, "timestamp", &timestamp, "image_size", &size, "checksum", &checksum); err != nil {
		return nil, err
	}
	if rvas.Len() > 1000000 {
		return nil, fmt.Errorf("symbolize: too many RVAs")
	}
	source, err := p.sourceFile()
	if err != nil {
		return nil, err
	}
	data, err := peReadSnapshotData(source)
	if err != nil {
		return nil, err
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer image.Close()
	optional, ok := image.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || image.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil, fmt.Errorf("symbolize: requires AMD64 PE")
	}
	if image.TimeDateStamp != timestamp || optional.SizeOfImage != size || optional.CheckSum != checksum {
		return nil, fmt.Errorf("symbolize: ETW image identity mismatch (timestamp/size/checksum)")
	}
	cv, err := peCodeView(data)
	if err != nil {
		return nil, err
	}
	if err := validateSymbolIdentity(cv, symbols); err != nil {
		return nil, err
	}
	out := make([]starlark.Value, rvas.Len())
	for i := range out {
		var value uint32
		if err := starlark.AsInt(rvas.Index(i), &value); err != nil {
			return nil, err
		}
		if value >= size {
			return nil, fmt.Errorf("symbolize: RVA outside image")
		}
		fn, found, err := amd64FindRuntimeFunction(image, data, value)
		if err != nil {
			return nil, err
		}
		symbol, ok := boundedSymbol(symbols.symbols, value, fn, found)
		confidence := "runtime_function"
		if !ok && found {
			owner, err := amd64SymbolOwner(image, data, fn)
			if err != nil {
				return nil, err
			}
			// A split range may precede its primary range. Only an exact
			// symbol at the explicitly chained owner is sufficient evidence.
			if owner != fn {
				candidate, exact := boundedSymbol(symbols.symbols, owner.begin, owner, true)
				if exact && candidate.rva == owner.begin {
					symbol, ok = candidate, true
					confidence = "chained_runtime_function"
				}
			}
		}
		if !ok {
			out[i] = starlark.None
			continue
		}
		d := starlark.NewDict(4)
		d.SetKey(starlark.String("name"), starlark.String(symbol.name))
		d.SetKey(starlark.String("rva"), starlark.MakeUint(uint(symbol.rva)))
		d.SetKey(starlark.String("displacement"), starlark.MakeInt64(int64(value)-int64(symbol.rva)))
		if symbol.rva == value {
			confidence = "exact_address"
		}
		d.SetKey(starlark.String("match"), starlark.String(confidence))
		out[i] = d
	}
	return starlark.NewList(out), nil
}

func validateSymbolIdentity(cv *peCodeViewInfo, symbols *pdbValue) error {
	if cv == nil {
		return fmt.Errorf("symbolize: image has no RSDS identity")
	}
	if !strings.EqualFold(cv.guid, symbols.guid) {
		return fmt.Errorf("symbolize: PDB GUID mismatch")
	}
	return symbols.validateImageAge(cv.age)
}

func boundedSymbol(symbols []pdbSymbol, rva uint32, fn amd64RuntimeFunction, found bool) (pdbSymbol, bool) {
	i := sort.Search(len(symbols), func(i int) bool { return symbols[i].rva > rva }) - 1
	if i < 0 {
		return pdbSymbol{}, false
	}
	s := symbols[i]
	return s, s.rva == rva || (found && s.rva >= fn.begin && s.rva < fn.end && rva >= fn.begin && rva < fn.end)
}

// Follow only explicit UNW_FLAG_CHAININFO ownership, never nearest-symbol
// heuristics for discontiguous ranges. Bound cycles, arithmetic and file reads.
func amd64SymbolOwner(image *pe.File, data []byte, fn amd64RuntimeFunction) (amd64RuntimeFunction, error) {
	for depth := 0; depth < 32; depth++ {
		header, err := amd64RVABytes(image, data, fn.unwind, 4)
		if err != nil {
			return fn, err
		}
		version, flags := header[0]&7, header[0]>>3
		if version != 1 && version != 2 {
			return fn, fmt.Errorf("symbolize: unsupported unwind version %d", version)
		}
		if flags&amd64UnwindChainInfo == 0 {
			return fn, nil
		}
		if flags&3 != 0 {
			return fn, fmt.Errorf("symbolize: chained unwind has handler flags")
		}
		offset := uint64(fn.unwind) + 4 + uint64((uint32(header[2])+1)&^1)*2
		if offset+12 > 1<<32 {
			return fn, fmt.Errorf("symbolize: chained RVA overflow")
		}
		raw, err := amd64RVABytes(image, data, uint32(offset), 12)
		if err != nil {
			return fn, err
		}
		fn = amd64RuntimeFunction{begin: binary.LittleEndian.Uint32(raw), end: binary.LittleEndian.Uint32(raw[4:]), unwind: binary.LittleEndian.Uint32(raw[8:])}
		if fn.begin >= fn.end {
			return fn, fmt.Errorf("symbolize: invalid chained function range")
		}
	}
	return fn, fmt.Errorf("symbolize: chained unwind cycle or depth exceeds 32")
}
