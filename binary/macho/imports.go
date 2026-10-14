package macho

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
)

type indirectSection struct {
	address, size, stride uint64
	start                 uint32
	stub                  bool
}

func readImports(source storage.Reader, command []byte, sections []indirectSection, symbols []Symbol, boundFileset bool) ([]Import, error) {
	le := binary.LittleEndian
	count := le.Uint32(command[60:])
	if count > maxSymbols {
		return nil, fmt.Errorf("macho: excessive indirect symbol table")
	}
	table, err := read(source, uint64(le.Uint32(command[56:])), uint64(count)*4)
	if err != nil {
		return nil, err
	}
	var imports []Import
	var slots uint64
	for _, s := range sections {
		n := s.size / s.stride
		if uint64(s.start) > uint64(count) || n > uint64(count)-uint64(s.start) || n > maxSymbols-slots {
			return nil, fmt.Errorf("macho: indirect section exceeds symbol table")
		}
		slots += n
		for i := uint64(0); i < n; i++ {
			index := le.Uint32(table[(uint64(s.start)+i)*4:])
			if index&0xc0000000 != 0 { // INDIRECT_SYMBOL_LOCAL / ABS
				continue
			}
			// Bound, stripped kernel-collection members retain their indirect
			// section geometry with zero placeholders and no symbol table.
			// Such slots contain no surviving import name to report.
			if boundFileset && len(symbols) == 0 && index == 0 {
				continue
			}
			if uint64(index) >= uint64(len(symbols)) {
				return nil, fmt.Errorf("macho: indirect symbol index outside symbol table")
			}
			if symbols[index].Type&0x0e != 0 { // defined symbol, not an import
				continue
			}
			kind := "pointer"
			if s.stub {
				kind = "stub"
			}
			imports = append(imports, Import{symbols[index].Name, kind, s.address + i*s.stride, s.stride})
		}
	}
	return imports, nil
}
