package elfmeta

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
)

const shtRELR elf.SectionType = 19

// readRELR expands the ELF64 address/bitmap encoding. Each bitmap describes
// 63 consecutive eight-byte words following the previous address or bitmap.
func readRELR(out []Relocation, order binary.ByteOrder, section *elf.Section, maximum int) ([]Relocation, error) {
	const word = 8
	const span = 63 * word
	if section.Flags&elf.SHF_COMPRESSED != 0 || section.Entsize != word || section.Size%word != 0 {
		return nil, fmt.Errorf("elf_symbols: invalid RELR section %q", section.Name)
	}
	source := section.Open()
	var record [word]byte
	var next uint64
	for i, count := uint64(0), section.Size/word; i < count; i++ {
		if _, err := io.ReadFull(source, record[:]); err != nil {
			return nil, fmt.Errorf("elf_symbols: read RELR section %q: %w", section.Name, err)
		}
		entry := order.Uint64(record[:])
		if entry&1 == 0 {
			if len(out) == maximum || entry > ^uint64(0)-word {
				return nil, fmt.Errorf("elf_symbols: invalid or over-limit RELR address")
			}
			out = append(out, relativeWord(entry))
			next = entry + word
			continue
		}
		bitmap := entry >> 1
		if i == 0 || next > ^uint64(0)-span || bits.OnesCount64(bitmap) > maximum-len(out) {
			return nil, fmt.Errorf("elf_symbols: invalid or over-limit RELR bitmap")
		}
		for bitmap != 0 {
			out = append(out, relativeWord(next+uint64(bits.TrailingZeros64(bitmap))*word))
			bitmap &= bitmap - 1
		}
		next += span
	}
	return out, nil
}

func relativeWord(address uint64) Relocation {
	return Relocation{Address: address, Type: uint32(elf.R_X86_64_RELATIVE), ImplicitAddend: true}
}
