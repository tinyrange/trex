package vmm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestARM64TranslationPartialRootAndCrossPageRead(t *testing.T) {
	// A 39-bit VA with 16 KiB granules has a 64-byte initial table;
	// TTBR need not align to a full granule. Exercise its last entry.
	ram := make([]byte, 6<<14)
	const root = 0x1040
	const address = uint64(7<<36 | 0x3fff)
	binary.LittleEndian.PutUint64(ram[root+7*8:], 0x4000|3)
	binary.LittleEndian.PutUint64(ram[0x4000:], 0x8000|3)
	binary.LittleEndian.PutUint64(ram[0x8000:], 0xc000|3)
	binary.LittleEndian.PutUint64(ram[0x8008:], 0x14000|3)
	ram[0xffff], ram[0x14000] = 'a', 'b'
	walker := ARM64Translation{TCR: 25 | 2<<14, TTBR0: root, ReadPhysical: func(a uint64, n int) ([]byte, error) {
		if a > uint64(len(ram)) || uint64(n) > uint64(len(ram))-a {
			return nil, fmt.Errorf("outside RAM")
		}
		return ram[a : a+uint64(n)], nil
	}}
	data, err := walker.Read(address, 2)
	if err != nil || string(data) != "ab" {
		t.Fatalf("partial root / split read: %q, %v", data, err)
	}
}

func TestARM64TranslationGranulesAndUpperAddresses(t *testing.T) {
	for _, bits := range []uint64{12, 14, 16} {
		for _, upper := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", bits, upper), func(t *testing.T) {
				page := uint64(1) << bits
				ram := make([]byte, 10*page)
				tcr := uint64(25) | 25<<16
				if bits == 14 {
					tcr |= 2<<14 | 1<<30
				} else if bits == 16 {
					tcr |= 1<<14 | 3<<30
				} else {
					tcr |= 2 << 30
				}
				address := uint64(0x12345)
				if upper {
					address |= ^uint64((1 << 39) - 1)
				}
				indexBits := bits - 3
				levels := (39 - bits + indexBits - 1) / indexBits
				table := page
				for level := uint64(4) - levels; level < 4; level++ {
					shift := bits + (3-level)*indexBits
					index := (address & ((1 << 39) - 1)) >> shift & (1<<indexBits - 1)
					desc := table + page | 3
					if level == 3 {
						desc = 8*page | 3
					}
					binary.LittleEndian.PutUint64(ram[table+index*8:], desc)
					table += page
				}
				walker := ARM64Translation{TCR: tcr, TTBR0: page, TTBR1: page, ReadPhysical: func(a uint64, n int) ([]byte, error) {
					if a > uint64(len(ram)) || uint64(n) > uint64(len(ram))-a {
						return nil, fmt.Errorf("outside RAM")
					}
					return ram[a : a+uint64(n)], nil
				}}
				pa, span, err := walker.Translate(address)
				if err != nil || pa != 8*page+address&(page-1) || span != page-address&(page-1) {
					t.Fatal(pa, span, err)
				}
				ram[pa] = 'x'
				b, err := walker.Read(address, 1)
				if err != nil || string(b) != "x" {
					t.Fatal(b, err)
				}
				walker.TCR |= 1<<37 | 1<<38
				tagged := address&0x00ffffffffffffff | 0xab<<56
				if _, _, err := walker.Translate(tagged); err != nil {
					t.Fatal("TBI", err)
				}
				if upper {
					walker.TCR |= 1 << 23
				} else {
					walker.TCR |= 1 << 7
				}
				if _, _, err := walker.Translate(address); err == nil {
					t.Fatal("disabled table accepted")
				}
			})
		}
	}
	if _, _, err := (ARM64Translation{}).Translate(0); err == nil {
		t.Fatal("missing reader")
	}
}
