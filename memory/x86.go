package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type PageEntry struct {
	Level          string
	Address, Value uint64
}
type Translation struct {
	Virtual, Physical, PageSize uint64
	Entries                     []PageEntry
}

// X86 is an i386 address space, not a CPU emulator. It decodes present hardware
// mappings only; non-present software PTEs and pagefile recovery are not guessed.
type X86 struct {
	physical *Physical
	dtb      uint64
	pae      bool
}

func NewX86(physical *Physical, dtb uint64, pae bool) (*X86, error) {
	if physical == nil || dtb > 0xffffffff {
		return nil, fmt.Errorf("invalid x86 directory-table base")
	}
	return &X86{physical: physical, dtb: dtb, pae: pae}, nil
}
func (x *X86) Size() int64                { return 1 << 32 }
func (x *X86) DirectoryTableBase() uint64 { return x.dtb }
func (x *X86) PAE() bool                  { return x.pae }
func (x *X86) Translate(va uint64) (Translation, error) {
	t := Translation{Virtual: va}
	if va >= 1<<32 {
		return t, &Fault{Kind: "invalid-address", Address: va, Level: "virtual"}
	}
	entry := func(level string, address uint64, width int) (uint64, error) {
		var data [8]byte
		if _, err := x.physical.ReadAt(data[:width], int64(address)); err != nil {
			return 0, contextualFault(err, va, address, level)
		}
		v := uint64(binary.LittleEndian.Uint32(data[:4]))
		if width == 8 {
			v = binary.LittleEndian.Uint64(data[:])
		}
		t.Entries = append(t.Entries, PageEntry{Level: level, Address: address, Value: v})
		if v&1 == 0 {
			return 0, &Fault{Kind: "not-present", Address: va, Physical: address, Level: level}
		}
		return v, nil
	}
	if x.pae {
		pdpte, err := entry("pdpte", (x.dtb&^31)+((va>>30)&3)*8, 8)
		if err != nil {
			return t, err
		}
		pde, err := entry("pde", (pdpte&0x000ffffffffff000)+((va>>21)&511)*8, 8)
		if err != nil {
			return t, err
		}
		if pde&0x80 != 0 {
			t.Physical = (pde & 0x000fffffffe00000) + (va & 0x1fffff)
			t.PageSize = 1 << 21
			return t, nil
		}
		pte, err := entry("pte", (pde&0x000ffffffffff000)+((va>>12)&511)*8, 8)
		if err != nil {
			return t, err
		}
		t.Physical = (pte & 0x000ffffffffff000) + (va & 4095)
		t.PageSize = 4096
	} else {
		pde, err := entry("pde", (x.dtb&^4095)+(va>>22)*4, 4)
		if err != nil {
			return t, err
		}
		if pde&0x80 != 0 {
			// PSE-36 is deliberately not silently truncated to 32 bits.
			if pde&0x003fe000 != 0 {
				return t, &Fault{Kind: "unsupported", Address: va, Level: "pse-36"}
			}
			t.Physical = (pde & 0xffc00000) + (va & 0x3fffff)
			t.PageSize = 1 << 22
			return t, nil
		}
		pte, err := entry("pte", (pde&0xfffff000)+((va>>12)&1023)*4, 4)
		if err != nil {
			return t, err
		}
		t.Physical = (pte & 0xfffff000) + (va & 4095)
		t.PageSize = 4096
	}
	return t, nil
}
func (x *X86) ReadAt(out []byte, offset int64) (int, error) {
	if offset < 0 || uint64(offset) > 1<<32 || uint64(len(out)) > (1<<32)-uint64(offset) {
		return 0, &Fault{Kind: "invalid-address", Address: uint64(offset), Level: "virtual"}
	}
	done := 0
	for done < len(out) {
		va := uint64(offset) + uint64(done)
		t, err := x.Translate(va)
		if err != nil {
			return done, err
		}
		count := min(uint64(len(out)-done), t.PageSize-(va&(t.PageSize-1)))
		n, err := x.physical.ReadAt(out[done:done+int(count)], int64(t.Physical))
		done += n
		if err != nil {
			return done, contextualFault(err, va+uint64(n), t.Physical+uint64(n), "data")
		}
	}
	return done, nil
}

func contextualFault(err error, address, physical uint64, level string) error {
	kind := "source-error"
	var fault *Fault
	if errors.As(err, &fault) {
		kind = fault.Kind
	}
	return &Fault{Kind: kind, Address: address, Physical: physical, Level: level, Cause: err}
}
