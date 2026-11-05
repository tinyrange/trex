package cc

import (
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

// legacyDescriptor decodes the architectural eight-byte protected-mode entry.
// IA-32e system entries have another eight bytes and are intentionally excluded.
func legacyDescriptor(raw []byte, selector int) (map[string]any, error) {
	if len(raw) != 8 || selector < 0 || selector > 65535 {
		return nil, fmt.Errorf("descriptor requires eight bytes and a 16-bit selector")
	}
	limit := uint32(binary.LittleEndian.Uint16(raw)) | uint32(raw[6]&15)<<16
	if raw[6]&0x80 != 0 {
		limit = limit<<12 | 4095
	}
	base := uint32(binary.LittleEndian.Uint16(raw[2:])) | uint32(raw[4])<<16 | uint32(raw[7])<<24
	return map[string]any{
		"selector": selector, "base": int64(base), "limit": int64(limit),
		"type": int(raw[5] & 15), "system": raw[5]&16 == 0,
		"dpl": int(raw[5]>>5) & 3, "present": raw[5]&128 != 0,
		"default32": raw[6]&64 != 0, "long": raw[6]&32 != 0,
	}, nil
}

func descriptorRange(limit uint32, start, count int) (int, error) {
	if limit > 65535 {
		return 0, fmt.Errorf("descriptor table exceeds the 16-bit selector space")
	}
	if start < 0 || start > 8192 || count < 1 || count > 256 {
		return 0, fmt.Errorf("descriptors requires start 0..8192 and count 1..256")
	}
	total := int((limit + 1) / 8)
	if total > 8192 || start > total {
		return 0, fmt.Errorf("descriptor range exceeds table limit")
	}
	return min(count, total-start), nil
}

func (i inspection) descriptors(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	table, start, count := "ldt", 0, 64
	if err := starlark.UnpackArgs("cc.descriptors", args, kwargs, "table?", &table, "start?", &start, "count?", &count); err != nil {
		return nil, err
	}
	if table != "gdt" && table != "ldt" {
		return nil, fmt.Errorf("descriptor table must be gdt or ldt")
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		p := i.driver.pc
		s, err := p.cpu.SystemRegisters()
		if err != nil {
			return err
		}
		if s.Cr0&1 == 0 || s.Efer&(1<<10) != 0 {
			return fmt.Errorf("descriptor inspection currently supports 16/32-bit protected mode")
		}
		base, limit, selectorBits := s.Gdt.Base, uint32(s.Gdt.Limit), 0
		if table == "ldt" {
			if s.Ldt.Unusable != 0 || s.Ldt.Present == 0 {
				return fmt.Errorf("local descriptor table is not present")
			}
			base, limit, selectorBits = s.Ldt.Base, s.Ldt.Limit, 4
		}
		n, err := descriptorRange(limit, start, count)
		if err != nil {
			return err
		}
		if base > 0xffffffff || base+uint64(start+n)*8 > 1<<32 {
			return fmt.Errorf("descriptor table exceeds the 32-bit address space")
		}
		data, err := p.readVirtualBytes(base+uint64(start)*8, n*8, 0)
		if err != nil {
			return err
		}
		entries := make([]any, n)
		for j := range entries {
			entries[j], err = legacyDescriptor(data[j*8:j*8+8], (start+j)*8|selectorBits)
			if err != nil {
				return err
			}
		}
		result, err = starvalue.Starlark(entries)
		return err
	})
	return result, err
}
