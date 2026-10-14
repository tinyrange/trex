package macho

import (
	"bytes"
	"fmt"
)

// Export is a dyld export-trie terminal. Reexports retain the dependency ordinal
// and import name, while stub/resolver exports retain both entry addresses.
type Export struct {
	Name                                      string
	Address, Flags, Resolver, ReexportOrdinal uint64
	ImportName                                string
}

func readExports(data []byte, base uint64) ([]Export, error) {
	var out []Export
	active := map[uint64]bool{}
	names := map[string]bool{}
	visits, nameBytes, workBytes := 0, 0, 0
	uleb := func(pos *int, end int) (uint64, error) {
		var n uint64
		for shift := uint(0); shift < 70; shift += 7 {
			if *pos >= end {
				return 0, fmt.Errorf("macho: truncated export ULEB")
			}
			b := data[*pos]
			*pos++
			if shift == 63 && b&0xfe != 0 {
				return 0, fmt.Errorf("macho: overflowing export ULEB")
			}
			n |= uint64(b&127) << shift
			if b&128 == 0 {
				return n, nil
			}
		}
		return 0, fmt.Errorf("macho: overflowing export ULEB")
	}
	cstring := func(pos *int, end int) (string, error) {
		if *pos >= end {
			return "", fmt.Errorf("macho: truncated export name")
		}
		n := bytes.IndexByte(data[*pos:end], 0)
		if n < 0 {
			return "", fmt.Errorf("macho: unterminated export name")
		}
		s := string(data[*pos : *pos+n])
		*pos += n + 1
		return s, nil
	}
	address := func(off uint64, absolute bool) (uint64, error) {
		if absolute {
			return off, nil
		}
		if off > ^uint64(0)-base {
			return 0, fmt.Errorf("macho: wrapping export address")
		}
		return base + off, nil
	}
	var walk func(uint64, string, int) error
	walk = func(offset uint64, prefix string, depth int) error {
		visits++
		if offset >= uint64(len(data)) || depth > 512 || visits > maxSymbols || active[offset] {
			return fmt.Errorf("macho: invalid, cyclic or excessive export trie")
		}
		active[offset] = true
		defer delete(active, offset)
		pos := int(offset)
		size, err := uleb(&pos, len(data))
		if err != nil {
			return err
		}
		if size > uint64(len(data)-pos) {
			return fmt.Errorf("macho: export terminal outside trie")
		}
		end := pos + int(size)
		if size != 0 {
			if prefix == "" || names[prefix] || len(out) >= maxSymbols || len(prefix) > maxStrings-nameBytes {
				return fmt.Errorf("macho: invalid, duplicate or excessive exports")
			}
			flags, err := uleb(&pos, end)
			if err != nil {
				return err
			}
			if flags&^uint64(0x3f) != 0 || flags&3 == 3 || flags&8 != 0 && flags&0x10 != 0 {
				return fmt.Errorf("macho: unsupported export flags %#x", flags)
			}
			e := Export{Name: prefix, Flags: flags}
			value, err := uleb(&pos, end)
			if err != nil {
				return err
			}
			if flags&8 != 0 {
				e.ReexportOrdinal = value
				e.ImportName, err = cstring(&pos, end)
				if len(e.ImportName) > maxStrings-workBytes {
					return fmt.Errorf("macho: aggregate export name limit")
				}
				workBytes += len(e.ImportName)
			} else {
				e.Address, err = address(value, flags&3 == 2)
				if err == nil && flags&0x10 != 0 {
					var resolver uint64
					resolver, err = uleb(&pos, end)
					if err == nil {
						e.Resolver, err = address(resolver, false)
					}
				}
			}
			if err != nil {
				return err
			}
			if pos != end {
				return fmt.Errorf("macho: unconsumed export terminal")
			}
			out = append(out, e)
			names[prefix] = true
			nameBytes += len(prefix)
		}
		pos = end
		if pos == len(data) {
			return fmt.Errorf("macho: missing export child count")
		}
		children := int(data[pos])
		pos++
		labels := map[string]bool{}
		for i := 0; i < children; i++ {
			label, err := cstring(&pos, len(data))
			if err != nil {
				return err
			}
			if label == "" || labels[label] || len(label) > maxStrings-len(prefix) {
				return fmt.Errorf("macho: invalid export edge")
			}
			labels[label] = true
			cost := len(prefix) + 2*len(label)
			if cost > maxStrings-workBytes {
				return fmt.Errorf("macho: aggregate export prefix limit")
			}
			workBytes += cost
			child, err := uleb(&pos, len(data))
			if err != nil {
				return err
			}
			if err := walk(child, prefix+label, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(0, "", 0)
	return out, err
}
