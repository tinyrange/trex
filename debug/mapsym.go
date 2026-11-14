package debug

import (
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// MapSymbol is an unrelocated IBM/Microsoft MAPSYM symbol. Segment is the
// file's load address, not a runtime selector. Absolute symbols use segment 0.
type MapSymbol struct {
	Module, SegmentName, Name string
	Segment                   uint16
	Offset                    uint32
}

// ReadMapSymbols reads linked MAPSYM maps and segments without trusting counts,
// relative offsets, or linked pointers. Line tables and alpha indexes are ignored.
func ReadMapSymbols(data []byte) ([]MapSymbol, error) {
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("mapsym: input exceeds 1 MiB")
	}
	var result []MapSymbol
	u16 := func(p int) int { return int(binary.LittleEndian.Uint16(data[p:])) }
	fits := func(p, n int) bool { return p >= 0 && n >= 0 && p <= len(data) && n <= len(data)-p }
	name := func(p int) (string, error) {
		if !fits(p, 1) || !fits(p+1, int(data[p])) {
			return "", fmt.Errorf("mapsym: truncated name at %#x", p)
		}
		return string(data[p+1 : p+1+int(data[p])]), nil
	}
	symbols := func(base, table, count int, wide bool, module, segment string, load uint16) error {
		if !fits(base+table, count*2) || len(result)+count > 1<<20 {
			return fmt.Errorf("mapsym: invalid symbol table")
		}
		width := 2
		if wide {
			width = 4
		}
		for i := 0; i < count; i++ {
			p := base + u16(base+table+i*2)
			if !fits(p, width+1) {
				return fmt.Errorf("mapsym: truncated symbol")
			}
			s, err := name(p + width)
			if err != nil {
				return err
			}
			offset := uint32(u16(p))
			if wide {
				offset = binary.LittleEndian.Uint32(data[p:])
			}
			result = append(result, MapSymbol{module, segment, s, load, offset})
		}
		return nil
	}
	maps := map[int]bool{}
	segments := map[int]bool{}
	for m := 0; ; {
		if maps[m] || !fits(m, 4) {
			return nil, fmt.Errorf("mapsym: invalid map chain")
		}
		maps[m] = true
		if u16(m) == 0 {
			if data[m+3] != 4 && data[m+3] != 5 && data[m+3] != 6 {
				return nil, fmt.Errorf("mapsym: unsupported version")
			}
			return result, nil
		}
		if !fits(m, 16) {
			return nil, fmt.Errorf("mapsym: truncated map")
		}
		module, err := name(m + 15)
		if err != nil {
			return nil, err
		}
		if err = symbols(m, u16(m+8), u16(m+6), data[m+2]&1 != 0, module, "", 0); err != nil {
			return nil, err
		}
		count, s := u16(m+10), u16(m+12)*16
		for i := 0; i < count; i++ {
			if s == 0 || segments[s] || !fits(s, 21) {
				return nil, fmt.Errorf("mapsym: invalid segment chain")
			}
			segments[s] = true
			seg, err := name(s + 20)
			if err != nil {
				return nil, err
			}
			if err = symbols(s, u16(s+4), u16(s+2), data[s+14]&1 != 0, module, seg, uint16(u16(s+6))); err != nil {
				return nil, err
			}
			s = u16(s) * 16
		}
		m = u16(m) * 16
	}
}

func MapSymbolsBuiltin(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &input); err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(input, 1<<20)
	if err != nil {
		return nil, err
	}
	symbols, err := ReadMapSymbols(data)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(symbols))
	for _, s := range symbols {
		values = append(values, starvalue.NewRecord(starlark.StringDict{
			"module": starlark.String(s.Module), "segment_name": starlark.String(s.SegmentName),
			"segment": starlark.MakeUint(uint(s.Segment)), "name": starlark.String(s.Name), "offset": starlark.MakeUint64(uint64(s.Offset)),
		}))
	}
	return starlark.NewList(values), nil
}
