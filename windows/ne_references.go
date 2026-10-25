package windows

import (
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

type neReference struct {
	Segment, Offset, SourceType                int
	TargetSegment, TargetOffset, TargetOrdinal int
	Additive                                   bool
}

// parseNEInternalReferences expands loader-linked internal relocation chains.
// Imported and OS fixups are outside this view; no relocation is applied.
func parseNEInternalReferences(data []byte, maximum int) ([]neReference, error) {
	m, err := parseWindowsNEModule(data)
	if err != nil {
		return nil, err
	}
	entries, err := parseWindowsNEExports(data)
	if err != nil {
		return nil, err
	}
	exports := map[int]windowsNEExport{}
	for _, entry := range entries {
		exports[entry.Ordinal] = entry
	}
	var refs []neReference
	for segment := 0; segment < m.segmentCount; segment++ {
		e := data[m.segments+segment*8:]
		flags := binary.LittleEndian.Uint16(e[4:])
		if flags&0x100 == 0 {
			continue
		}
		if flags&8 != 0 {
			return nil, fmt.Errorf("iterated NE relocation storage is unsupported")
		}
		base := uint64(binary.LittleEndian.Uint16(e)) << m.alignShift
		length := windowsNEExpandedLength(binary.LittleEndian.Uint16(e[2:]))
		allocated := max(length, windowsNEExpandedLength(binary.LittleEndian.Uint16(e[6:])))
		at := base + length
		if base == 0 || at > uint64(len(data)) || uint64(len(data))-at < 2 {
			return nil, fmt.Errorf("truncated NE relocation table")
		}
		count := int(binary.LittleEndian.Uint16(data[at:]))
		at += 2
		if count > (len(data)-int(at))/8 {
			return nil, fmt.Errorf("truncated NE relocation records")
		}
		for range count {
			p := data[at : at+8]
			at += 8
			if p[1]&3 != 0 {
				continue
			}
			width := 0
			switch p[0] {
			case 0:
				width = 1
			case 2, 5:
				width = 2
			case 3, 13:
				width = 4
			case 11:
				width = 6
			default:
				return nil, fmt.Errorf("unsupported NE relocation source type %d", p[0])
			}
			r := neReference{Segment: segment + 1, Offset: int(binary.LittleEndian.Uint16(p[2:])), SourceType: int(p[0]), TargetSegment: int(p[4]), TargetOffset: int(binary.LittleEndian.Uint16(p[6:])), Additive: p[1]&4 != 0}
			if r.TargetSegment == 255 {
				r.TargetOrdinal = r.TargetOffset
				target, ok := exports[r.TargetOrdinal]
				if !ok || target.Constant {
					return nil, fmt.Errorf("invalid NE entry reference")
				}
				r.TargetSegment, r.TargetOffset = target.Segment, target.Offset
			}
			if r.TargetSegment < 1 || r.TargetSegment > m.segmentCount {
				return nil, fmt.Errorf("invalid NE target segment")
			}
			seen := map[int]bool{}
			for {
				if uint64(r.Offset+width) > allocated || seen[r.Offset] {
					return nil, fmt.Errorf("invalid NE relocation chain in segment %d at %#x (source type %d, allocation %#x, record %x)", segment+1, r.Offset, r.SourceType, allocated, p)
				}
				seen[r.Offset] = true
				if len(refs) >= maximum {
					return nil, fmt.Errorf("NE internal references exceed maximum %d", maximum)
				}
				refs = append(refs, r)
				if r.Additive {
					break
				}
				if uint64(r.Offset+2) > allocated {
					return nil, fmt.Errorf("truncated NE relocation link")
				}
				// The loader zero-fills the segment's allocation beyond the
				// stored bytes. Windows 2 USER has additive fixups there; a
				// linked fixup must likewise see zero, never relocation-table bytes.
				next := 0
				for index := 0; index < 2; index++ {
					if uint64(r.Offset+index) < length {
						next |= int(data[base+uint64(r.Offset+index)]) << (8 * index)
					}
				}
				if next == 65535 {
					break
				}
				r.Offset = next
			}
		}
	}
	return refs, nil
}

func windowsNEInternalReferencesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := 65536
	if err := starlark.UnpackArgs("ne_internal_references", args, kwargs, "source", &source, "maximum_references?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 1 || maximum > 1<<20 {
		return nil, fmt.Errorf("invalid NE reference limit")
	}
	data, err := bytesForBinaryValueLimited(source, windowsNEFastBootMaximum)
	if err != nil {
		return nil, err
	}
	refs, err := parseNEInternalReferences(data, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(refs))
	for i, r := range refs {
		values[i] = starvalue.NewRecord(starlark.StringDict{
			"segment": starlark.MakeInt(r.Segment), "offset": starlark.MakeInt(r.Offset), "source_type": starlark.MakeInt(r.SourceType),
			"target_segment": starlark.MakeInt(r.TargetSegment), "target_offset": starlark.MakeInt(r.TargetOffset), "target_ordinal": starlark.MakeInt(r.TargetOrdinal), "additive": starlark.Bool(r.Additive),
		})
	}
	return starlark.NewList(values), nil
}
