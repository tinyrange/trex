package nsis

import (
	"fmt"
	"path"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Archive owns bounded decoded members. Stable instruction-based names preserve
// duplicate filenames and never pretend a static hint is an install destination.
type Archive struct {
	source  storage.Reader
	maximum int64
	Listing *Listing
	members map[string]starfile.File
	names   []string
}

func MemberName(e Entry) string { return fmt.Sprintf("/files/%06d", e.Instruction) }

// Open decodes the independently compressed members with a cumulative bound.
// It does not execute installation code, load native DLLs or write host files.
func Open(source storage.Reader, options Options, maximumBytes int64) (*Archive, error) {
	if maximumBytes <= 0 {
		return nil, fmt.Errorf("nsis: maximum_bytes must be positive")
	}
	listing, err := List(source, options)
	if err != nil {
		return nil, err
	}
	archive := &Archive{source: source, maximum: maximumBytes, Listing: listing, members: make(map[string]starfile.File)}
	decoded := make(map[int64]starfile.File)
	remaining := maximumBytes
	for _, entry := range listing.Entries {
		name := MemberName(entry)
		file := decoded[entry.Offset]
		if file == nil {
			if entry.PackedSize > maximumBytes {
				return nil, ErrLimit
			}
			packed := make([]byte, int(entry.PackedSize))
			if err := readAt(source, packed, entry.Offset+4); err != nil {
				return nil, err
			}
			data := packed
			if entry.Compressed {
				data, err = inflateNSIS(packed, remaining)
				if err != nil {
					return nil, fmt.Errorf("nsis: member %d %q: %w", entry.Instruction, entry.Name, err)
				}
			}
			if int64(len(data)) > remaining {
				return nil, ErrLimit
			}
			remaining -= int64(len(data))
			file = &starfile.Bytes{Name: name, Data: data}
			decoded[entry.Offset] = file
		}
		archive.names = append(archive.names, name)
		archive.members[name] = file
	}
	return archive, nil
}

// String resolves encoded NSIS metadata to symbolic text, not guest variables.
func (l *Listing) String(offset int32) (string, error) {
	s, _, err := decodeString(l.strings, offset)
	return s, err
}

func (a *Archive) String() string      { return fmt.Sprintf("<nsis files=%d>", len(a.names)) }
func (*Archive) Type() string          { return "nsis" }
func (*Archive) Freeze()               {}
func (*Archive) Truth() starlark.Bool  { return starlark.True }
func (*Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: nsis") }
func (a *Archive) Get(value starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(value)
	if !ok {
		return nil, false, fmt.Errorf("nsis: member name must be a string")
	}
	f, found := a.members[path.Clean("/"+name)]
	return f, found, nil
}
func (a *Archive) AttrNames() []string {
	return []string{"entries", "files", "find", "instructions", "sections", "string"}
}
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		values := make([]starlark.Value, len(a.names))
		for i, s := range a.names {
			values[i] = starlark.String(s)
		}
		return starlark.NewList(values), nil
	case "entries":
		values := make([]starlark.Value, len(a.Listing.Entries))
		for i, e := range a.Listing.Entries {
			values[i] = starfile.NewRecord(starlark.StringDict{"source": starlark.String(MemberName(e)), "instruction": starlark.MakeInt(e.Instruction), "name": starlark.String(e.Name), "output_directory_hint": starlark.String(e.OutputDirectory), "file": a.members[MemberName(e)]})
		}
		return starlark.NewList(values), nil
	case "instructions":
		values := make([]starlark.Value, len(a.Listing.Code))
		for i, c := range a.Listing.Code {
			operands := make([]starlark.Value, 6)
			for n, v := range c.Operands {
				operands[n] = starlark.MakeInt64(int64(v))
			}
			values[i] = starfile.NewRecord(starlark.StringDict{"opcode": starlark.MakeUint(uint(c.Opcode)), "operands": starlark.NewList(operands)})
		}
		return starlark.NewList(values), nil
	case "sections":
		values := make([]starlark.Value, len(a.Listing.Sections))
		for i, s := range a.Listing.Sections {
			values[i] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "flags": starlark.MakeUint(uint(s.Flags)), "start": starlark.MakeInt(s.Start), "count": starlark.MakeInt(s.Count)})
		}
		return starlark.NewList(values), nil
	case "string":
		return starlark.NewBuiltin("nsis.string", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var offset int32
			if err := starlark.UnpackArgs("nsis.string", args, kwargs, "offset", &offset); err != nil {
				return nil, err
			}
			value, err := a.Listing.String(offset)
			return starlark.String(value), err
		}), nil
	case "find":
		return starlark.NewBuiltin("nsis.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("nsis.find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, found, err := a.Get(starlark.String(name))
			if !found {
				return starlark.None, err
			}
			return value, err
		}), nil
	}
	return nil, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	o := Options{}
	maximum := int64(512 << 20)
	if err := starlark.UnpackArgs("nsis", args, kwargs, "file", &value, "maximum_bytes?", &maximum, "maximum_scan?", &o.MaxScanBytes, "maximum_metadata?", &o.MaxMetadataBytes, "maximum_instructions?", &o.MaxInstructions); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("nsis: got %s, want file", value.Type())
	}
	return Open(source, o, maximum)
}
