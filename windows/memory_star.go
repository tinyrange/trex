package windows

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/memory"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type memoryValue struct {
	physical *memory.Physical
	virtual  *memory.X86
	reader   storage.Reader
}

func (v *memoryValue) Type() string {
	if v.virtual != nil {
		return "windows.address_space"
	}
	return "windows.memory_image"
}
func (v *memoryValue) String() string      { return "<" + v.Type() + ">" }
func (*memoryValue) Freeze()               {}
func (*memoryValue) Truth() starlark.Bool  { return starlark.True }
func (*memoryValue) Hash() (uint32, error) { return 0, fmt.Errorf("memory views are unhashable") }
func (v *memoryValue) AttrNames() []string {
	if v.virtual != nil {
		return []string{"read", "probe", "view", "translate", "directory_table_base", "pae"}
	}
	return []string{"read", "probe", "view", "ranges", "address_space"}
}
func memoryImageBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	var mapping starlark.Value = starlark.None
	if err := starlark.UnpackArgs("memory_image", args, kwargs, "file", &file, "ranges?", &mapping); err != nil {
		return nil, err
	}
	var ranges []memory.Range
	if mapping != starlark.None {
		list, ok := mapping.(*starlark.List)
		if !ok || list.Len() > 1<<20 {
			return nil, fmt.Errorf("ranges must be a bounded list of (physical_start, file_offset, size)")
		}
		ranges = make([]memory.Range, 0, list.Len())
		for i := 0; i < list.Len(); i++ {
			tuple, ok := list.Index(i).(starlark.Tuple)
			if !ok || len(tuple) != 3 {
				return nil, fmt.Errorf("range must be a three-integer tuple")
			}
			var r memory.Range
			for j, p := range []*uint64{&r.Start, &r.Offset, &r.Size} {
				if err := starlark.AsInt(tuple[j], p); err != nil {
					return nil, err
				}
			}
			ranges = append(ranges, r)
		}
	}
	physical, err := memory.NewPhysical(file, ranges)
	if err != nil {
		return nil, err
	}
	return &memoryValue{physical: physical, reader: physical}, nil
}
func memoryFault(err error) starlark.Value {
	if err == nil {
		return starlark.None
	}
	fields := starlark.StringDict{"kind": starlark.String("invalid-structure"), "message": starlark.String(err.Error())}
	var fault *memory.Fault
	if errors.As(err, &fault) {
		fields["kind"] = starlark.String(fault.Kind)
		fields["address"] = starlark.MakeUint64(fault.Address)
		fields["physical_address"] = starlark.MakeUint64(fault.Physical)
		fields["level"] = starlark.String(fault.Level)
	}
	return starfile.NewRecord(fields)
}
func (v *memoryValue) Attr(name string) (starlark.Value, error) {
	if v.virtual != nil {
		switch name {
		case "directory_table_base":
			return starlark.MakeUint64(v.virtual.DirectoryTableBase()), nil
		case "pae":
			return starlark.Bool(v.virtual.PAE()), nil
		}
	}
	if name == "ranges" && v.virtual == nil {
		var values []starlark.Value
		for _, r := range v.physical.Ranges() {
			values = append(values, starlark.Tuple{starlark.MakeUint64(r.Start), starlark.MakeUint64(r.Offset), starlark.MakeUint64(r.Size)})
		}
		return starlark.NewList(values), nil
	}
	valid := false
	for _, attr := range v.AttrNames() {
		if name == attr {
			valid = true
		}
	}
	if !valid {
		return nil, nil
	}
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		switch name {
		case "address_space":
			var dtb uint64
			var pae bool
			if err := starlark.UnpackArgs(name, args, kwargs, "directory_table_base", &dtb, "pae?", &pae); err != nil {
				return nil, err
			}
			x, err := memory.NewX86(v.physical, dtb, pae)
			if err != nil {
				return nil, err
			}
			return &memoryValue{physical: v.physical, virtual: x, reader: x}, nil
		case "read", "probe", "view":
			var address uint64
			var size int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
				return nil, err
			}
			if size < 0 || size > 64<<20 || address > math.MaxInt64 || uint64(size) > math.MaxInt64-address {
				return nil, fmt.Errorf("invalid or oversized memory range")
			}
			if name == "view" {
				return &memoryViewFile{reader: v.reader, offset: int64(address), size: int64(size)}, nil
			}
			data, err := memory.Read(v.reader, address, size)
			if name == "read" {
				if err != nil {
					return nil, err
				}
				return starlark.Bytes(data), nil
			}
			return starfile.NewRecord(starlark.StringDict{"data": starlark.Bytes(data), "complete": starlark.Bool(err == nil), "fault": memoryFault(err)}), nil
		case "translate":
			var address uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address); err != nil {
				return nil, err
			}
			t, err := v.virtual.Translate(address)
			var entries []starlark.Value
			for _, e := range t.Entries {
				entries = append(entries, starfile.NewRecord(starlark.StringDict{"level": starlark.String(e.Level), "address": starlark.MakeUint64(e.Address), "value": starlark.MakeUint64(e.Value)}))
			}
			physical := starlark.Value(starlark.None)
			if err == nil {
				physical = starlark.MakeUint64(t.Physical)
			}
			return starfile.NewRecord(starlark.StringDict{"mapped": starlark.Bool(err == nil), "physical_address": physical, "page_size": starlark.MakeUint64(t.PageSize), "entries": starlark.NewList(entries), "fault": memoryFault(err)}), nil
		}
		return nil, fmt.Errorf("unsupported memory operation")
	}), nil
}

// A bounded lazy file view for existing byte/format readers. No WriteAt path
// reaches the source, even when the caller originally supplied a writable file.
type memoryViewFile struct {
	reader       storage.Reader
	offset, size int64
}

func (v *memoryViewFile) Size() int64 { return v.size }
func (v *memoryViewFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > v.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	wanted := len(p)
	if int64(len(p)) > v.size-off {
		p = p[:v.size-off]
	}
	n, err := v.reader.ReadAt(p, v.offset+off)
	if err == nil && n < wanted {
		err = io.EOF
	}
	return n, err
}
func (*memoryViewFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("memory view is read-only")
}
func (*memoryViewFile) Type() string { return "file" }
func (v *memoryViewFile) String() string {
	return fmt.Sprintf("<memory file %#x+%#x>", v.offset, v.size)
}
func (*memoryViewFile) Freeze()               {}
func (*memoryViewFile) Truth() starlark.Bool  { return starlark.True }
func (*memoryViewFile) Hash() (uint32, error) { return 0, fmt.Errorf("memory file is unhashable") }
func (v *memoryViewFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(v, name), nil
}
func (*memoryViewFile) AttrNames() []string { return starfile.AttrNames() }
