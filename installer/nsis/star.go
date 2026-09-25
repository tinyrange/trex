package nsis

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ListBuiltin exposes metadata only; it does not masquerade as a readable archive.
func ListBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	o := Options{}
	if err := starlark.UnpackArgs("nsis_list", args, kwargs, "file", &value,
		"maximum_scan?", &o.MaxScanBytes, "maximum_metadata?", &o.MaxMetadataBytes, "maximum_instructions?", &o.MaxInstructions); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("nsis_list: got %s, want file", value.Type())
	}
	listing, err := List(source, o)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, 0, len(listing.Entries))
	for _, e := range listing.Entries {
		entries = append(entries, starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(e.Name), "raw_name": starlark.Bytes(e.RawName),
			"instruction":           starlark.MakeInt(e.Instruction),
			"output_directory_hint": starlark.String(e.OutputDirectory),
			"directory_instruction": starlark.MakeInt(e.DirectoryInstruction),
			"data_offset":           starlark.MakeInt64(e.DataOffset), "offset": starlark.MakeInt64(e.Offset),
			"packed_size": starlark.MakeInt64(e.PackedSize), "compressed": starlark.Bool(e.Compressed),
			"filetime": starlark.MakeUint64(e.FileTime),
		}))
	}
	return starfile.NewRecord(starlark.StringDict{
		"format":             starlark.String("nsis2-ansi"),
		"header_offset":      starlark.MakeInt64(listing.HeaderOffset),
		"data_offset":        starlark.MakeInt64(listing.DataOffset),
		"header_size":        starlark.MakeInt64(listing.HeaderSize),
		"header_compression": starlark.String(listing.HeaderCompression),
		"instruction_count":  starlark.MakeInt(listing.Instructions),
		"entries":            starlark.NewList(entries),
	}), nil
}
