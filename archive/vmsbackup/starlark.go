package vmsbackup

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type starPayload struct{ storage.Reader }

func (*starPayload) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("vms backup: read-only payload")
}
func (*starPayload) String() string                             { return "<VMS BACKUP file>" }
func (*starPayload) Type() string                               { return "file" }
func (*starPayload) Freeze()                                    {}
func (*starPayload) Truth() starlark.Bool                       { return starlark.True }
func (*starPayload) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *starPayload) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*starPayload) AttrNames() []string                        { return starfile.AttrNames() }

func FilesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limits := Limits{MaximumBlocks: 1000000, MaximumRecords: 1000000, MaximumBlockSize: 16 << 20}
	maximumFiles, maximumAttributes := 1000000, 256
	if err := starlark.UnpackArgs("vmsbackup", args, kwargs, "file", &value,
		"maximum_blocks?", &limits.MaximumBlocks, "maximum_records?", &limits.MaximumRecords,
		"maximum_block_size?", &limits.MaximumBlockSize, "maximum_files?", &maximumFiles,
		"maximum_attributes?", &maximumAttributes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("vms backup: expected file")
	}
	blocks, err := ReadBlocks(file, limits)
	if err != nil {
		return nil, err
	}
	entries, err := Files(blocks, maximumFiles, maximumAttributes)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		var data starlark.Value = starlark.None
		if e.Data != nil {
			data = &starPayload{e.Data}
		}
		attributes := make([]starlark.Value, 0, len(e.Attributes))
		for _, a := range e.Attributes {
			attributes = append(attributes, starfile.NewRecord(starlark.StringDict{"kind": starlark.MakeUint(uint(a.Kind)), "data": starlark.Bytes(a.Data)}))
		}
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"name": starlark.Bytes(e.Name), "flags": starlark.MakeUint(uint(e.Flags)),
			"size": starlark.MakeInt64(e.Size), "stored_size": starlark.MakeInt64(e.StoredSize),
			"missing_contents": starlark.Bool(e.MissingContents), "data": data,
			"attributes": starlark.NewList(attributes),
		}))
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(values)}), nil
}

func BlocksBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limits := Limits{MaximumBlocks: 1000000, MaximumRecords: 1000000, MaximumBlockSize: 16 << 20}
	if err := starlark.UnpackArgs("vmsbackup_blocks", args, kwargs, "file", &value,
		"maximum_blocks?", &limits.MaximumBlocks, "maximum_records?", &limits.MaximumRecords,
		"maximum_block_size?", &limits.MaximumBlockSize); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("vms backup: expected file")
	}
	blocks, err := ReadBlocks(file, limits)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(blocks))
	for _, b := range blocks {
		records := make([]starlark.Value, 0, len(b.Records))
		for _, r := range b.Records {
			records = append(records, starfile.NewRecord(starlark.StringDict{
				"offset": starlark.MakeInt64(r.Offset), "kind": starlark.MakeUint(uint(r.Kind)),
				"flags": starlark.MakeUint(uint(r.Flags)), "address": starlark.MakeUint(uint(r.Address)),
				"reserved": starlark.MakeUint(uint(r.Reserved)),
				"data":     &starfile.Slice{Name: "VMS BACKUP record", Base: file, Offset: r.Offset + 16, Length: r.Data.Size()},
			}))
		}
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"offset": starlark.MakeInt64(b.Offset), "sequence": starlark.MakeUint(uint(b.Sequence)),
			"header": starlark.Bytes(b.Header[:]), "parity": starlark.Bool(b.Parity),
			"records": starlark.NewList(records),
		}))
	}
	return starfile.NewRecord(starlark.StringDict{"blocks": starlark.NewList(values)}), nil
}
