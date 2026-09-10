package ntfs

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// RecordBuiltin inspects one FILE record without scanning or repairing the
// namespace. Attribute headers and update-sequence fixups are still validated;
// attribute values are returned verbatim, not interpreted as complete streams.
func RecordBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var number int64
	if err := starlark.UnpackArgs("ntfs_record", args, kwargs, "source", &value, "number", &number); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ntfs_record: expected a volume file")
	}
	v, err := openNTFSMFT(file)
	if err != nil {
		return nil, err
	}
	if number < 0 || number >= v.mft.size/v.recordSize {
		return nil, fmt.Errorf("ntfs_record: record number outside MFT")
	}
	raw := make([]byte, v.recordSize)
	if _, err := starfile.ReadFullAt(v.mft, raw, number*v.recordSize); err != nil {
		return nil, err
	}
	if err := applyNTFSReadFixup(raw, v.sectorSize, "inspected MFT"); err != nil {
		return nil, err
	}
	attributes, err := parseNTFSReadAttributes(raw, v.clusterSize)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(attributes))
	offset := int(binary.LittleEndian.Uint16(raw[20:22]))
	for _, a := range attributes {
		length := int(binary.LittleEndian.Uint32(raw[offset+4:]))
		fields := starlark.StringDict{
			"type": starlark.MakeUint(uint(a.typ)), "name": starlark.String(a.name),
			"instance": starlark.MakeUint(uint(a.instance)), "flags": starlark.MakeUint(uint(a.flags)),
			"nonresident": starlark.Bool(a.nonresident), "size": starlark.MakeInt64(a.size),
			"first_vcn": starlark.MakeInt64(a.firstVCN),
			"header":    starlark.Bytes(raw[offset : offset+length]),
		}
		if a.nonresident {
			fields["initialized_size"] = starlark.MakeUint64(binary.LittleEndian.Uint64(raw[offset+56:]))
			fields["allocated_size"] = starlark.MakeUint64(binary.LittleEndian.Uint64(raw[offset+40:]))
			runs := make([]starlark.Value, 0, len(a.runs))
			for _, r := range a.runs {
				runs = append(runs, starfile.NewRecord(starlark.StringDict{
					"cluster": starlark.MakeInt64(r.start), "count": starlark.MakeInt64(r.length), "sparse": starlark.Bool(r.sparse),
				}))
			}
			fields["runs"] = starlark.NewList(runs)
		} else {
			fields["value"] = starlark.Bytes(a.value)
		}
		values = append(values, starfile.NewRecord(fields))
		offset += length
	}
	return starfile.NewRecord(starlark.StringDict{
		"number": starlark.MakeInt64(number), "sequence": starlark.MakeUint(uint(binary.LittleEndian.Uint16(raw[16:]))),
		"base_reference": starlark.MakeUint64(binary.LittleEndian.Uint64(raw[32:])),
		"flags":          starlark.MakeUint(uint(binary.LittleEndian.Uint16(raw[22:]))),
		"cluster_size":   starlark.MakeInt64(v.clusterSize), "record_size": starlark.MakeInt64(v.recordSize),
		"attributes": starlark.NewList(values), "raw": starlark.Bytes(raw),
	}), nil
}
