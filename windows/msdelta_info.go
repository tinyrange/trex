package windows

import (
	"crypto/sha256"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/msdelta"
	"go.starlark.net/starlark"
)

const deltaInfoLimit = 16 << 20
const deltaApplyLimit = 64 << 20
const deltaMaximumLimit = 128 << 20

func deltaInfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	psfRecord := false
	maximum := int64(deltaInfoLimit)
	if err := starlark.UnpackArgs("delta_info", args, kwargs, "value", &value, "psf_record?", &psfRecord, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 1 || maximum > deltaMaximumLimit {
		return nil, fmt.Errorf("delta_info: maximum must be between 1 and %d", deltaMaximumLimit)
	}
	data, err := bytesForBinaryValueLimited(value, maximum)
	if err != nil {
		return nil, fmt.Errorf("delta_info: %w", err)
	}
	var header *msdelta.Header
	if psfRecord {
		header, err = msdelta.ParsePSFRecord(data)
	} else {
		header, err = msdelta.Parse(data)
	}
	if err != nil {
		return nil, fmt.Errorf("delta_info: %w", err)
	}
	extension := make([]starlark.Value, len(header.Extension))
	for index, value := range header.Extension {
		extension[index] = starlark.MakeUint64(uint64(value))
	}
	preprocessHash := sha256.Sum256(header.Preprocess)
	patchHash := sha256.Sum256(header.Patch)
	pePreprocess := starlark.Value(starlark.None)
	if header.FileType > 1 && header.FileType <= 0x80 && header.FileType&(header.FileType-1) == 0 && len(header.Preprocess) != 0 {
		info, err := msdelta.InspectPEPreprocess(header.Preprocess)
		if err != nil {
			return nil, fmt.Errorf("delta_info: PE preprocessing: %w", err)
		}
		riftValues := func(entries []msdelta.PERiftEntry) *starlark.List {
			values := make([]starlark.Value, len(entries))
			for index, entry := range entries {
				values[index] = starfile.NewRecord(starlark.StringDict{
					"source": starlark.MakeInt64(entry.Source),
					"target": starlark.MakeInt64(entry.Target),
				})
			}
			return starlark.NewList(values)
		}
		managed := starlark.Value(starlark.None)
		if m := info.Managed; m != nil {
			streams := make([]starlark.Value, 5)
			for i, stream := range m.Streams {
				streams[i] = starlark.Tuple{starlark.MakeUint(uint(stream.Offset)), starlark.MakeUint(uint(stream.Size))}
			}
			rows := make([]starlark.Value, 64)
			tables := make([]starlark.Value, 64)
			heaps := make([]starlark.Value, 4)
			for i := range rows {
				rows[i] = starlark.MakeUint(uint(m.Rows[i]))
				tables[i] = riftValues(m.TableMaps[i])
			}
			for i := range heaps {
				heaps[i] = riftValues(m.HeapMaps[i])
			}
			managed = starfile.NewRecord(starlark.StringDict{
				"metadata_offset": starlark.MakeUint(uint(m.MetadataOffset)), "metadata_size": starlark.MakeUint(uint(m.MetadataSize)),
				"metadata_rva": starlark.MakeUint(uint(m.MetadataRVA)), "streams": starlark.NewList(streams),
				"rows": starlark.NewList(rows), "heap_maps": starlark.NewList(heaps), "table_maps": starlark.NewList(tables),
			})
		}
		pePreprocess = starfile.NewRecord(starlark.StringDict{
			"managed":              managed,
			"checksum":             starlark.MakeUint(uint(info.Checksum)),
			"image_base":           starlark.MakeUint64(info.ImageBase),
			"source_to_target_rva": riftValues(info.SourceToTargetRVA),
			"target_rva_to_file":   riftValues(info.TargetRVAtoFile),
			"timestamp":            starlark.MakeUint(uint(info.Timestamp)),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"version":              starlark.String(header.Version),
		"target_filetime":      starlark.MakeUint64(header.TargetFileTime),
		"file_type_set":        starlark.MakeInt64(header.FileTypeSet),
		"file_type":            starlark.MakeInt64(header.FileType),
		"flags":                starlark.MakeInt64(header.Flags),
		"target_size":          starlark.MakeUint64(header.TargetSize),
		"hash_algorithm":       starlark.MakeUint64(uint64(header.HashAlgorithm)),
		"target_hash":          starlark.Bytes(header.TargetHash),
		"extension":            starlark.NewList(extension),
		"extension_hash":       starlark.Bytes(header.ExtensionHash),
		"preprocessing":        starlark.Bytes(header.Preprocess),
		"preprocessing_size":   starlark.MakeInt(len(header.Preprocess)),
		"preprocessing_head":   starlark.Bytes(header.Preprocess[:min(len(header.Preprocess), 32)]),
		"preprocessing_sha256": starlark.Bytes(preprocessHash[:]),
		"patch_size":           starlark.MakeInt(len(header.Patch)),
		"patch_head":           starlark.Bytes(header.Patch[:min(len(header.Patch), 32)]),
		"patch_sha256":         starlark.Bytes(patchHash[:]),
		"pe_preprocess":        pePreprocess,
	}), nil
}

func deltaApplyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourceValue, deltaValue starlark.Value
	psfRecord := false
	maximum := int64(deltaApplyLimit)
	if err := starlark.UnpackArgs("delta_apply", args, kwargs, "source", &sourceValue, "delta", &deltaValue, "psf_record?", &psfRecord, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 1 || maximum > deltaMaximumLimit {
		return nil, fmt.Errorf("delta_apply: maximum must be between 1 and %d", deltaMaximumLimit)
	}
	source, err := bytesForBinaryValueLimited(sourceValue, maximum)
	if err != nil {
		return nil, fmt.Errorf("delta_apply: source: %w", err)
	}
	delta, err := bytesForBinaryValueLimited(deltaValue, maximum)
	if err != nil {
		return nil, fmt.Errorf("delta_apply: delta: %w", err)
	}
	var target []byte
	if psfRecord {
		target, err = msdelta.ApplyPSFRecordBounded(source, delta, uint64(maximum))
	} else {
		target, err = msdelta.ApplyBounded(source, delta, uint64(maximum))
	}
	if err != nil {
		return nil, fmt.Errorf("delta_apply: %w", err)
	}
	return starlark.Bytes(target), nil
}

func deltaTraceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourceValue, deltaValue starlark.Value
	var start, end int
	psfRecord := false
	peTransforms := true
	inspectSignatures := false
	preparedStart, preparedEnd := -1, -1
	if err := starlark.UnpackArgs("delta_trace", args, kwargs,
		"source", &sourceValue, "delta", &deltaValue, "start", &start, "end", &end,
		"psf_record?", &psfRecord, "pe_transforms?", &peTransforms,
		"prepared_source_start?", &preparedStart, "prepared_source_end?", &preparedEnd,
		"inspect_signatures?", &inspectSignatures); err != nil {
		return nil, err
	}
	source, err := bytesForBinaryValueLimited(sourceValue, deltaApplyLimit)
	if err != nil {
		return nil, fmt.Errorf("delta_trace: source: %w", err)
	}
	delta, err := bytesForBinaryValueLimited(deltaValue, deltaApplyLimit)
	if err != nil {
		return nil, fmt.Errorf("delta_trace: delta: %w", err)
	}
	if psfRecord {
		if _, err := msdelta.ParsePSFRecord(delta); err != nil {
			return nil, fmt.Errorf("delta_trace: %w", err)
		}
		delta = delta[4:]
	}
	var info msdelta.PatchRangeInfo
	var prepared starlark.Value = starlark.None
	signatures := []starlark.Value{}
	if inspectSignatures && (preparedStart < 0 || preparedEnd < 0) {
		return nil, fmt.Errorf("delta_trace: inspect_signatures requires a prepared-source range")
	}
	if preparedStart != -1 || preparedEnd != -1 {
		window, err := msdelta.InspectPreparedSourceRange(source, delta, preparedStart, preparedEnd)
		if err != nil {
			return nil, fmt.Errorf("delta_trace: %w", err)
		}
		prepared = starlark.Bytes(window)
	}
	if inspectSignatures {
		refs, err := msdelta.InspectCLISignatureReferences(source, preparedStart, preparedEnd)
		if err != nil {
			return nil, fmt.Errorf("delta_trace: source signatures: %w", err)
		}
		for _, ref := range refs {
			signatures = append(signatures, starfile.NewRecord(starlark.StringDict{
				"table": starlark.MakeInt(ref.Table), "row": starlark.MakeInt(ref.Row),
				"blob_index": starlark.MakeInt(ref.BlobIndex), "offset": starlark.MakeInt(ref.Offset),
				"size": starlark.MakeInt(ref.Size),
			}))
		}
	}
	if peTransforms {
		info, err = msdelta.InspectPatchRangeBounded(source, delta, start, end, deltaApplyLimit)
	} else {
		info, err = msdelta.InspectPatchRangeBytesBounded(source, delta, start, end, deltaApplyLimit)
	}
	if err != nil {
		return nil, fmt.Errorf("delta_trace: %w", err)
	}
	matches := make([]starlark.Value, len(info.Matches))
	for index, match := range info.Matches {
		matches[index] = starfile.NewRecord(starlark.StringDict{
			"kind":               starlark.String(match.Kind),
			"target_start":       starlark.MakeInt(match.TargetStart),
			"target_end":         starlark.MakeInt(match.TargetEnd),
			"combined_start":     starlark.MakeInt64(match.CombinedStart),
			"distance":           starlark.MakeInt64(match.Distance),
			"rift_offset":        starlark.MakeInt64(match.RiftOffset),
			"rift_next":          starlark.MakeInt64(match.RiftNext),
			"source_rift_offset": starlark.MakeInt64(match.SourceRiftOffset),
			"source_rift_next":   starlark.MakeInt64(match.SourceRiftNext),
		})
	}
	transforms := make([]starlark.Value, len(info.PETransforms))
	for index, event := range info.PETransforms {
		transforms[index] = starfile.NewRecord(starlark.StringDict{
			"raw_start": starlark.MakeInt(event.RawStart), "raw_end": starlark.MakeInt(event.RawEnd),
			"instruction_raw":    starlark.MakeInt(event.InstructionRaw),
			"instruction_rva":    starlark.MakeInt(event.InstructionRVA),
			"instruction_length": starlark.MakeInt(event.InstructionLength),
			"field":              starlark.MakeInt(event.Field),
			"old":                starlark.MakeInt64(int64(event.Old)), "mapped": starlark.MakeInt64(int64(event.Mapped)),
			"target":           starlark.MakeInt64(event.Target),
			"target_reachable": starlark.Bool(event.TargetReachable),
			"target_marked":    starlark.Bool(event.TargetMarked),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"start": starlark.MakeInt(info.Start), "end": starlark.MakeInt(info.End),
		"decoded":               starlark.Bytes(info.Decoded),
		"matches":               starlark.NewList(matches),
		"pe_transforms":         starlark.NewList(transforms),
		"prepared_source":       prepared,
		"prepared_source_start": starlark.MakeInt(preparedStart),
		"source_signatures":     starlark.NewList(signatures),
	}), nil
}
