package windows

import (
	"fmt"
	"go.starlark.net/starlark"
)

// typeLibraryBuiltin reuses the bounded PE resource parsers for standalone
// .tlb/.olb inputs. It returns facts only; registry policy belongs to the caller.
func typeLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("type_library", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 16<<20)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("type_library: truncated header")
	}
	var library msftTypeLib
	switch string(data[:4]) {
	case "MSFT":
		library, err = parseMSFTTypeLib(data)
	case "SLTG":
		library, err = parseSLTGTypeLib(data)
	default:
		return nil, fmt.Errorf("type_library: expected standalone MSFT or SLTG library")
	}
	if err != nil {
		return nil, fmt.Errorf("type_library: %w", err)
	}
	records, err := typeLibRecords([]msftTypeLib{library})
	if err != nil {
		return nil, err
	}
	return records.Index(0), nil
}
