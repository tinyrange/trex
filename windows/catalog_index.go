package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/catalog"

	"go.starlark.net/starlark"
)

// Catalog index entries locate signed catalogs; they are not trust decisions.
// Parse CTL entries, not arbitrary digest-sized octet strings in certificates
// or attributes. Version 1 uses SPC indirect-data digests; version 2 uses the
// subject identifier directly, matching CryptSvc's CTL iteration.
func catalogIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog_index", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	var entries [][]byte
	var err error
	if parsed, ok := value.(*parsedCatalog); ok {
		entries = parsed.entries
	} else {
		var data []byte
		data, err = bytesForBinaryValueLimited(value, 64<<20)
		if err == nil {
			entries, err = catalog.ParseIndex(data)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("catalog_index: %w", err)
	}
	result := starlark.NewDict(2)
	for _, size := range []int{20, 32} {
		values := []starlark.Value{}
		for _, entry := range entries {
			if len(entry) == size {
				values = append(values, starlark.Bytes(entry))
			}
		}
		name := "sha1"
		if size == 32 {
			name = "sha256"
		}
		if err := result.SetKey(starlark.String(name), starlark.NewList(values)); err != nil {
			return nil, err
		}
	}
	return result, nil
}
