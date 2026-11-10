package windows

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// csiFileSourceKeyBuiltin implements the bounded ordinary InsertFileInfo key,
// not an exact component identity or authority to select payload bytes.
func csiFileSourceKeyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	var name string
	if err := starlark.UnpackArgs("csi_file_source_key", args, kwargs, "identity", &data, "name", &name); err != nil {
		return nil, err
	}
	id, err := uup.ParseCSIIdentity([]byte(data))
	if err != nil {
		return nil, err
	}
	scope := strings.ToLower(id.VersionScope)
	if scope != "" && scope != "nonsxs" {
		return nil, fmt.Errorf("unsupported file source versionScope")
	}
	if name == "" || strings.ContainsAny(name, "/:") {
		return nil, fmt.Errorf("file source key requires a relative source name")
	}
	for _, part := range strings.Split(name, `\`) {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("file source key requires a relative source name")
		}
	}
	kind := ""
	for _, attr := range id.Attributes {
		if attr.Namespace == "" && attr.Name == "type" {
			kind = attr.Value
		}
	}
	fields := [...]string{id.Name, id.Language, id.ProcessorArchitecture, id.PublicKeyToken, kind, id.VersionScope, name}
	result := make(starlark.Tuple, len(fields)+1)
	for i, field := range fields {
		for j := 0; j < len(field); j++ {
			if field[j] < 32 || field[j] > 126 {
				return nil, fmt.Errorf("file source key requires bounded ASCII comparison")
			}
		}
		result[i] = starlark.String(strings.ToLower(field))
	}
	family := starlark.Tuple{}
	if scope == "" {
		// ParseCSIIdentity already validates the complete four-part version.
		for _, part := range strings.Split(id.Version, ".")[:2] {
			value, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return nil, err
			}
			family = append(family, starlark.MakeUint64(value))
		}
	}
	result[len(fields)] = family
	return result, nil
}
