package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiIdentityHashBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var omitVersion bool
	if err := starlark.UnpackArgs("csi_identity_hash", args, kwargs, "data", &value, "omit_version?", &omitVersion); err != nil {
		return nil, err
	}
	data, ok := value.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("csi_identity_hash requires bytes")
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("csi_identity_hash exceeds 64 KiB")
	}
	hash, err := uup.HashCSIIdentity([]byte(data), omitVersion)
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(hash), nil
}
