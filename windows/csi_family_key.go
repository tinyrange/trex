package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func csiWinnerFamilyKeyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("csi_winner_family_key", args, kwargs, "data", &value); err != nil {
		return nil, err
	}
	data, ok := value.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("csi_winner_family_key requires bytes")
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("csi_winner_family_key exceeds 64 KiB")
	}
	key, err := uup.CSIWinnerFamilyKey([]byte(data))
	if err != nil {
		return nil, err
	}
	return starlark.String(key), nil
}
