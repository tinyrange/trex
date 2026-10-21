package star

import (
	_ "embed"
	"go.starlark.net/starlark"
)

//go:embed extension_protocol.md
var extensionProtocol string

func extensionProtocolBuiltin(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("channel.extension_protocol", a, k); err != nil {
		return nil, err
	}
	return starlark.String(extensionProtocol), nil
}
