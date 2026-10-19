package starlarkfrontend

import (
	"errors"

	blocknative "github.com/tinyrange/trex/block/native"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

// Native resource policy belongs to the frontend, not the portable block API.
// Create backing before its VM: runtime resources close in reverse order.
func temporaryOverlayBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var base starlark.Value
	var directory string
	if err := starlark.UnpackArgs("temporary_overlay", args, kwargs, "base", &base, "directory", &directory); err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	device, err := blockstar.AsDevice(base)
	if err != nil {
		return nil, err
	}
	overlay, err := blocknative.NewTemporaryOverlay(device, directory)
	if err != nil {
		return nil, err
	}
	if _, err := resources.Add(overlay); err != nil {
		return nil, errors.Join(err, overlay.Close())
	}
	return blockstar.NewValue("temporary sparse", overlay), nil
}
