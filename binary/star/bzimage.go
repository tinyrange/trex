package star

import (
	"fmt"

	"github.com/tinyrange/trex/boot/linux"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func bzimagePayloadBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("bzimage_payload", args, kwargs, "file", &source); err != nil {
		return nil, err
	}
	file, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("bzimage_payload: expected a file")
	}
	image, err := linux.OpenBZImage(file)
	if err != nil {
		return nil, err
	}
	payload, err := image.KernelPayload()
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("bzImage kernel payload", payload), nil
}

func bzimageReleaseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("bzimage_release", args, kwargs, "file", &source); err != nil {
		return nil, err
	}
	file, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("bzimage_release: expected a file")
	}
	image, err := linux.OpenBZImage(file)
	if err != nil {
		return nil, err
	}
	release, err := image.KernelRelease()
	if err != nil {
		return nil, err
	}
	return starlark.String(release), nil
}
