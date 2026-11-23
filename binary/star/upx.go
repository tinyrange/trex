package star

import (
	"github.com/tinyrange/trex/binary/upx"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func upxDOSImageBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	if err := starlark.UnpackArgs("upx_dos_image", args, kwargs, "source", &source, "header_offset", &offset); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	image, err := upx.DOSImage(view, offset)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "upx.dos.image", Data: image}, nil
}
