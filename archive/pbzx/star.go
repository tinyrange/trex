package pbzx

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("pbzx", 10, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 4 || string(p[:4]) != "pbzx" {
			return nil, auto.ErrNoMatch
		}
		f, err := Open(r, o.StreamingMaximum())
		if err != nil {
			return nil, err
		}
		return &auto.DecodedView{Reader: f, Format: "pbzx", Attributes: map[string]any{"chunks": len(f.Chunks), "decoded_size": f.Size()}}, nil
	})
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var maximum int64
	if err := starlark.UnpackArgs("pbzx", args, kwargs, "file", &value, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("pbzx: expected file")
	}
	f, err := Open(r, maximum)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("payload.cpio", f), nil
}
