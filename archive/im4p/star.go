package im4p

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("im4p", 15, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 2 || p[0] != 0x30 {
			return nil, auto.ErrNoMatch
		}
		// Inspect only the bounded first DER string; ordinary ASN.1 is not IM4P.
		_, h, n, err := header(r, 0, r.Size())
		if err != nil {
			return nil, auto.ErrNoMatch
		}
		tag, inner, size, err := header(r, h, h+n)
		if err != nil || tag != 0x16 || size != 4 {
			return nil, auto.ErrNoMatch
		}
		var sig [4]byte
		if _, err := r.ReadAt(sig[:], h+inner); err != nil {
			return nil, err
		}
		if string(sig[:]) != "IM4P" {
			return nil, auto.ErrNoMatch
		}
		f, err := Open(r)
		if err != nil {
			return nil, err
		}
		return &auto.DecodedView{Reader: f.Payload, Format: "im4p", Attributes: map[string]any{"type": f.Type, "description": f.Description, "expected_size": f.ExpectedSize}}, nil
	})
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("im4p", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("im4p: expected file")
	}
	f, err := Open(r)
	if err != nil {
		return nil, err
	}
	extras := make([]starlark.Value, len(f.Extras))
	for i, n := range f.Extras {
		extras[i] = starfile.NewReader("metadata.der", n.Raw)
	}
	return starfile.NewRecord(starlark.StringDict{"payload_type": starlark.String(f.Type), "description": starlark.String(f.Description), "payload": starfile.NewReader("payload", f.Payload), "extras": starlark.NewList(extras), "expected_size": starlark.MakeInt64(f.ExpectedSize)}), nil
}
