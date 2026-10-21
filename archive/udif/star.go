package udif

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("udif", 90, func(_ []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if stream, ok := r.(interface{ KnownSize() (int64, bool) }); ok {
			if _, known := stream.KnownSize(); !known {
				return nil, auto.ErrNoMatch
			}
		}
		if r.Size() < 512 {
			return nil, auto.ErrNoMatch
		}
		var sig [4]byte
		if _, err := r.ReadAt(sig[:], r.Size()-512); err != nil {
			return nil, err
		}
		if string(sig[:]) != "koly" {
			return nil, auto.ErrNoMatch
		}
		d, err := Open(r)
		if err != nil {
			return nil, err
		}
		return &auto.DecodedView{Reader: d, Name: "disk", Format: "udif", Attributes: map[string]any{"logical_size": d.Size(), "block_maps": len(d.Tables)}}, nil
	})
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("udif", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("udif: expected file")
	}
	d, err := Open(r)
	if err != nil {
		return nil, err
	}
	var tables []starlark.Value
	for _, t := range d.Tables {
		tables = append(tables, starfile.NewRecord(starlark.StringDict{"name": starlark.String(t.Name), "offset": starlark.MakeInt64(t.Offset), "size": starlark.MakeInt64(t.Size), "raw": starlark.Bytes(t.Raw)}))
	}
	verify := starlark.NewBuiltin("udif.verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
			return nil, err
		}
		if err := d.Verify(); err != nil {
			return nil, err
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"disk": starfile.NewReader("disk", d), "xml": starfile.NewReader("plist.xml", d.XML), "trailer": starfile.NewReader("koly", d.Trailer), "tables": starlark.NewList(tables), "verify": verify}), nil
}
