package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs("cdf_decode", args, kwargs, "data", &value); e != nil {
		return nil, e
	}
	b, ok := value.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("cdf_decode: data must be bytes")
	}
	if len(b) > cdf.MaxSize {
		return nil, fmt.Errorf("CDF input exceeds 64 MiB")
	}
	d, e := cdf.Parse([]byte(b))
	if e != nil {
		return nil, e
	}
	out := starlark.NewDict(9)
	put := func(k string, v starlark.Value) { _ = out.SetKey(starlark.String(k), v) }
	ids := func(values []uint32) *starlark.List {
		result := make([]starlark.Value, len(values))
		for i, v := range values {
			result[i] = starlark.MakeUint64(uint64(v))
		}
		return starlark.NewList(result)
	}
	put("flags", starlark.MakeUint64(uint64(d.Flags)))
	put("format", starlark.Bytes(d.Format[:]))
	put("root", starlark.MakeUint64(uint64(d.Root)))
	put("auxiliary_root", starlark.MakeUint64(uint64(d.AuxiliaryRoot)))
	put("strings", ids(d.Strings))
	put("identities", ids(d.Identities))
	put("appids", ids(d.AppIDs))
	guids := make([]starlark.Value, len(d.GUIDs))
	for i, g := range d.GUIDs {
		guids[i] = starlark.Bytes(g[:])
	}
	put("guids", starlark.NewList(guids))
	blobs := make([]starlark.Value, len(d.Blobs))
	for i, b := range d.Blobs {
		blobs[i] = starlark.Tuple{starlark.MakeInt(int(b.Kind)), starlark.Bytes(b.Data)}
	}
	put("blobs", starlark.NewList(blobs))
	return out, nil
}

func cdfEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value *starlark.Dict
	if e := starlark.UnpackArgs("cdf_encode", args, kwargs, "document", &value); e != nil {
		return nil, e
	}
	if value.Len() != 9 {
		return nil, fmt.Errorf("cdf_encode: expected exactly nine document fields")
	}
	get := func(key string) (starlark.Value, error) {
		v, ok, e := value.Get(starlark.String(key))
		if e != nil {
			return nil, e
		}
		if !ok {
			return nil, fmt.Errorf("cdf_encode: missing %s", key)
		}
		return v, nil
	}
	uint32Value := func(v starlark.Value) (uint32, error) {
		n, ok := v.(starlark.Int)
		if !ok {
			return 0, fmt.Errorf("cdf_encode: expected uint32")
		}
		u, ok := n.Uint64()
		if !ok || u > 0xffffffff {
			return 0, fmt.Errorf("cdf_encode: integer outside uint32")
		}
		return uint32(u), nil
	}
	getUint := func(key string) (uint32, error) {
		v, e := get(key)
		if e != nil {
			return 0, e
		}
		return uint32Value(v)
	}
	sequence := func(key string) (starlark.Indexable, error) {
		v, e := get(key)
		if e != nil {
			return nil, e
		}
		switch v.(type) {
		case *starlark.List, starlark.Tuple:
		default:
			return nil, fmt.Errorf("cdf_encode: %s must be list or tuple", key)
		}
		s := v.(starlark.Indexable)
		if s.Len() > 1<<20 {
			return nil, fmt.Errorf("cdf_encode: too many %s", key)
		}
		return s, nil
	}
	d := &cdf.Document{}
	var e error
	if d.Flags, e = getUint("flags"); e != nil {
		return nil, e
	}
	if d.Root, e = getUint("root"); e != nil {
		return nil, e
	}
	if d.AuxiliaryRoot, e = getUint("auxiliary_root"); e != nil {
		return nil, e
	}
	format, e := get("format")
	if e != nil {
		return nil, e
	}
	f, ok := format.(starlark.Bytes)
	if !ok || len(f) != 16 {
		return nil, fmt.Errorf("cdf_encode: format must be 16 bytes")
	}
	copy(d.Format[:], f)
	for _, field := range []struct {
		name string
		out  *[]uint32
	}{{"strings", &d.Strings}, {"identities", &d.Identities}, {"appids", &d.AppIDs}} {
		s, e := sequence(field.name)
		if e != nil {
			return nil, e
		}
		*field.out = make([]uint32, s.Len())
		for i := 0; i < s.Len(); i++ {
			u, e := uint32Value(s.Index(i))
			if e != nil {
				return nil, e
			}
			(*field.out)[i] = u
		}
	}
	gs, e := sequence("guids")
	if e != nil {
		return nil, e
	}
	d.GUIDs = make([][16]byte, gs.Len())
	for i := 0; i < gs.Len(); i++ {
		g, ok := gs.Index(i).(starlark.Bytes)
		if !ok || len(g) != 16 {
			return nil, fmt.Errorf("cdf_encode: GUID must be 16 bytes")
		}
		copy(d.GUIDs[i][:], g)
	}
	bs, e := sequence("blobs")
	if e != nil {
		return nil, e
	}
	d.Blobs = make([]cdf.Blob, bs.Len())
	total := 0
	for i := 0; i < bs.Len(); i++ {
		pair, ok := bs.Index(i).(starlark.Tuple)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("cdf_encode: blob must be (kind, bytes) tuple")
		}
		k, e := uint32Value(pair[0])
		if e != nil || k > 255 {
			return nil, fmt.Errorf("cdf_encode: invalid blob kind")
		}
		data, ok := pair[1].(starlark.Bytes)
		if !ok {
			return nil, fmt.Errorf("cdf_encode: blob payload must be bytes")
		}
		if len(data) > 0xffffff || len(data) > cdf.MaxSize-total {
			return nil, fmt.Errorf("cdf_encode: blob size limit")
		}
		total += len(data)
		d.Blobs[i] = cdf.Blob{Kind: uint8(k), Data: []byte(data)}
	}
	out, e := d.Marshal()
	if e != nil {
		return nil, e
	}
	return starlark.Bytes(out), nil
}
