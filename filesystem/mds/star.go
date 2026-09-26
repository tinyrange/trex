package mds

import (
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Builtin accepts an explicit mapping from descriptor filenames to portable
// files. In particular {"*.mdf": image} binds the standard wildcard directly.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starlark.Value
	var images *starlark.Dict
	if err := starlark.UnpackArgs("mds", args, kwargs, "file", &file, "images?", &images); err != nil {
		return nil, err
	}
	source, ok := file.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("mds: expected file")
	}
	image, err := Open(source)
	if err != nil {
		return nil, err
	}
	var resolve Resolver
	if images != nil && images.Len() != 0 {
		files := map[string]storage.Reader{}
		for _, item := range images.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("mds: image name must be string")
			}
			r, ok := item[1].(storage.Reader)
			if !ok {
				return nil, fmt.Errorf("mds: image %q must be file", name)
			}
			files[name] = r
		}
		resolve = func(name string) (storage.Reader, error) {
			r := files[name]
			if r == nil {
				return nil, fmt.Errorf("mds: missing image %q", name)
			}
			return r, nil
		}
	}
	view, err := image.View(resolve)
	if err != nil {
		return nil, err
	}
	return &value{image: image, view: view, resolve: resolve}, nil
}

type value struct {
	image   *Image
	view    auto.View
	resolve Resolver
}

func (*value) String() string                               { return "<mds>" }
func (*value) Type() string                                 { return "mds" }
func (*value) Freeze()                                      {}
func (*value) Truth() starlark.Bool                         { return true }
func (*value) Hash() (uint32, error)                        { return 0, fmt.Errorf("unhashable mds") }
func (v *value) AutoView(_ auto.Options) (auto.View, error) { return v.view, nil }
func (*value) AttrNames() []string                          { return []string{"version", "medium", "sessions"} }
func (v *value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "version":
		return starlark.String(fmt.Sprintf("%d.%d", v.image.Version[0], v.image.Version[1])), nil
	case "medium":
		return starlark.MakeInt(int(v.image.Medium)), nil
	case "sessions":
		var sessions []starlark.Value
		for _, s := range v.image.Sessions {
			var tracks []starlark.Value
			for _, t := range s.Tracks {
				a := starlark.StringDict{}
				for k, val := range t.Attributes() {
					switch val := val.(type) {
					case int:
						a[k] = starlark.MakeInt(val)
					case int64:
						a[k] = starlark.MakeInt64(val)
					case uint64:
						a[k] = starlark.MakeUint64(val)
					case []string:
						vs := make([]starlark.Value, len(val))
						for i, n := range val {
							vs[i] = starlark.String(n)
						}
						a[k] = starlark.NewList(vs)
					}
				}
				a["raw"], a["data"], a["subchannel"] = starlark.None, starlark.None, starlark.None
				if v.resolve != nil {
					r, err := t.Readers(v.resolve)
					if err != nil {
						return nil, err
					}
					a["raw"], a["data"] = adapter.File(r.Raw), adapter.File(r.Data)
					if r.Subchannel != nil {
						a["subchannel"] = adapter.File(r.Subchannel)
					}
				}
				tracks = append(tracks, starfile.NewRecord(a))
			}
			var toc []starlark.Value
			for _, b := range s.TOC {
				toc = append(toc, starlark.Bytes(b))
			}
			sessions = append(sessions, starfile.NewRecord(starlark.StringDict{"number": starlark.MakeInt(int(s.Number)), "start_lba": starlark.MakeInt64(int64(s.Start)), "end_lba": starlark.MakeInt64(int64(s.End)), "first_track": starlark.MakeInt(int(s.FirstTrack)), "last_track": starlark.MakeInt(int(s.LastTrack)), "toc": starlark.NewList(toc), "tracks": starlark.NewList(tracks)}))
		}
		return starlark.NewList(sessions), nil
	}
	return nil, nil
}
