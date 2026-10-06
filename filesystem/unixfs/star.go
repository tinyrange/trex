package unixfs

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ParseEntries accepts dictionaries, preserving payload readers without copying.
func ParseEntries(value starlark.Value) ([]Entry, error) {
	iter := starlark.Iterate(value)
	if iter == nil {
		return nil, fmt.Errorf("entries: expected iterable")
	}
	defer iter.Done()
	var out []Entry
	var v starlark.Value
	for iter.Next(&v) {
		if len(out) >= 1000000 {
			return nil, fmt.Errorf("entries: too many entries")
		}
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("entry: expected dict")
		}
		e := Entry{Mode: Regular | 0644}
		for _, pair := range d.Items() {
			key, ok := starlark.AsString(pair[0])
			if !ok {
				return nil, fmt.Errorf("entry: field must be string")
			}
			val := pair[1]
			var dst *uint32
			switch key {
			case "path":
				e.Path, ok = starlark.AsString(val)
				if !ok {
					return nil, fmt.Errorf("entry: path must be string")
				}
			case "target":
				e.Target, ok = starlark.AsString(val)
				if !ok {
					return nil, fmt.Errorf("entry: target must be string")
				}
			case "hardlink":
				b, ok := val.(starlark.Bool)
				if !ok {
					return nil, fmt.Errorf("entry: hardlink must be bool")
				}
				e.Hardlink = bool(b)
			case "data":
				switch v := val.(type) {
				case storage.Reader:
					e.Data = v
				case starlark.String:
					e.Data = &starfile.Bytes{Data: []byte(v)}
				case starlark.Bytes:
					e.Data = &starfile.Bytes{Data: []byte(v)}
				default:
					return nil, fmt.Errorf("entry: data must be file, string or bytes")
				}
			case "mode":
				dst = &e.Mode
			case "uid":
				dst = &e.UID
			case "gid":
				dst = &e.GID
			case "mtime":
				dst = &e.Mtime
			case "major":
				dst = &e.Major
			case "minor":
				dst = &e.Minor
			default:
				return nil, fmt.Errorf("entry: unknown field %q", key)
			}
			if dst != nil {
				if err := starlark.AsInt(val, dst); err != nil {
					return nil, fmt.Errorf("entry: %s: %w", key, err)
				}
			}
		}
		out = append(out, e)
	}
	return out, nil
}
