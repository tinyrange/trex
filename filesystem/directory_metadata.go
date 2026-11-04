package filesystem

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// getMetadataBuiltin reports construction metadata, not metadata attached to
// the content reader. Replacement/lazy readers need not implement metadata.
// Zero timestamps mean unspecified; filesystem-builder defaults are not applied.
func (d *Directory) getMetadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("get_metadata", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	name = storage.CleanPath(name)
	if _, ok := d.dirs[name]; !ok {
		if _, ok := d.files[name]; !ok {
			return nil, fmt.Errorf("get_metadata: path %q does not exist", name)
		}
	}
	m := d.metadata[name]
	return starfile.NewRecord(starlark.StringDict{
		"extended_attributes": extendedAttributesValue(m.ExtendedAttributes),
		"creation_time":       starlark.MakeUint64(m.CreationTime),
		"last_write_time":     starlark.MakeUint64(m.LastWriteTime),
		"last_access_time":    starlark.MakeUint64(m.LastAccessTime),
		"hard_link_id":        starlark.MakeUint64(m.HardLink),
		// Local path binding generation, not a digest or filesystem timestamp.
		"write_order":         starlark.MakeUint64(d.files[name].WriteOrder),
		"file_attributes":     starlark.MakeUint64(uint64(m.FileAttributes)),
		"has_file_attributes": starlark.Bool(m.HasFileAttributes),
	}), nil
}

func (d *Directory) setTimesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var creation, write, access uint64
	if err := starlark.UnpackArgs("set_times", args, kwargs, "name", &name, "creation_time", &creation, "last_write_time", &write, "last_access_time", &access); err != nil {
		return nil, err
	}
	if err := d.SetTimes(name, creation, write, access); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// SetTimes sets raw Windows FILETIME timestamps on an existing file identity
// (all hardlink aliases) or directory, preserving all other metadata.
func (d *Directory) SetTimes(name string, creation, write, access uint64) error {
	name = storage.CleanPath(name)
	if _, ok := d.dirs[name]; !ok {
		if _, ok := d.files[name]; !ok {
			return fmt.Errorf("set_times: path %q does not exist", name)
		}
	}
	m := d.metadata[name]
	m.CreationTime, m.LastWriteTime, m.LastAccessTime = creation, write, access
	d.SetMetadata(name, m)
	if m.HardLink != 0 && d.hardLinkRefs[m.HardLink] > 1 {
		for _, alias := range d.hardLinkNames[m.HardLink] {
			other := d.metadata[alias]
			if other.HardLink == m.HardLink {
				other.CreationTime, other.LastWriteTime, other.LastAccessTime = creation, write, access
				d.metadata[alias] = other
			}
		}
	}
	return nil
}
