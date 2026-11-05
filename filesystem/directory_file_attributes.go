package filesystem

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func (d *Directory) setFileAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var attributes uint32
	if err := starlark.UnpackArgs("set_file_attributes", args, kwargs, "name", &name, "attributes", &attributes); err != nil {
		return nil, err
	}
	if err := d.SetFileAttributes(name, attributes); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// SetFileAttributes replaces ordinary Windows basic-information attributes on
// an existing object. Structural flags (directory/reparse/compression) are not
// settable through this entry point. NORMAL is ignored with other attributes.
// Shared metadata is updated for every hardlink, not only its directory entry.
func (d *Directory) SetFileAttributes(name string, attributes uint32) error {
	name = storage.CleanPath(name)
	_, directory := d.dirs[name]
	if !directory {
		if _, ok := d.files[name]; !ok {
			return fmt.Errorf("set_file_attributes: path %q does not exist", name)
		}
	}
	const writable = uint32(0x1 | 0x2 | 0x4 | 0x20 | 0x80 | 0x100 | 0x1000 | 0x2000)
	if attributes & ^writable != 0 {
		return fmt.Errorf("set_file_attributes: unsupported basic-information attributes %#x", attributes)
	}
	attributes &^= 0x80
	m := d.metadata[name]
	// Preserve non-basic flags belonging to the object representation.
	m.FileAttributes = (m.FileAttributes & ^(writable | 0x10)) | attributes
	if directory {
		m.FileAttributes |= 0x10
	}
	m.HasFileAttributes = true
	d.SetMetadata(name, m)
	delete(d.attributes, name)
	if m.HardLink != 0 && d.hardLinkRefs[m.HardLink] > 1 {
		for _, alias := range d.hardLinkNames[m.HardLink] {
			other := d.metadata[alias]
			if other.HardLink == m.HardLink {
				other.FileAttributes, other.HasFileAttributes = m.FileAttributes, true
				d.metadata[alias] = other
				delete(d.attributes, alias)
			}
		}
	}
	return nil
}
