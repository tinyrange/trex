package filesystem

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"path"
)

func (d *Directory) rmdirBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("rmdir", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	if err := d.RemoveEmptyDirectory(name); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// RemoveEmptyDirectory removes one existing empty directory, never a subtree.
// FileMap/ownership policy belongs to the caller, not this filesystem primitive.
func (d *Directory) RemoveEmptyDirectory(name string) error {
	name = storage.CleanPath(name)
	if name == "/" {
		return fmt.Errorf("rmdir: cannot remove the root directory")
	}
	if _, ok := d.dirs[name]; !ok {
		return fmt.Errorf("rmdir: directory %q does not exist", name)
	}
	d.ensureChildren()
	if _, file := d.files[name]; file || len(d.children[name]) != 0 {
		return fmt.Errorf("rmdir: directory %q is not empty", name)
	}
	parent := path.Dir(name)
	children := d.children[parent]
	for i, child := range children {
		if child == name {
			d.children[parent] = append(children[:i], children[i+1:]...)
			break
		}
	}
	delete(d.children, name)
	delete(d.dirs, name)
	d.SetMetadata(name, Metadata{})
	delete(d.metadata, name)
	delete(d.attributes, name)
	d.invalidateNamespace()
	d.childrenRevision = d.revision
	d.fatShortValid = false
	return nil
}
