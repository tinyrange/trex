package filesystem

import "go.starlark.net/starlark"

// Clone creates an independently mutable tree, preserving every file identity,
// directory entry and metadata field. Immutable lazy file readers are borrowed
// without reading their payloads; their owner must outlive both trees, just as
// for Snapshot. Derived lookup caches are rebuilt independently on demand.
func (d *Directory) Clone() *Directory {
	snapshot := d.Snapshot()
	clone := &Directory{
		dirs:           make(map[string]struct{}, len(snapshot.Directories)),
		files:          snapshot.Files,
		attributes:     snapshot.Attributes,
		metadata:       snapshot.Metadata,
		hardLinkRefs:   make(map[uint64]uint64, len(d.hardLinkRefs)),
		hardLinkNames:  make(map[uint64][]string, len(d.hardLinkNames)),
		nextHardLink:   d.nextHardLink,
		nextWriteOrder: d.nextWriteOrder,
		revision:       d.revision,
	}
	for _, name := range snapshot.Directories {
		clone.dirs[name] = struct{}{}
	}
	for id, count := range d.hardLinkRefs {
		clone.hardLinkRefs[id] = count
	}
	for id, names := range d.hardLinkNames {
		clone.hardLinkNames[id] = append([]string(nil), names...)
	}
	return clone
}

func (d *Directory) cloneBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("clone", args, kwargs); err != nil {
		return nil, err
	}
	return d.Clone(), nil
}
