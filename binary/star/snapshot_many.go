package star

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// A batch owns one read-cache budget, rather than one per small file. Validate
// every source and the total bound before starting any reads.
func binarySnapshotManyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values starlark.Iterable
	maximum, cacheBytes := int64(defaultBinaryBuilderLimit), int64(1<<20)
	if err := starlark.UnpackArgs("binary.snapshot_many", args, kwargs, "files", &values, "maximum?", &maximum, "cache_bytes?", &cacheBytes); err != nil {
		return nil, err
	}
	if maximum < 0 || cacheBytes < 0 || cacheBytes > maximum {
		return nil, fmt.Errorf("binary.snapshot_many: require 0 <= cache_bytes <= maximum")
	}
	it := values.Iterate()
	defer it.Done()
	var value starlark.Value
	var files []starfile.File
	var total int64
	for it.Next(&value) {
		if len(files) >= 65536 {
			return nil, fmt.Errorf("binary.snapshot_many: too many files")
		}
		f, ok := value.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("binary.snapshot_many: got %s, want file", value.Type())
		}
		size := f.Size()
		if size < 0 || size > maximum-total {
			return nil, fmt.Errorf("binary.snapshot_many: aggregate size exceeds maximum")
		}
		total += size
		files = append(files, f)
	}
	store, err := starfile.NewPackedFileStore(cacheBytes, true)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, 0, len(files))
	var copied int64
	for _, f := range files {
		snapshot, err := store.Snapshot("snapshot", f, maximum-copied)
		if err != nil {
			return nil, err
		}
		copied += snapshot.Size()
		result = append(result, snapshot)
	}
	return starlark.NewList(result), nil
}
