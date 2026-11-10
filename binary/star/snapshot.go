package star

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func binarySnapshotBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, cacheBytes := int64(defaultBinaryBuilderLimit), int64(starfile.PackedChunkBytes)
	if err := starlark.UnpackArgs("binary.snapshot", args, kwargs, "file", &value, "maximum?", &maximum, "cache_bytes?", &cacheBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("binary.snapshot: got %s, want file", value.Type())
	}
	if maximum < 0 || cacheBytes < 0 || cacheBytes > maximum {
		return nil, fmt.Errorf("binary.snapshot: require 0 <= cache_bytes <= maximum")
	}
	store, err := starfile.NewPackedFileStore(cacheBytes, false)
	if err != nil {
		return nil, err
	}
	return store.Snapshot("snapshot", file, maximum)
}
