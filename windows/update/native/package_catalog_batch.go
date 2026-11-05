package native

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func packageCatalogBatchBuiltin(index *uup.PackageMetadataIndex) *starlark.Builtin {
	return starlark.NewBuiltin("servicing_metadata.open_catalogs", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var packages, manifestValues *starlark.List
		var callback starlark.Callable
		workers := 4
		if err := starlark.UnpackArgs("open_catalogs", args, kwargs, "packages", &packages, "manifests?", &manifestValues, "workers?", &workers, "while_opening?", &callback); err != nil {
			return nil, err
		}
		if packages.Len() > 4096 || workers < 1 || workers > 8 || manifestValues != nil && manifestValues.Len() != packages.Len() {
			return nil, fmt.Errorf("open_catalogs requires at most 4096 paired entries and 1..8 workers")
		}
		names := make([]string, packages.Len())
		var manifests []*uup.ParsedAssemblyFile
		if manifestValues != nil {
			manifests = make([]*uup.ParsedAssemblyFile, len(names))
		}
		for i := range names {
			var ok bool
			names[i], ok = starlark.AsString(packages.Index(i))
			if !ok {
				return nil, fmt.Errorf("open_catalogs: package %d must be string", i)
			}
			if manifests != nil && manifestValues.Index(i) != starlark.None {
				if reader, ok := manifestValues.Index(i).(*starvalue.ReaderValue); ok {
					manifests[i], _ = reader.StorageReader().(*uup.ParsedAssemblyFile)
				}
				if manifests[i] == nil {
					return nil, fmt.Errorf("open_catalogs: manifest %d must be an owned package snapshot", i)
				}
			}
		}
		files, err := captureCatalogBatch(thread, callback, func() ([]storage.Reader, error) { return index.OpenCatalogMany(names, manifests, workers) })
		if err != nil {
			return nil, err
		}
		result := make([]starlark.Value, len(files))
		for i, file := range files {
			result[i] = starvalue.NewReader(names[i]+".cat", file)
		}
		return starlark.NewList(result), nil
	})
}

// Only native immutable reads run on the worker. Callback execution and all
// Starlark value construction stay on the caller. Even callback errors/panics
// join the native work before its input resources can be released.
func captureCatalogBatch(thread *starlark.Thread, callback starlark.Callable, read func() ([]storage.Reader, error)) ([]storage.Reader, error) {
	if callback == nil {
		return read()
	}
	var files []storage.Reader
	var workerErr error
	done := make(chan struct{})
	go func() { defer close(done); files, workerErr = read() }()
	defer func() { <-done }()
	_, err := starlark.Call(thread, callback, nil, nil)
	<-done
	if err != nil {
		return nil, err
	}
	if workerErr != nil {
		return nil, workerErr
	}
	return files, nil
}
