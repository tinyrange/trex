package wim

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"go.starlark.net/starlark"
)

// prefetchBuiltin prepares an explicit file set in physical resource order.
// Unlike filesystem traversal order, this reuses large solid chunks before
// they leave the bounded cache. It never changes or persists source data.
func (w *Archive) prefetchBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var paths *starlark.List
	if err := starlark.UnpackArgs("prefetch", args, kwargs, "paths", &paths); err != nil {
		return nil, err
	}
	if paths.Len() > 200000 {
		return nil, fmt.Errorf("wim: prefetch path count exceeds 200000")
	}
	files := make([]*File, 0, paths.Len())
	seen := make(map[[20]byte]bool)
	for i := 0; i < paths.Len(); i++ {
		name, ok := starlark.AsString(paths.Index(i))
		if !ok {
			return nil, fmt.Errorf("wim: prefetch paths must be strings")
		}
		item, found, err := w.Get(starlark.String(name))
		if err != nil {
			return nil, err
		}
		file, ok := item.(*File)
		if !found || !ok {
			return nil, fmt.Errorf("wim: prefetch path %q is not an available file", name)
		}
		// Modern WIMs legitimately represent empty streams with a zero hash
		// and no lookup resource. They are available without any payload I/O.
		if file.entry.size == 0 && file.entry.hash == ([20]byte{}) {
			continue
		}
		if file.reader == nil {
			return nil, fmt.Errorf("wim: prefetch resource for %q is unavailable", name)
		}
		if file.entry.size <= 0 || w.blobCache == nil || file.location == nil || file.location.resource.flags&wimResourceSolid == 0 || file.location.resource.compression != 3 {
			continue
		}
		if !seen[file.entry.hash] {
			files = append(files, file)
			seen[file.entry.hash] = true
		}
	}
	slices.SortFunc(files, func(a, b *File) int {
		x, y := a.location, b.location
		if c := compareInt64(int64(x.archive.cacheSource), int64(y.archive.cacheSource)); c != 0 {
			return c
		}
		if c := compareInt64(x.resource.offset, y.resource.offset); c != 0 {
			return c
		}
		return compareInt64(x.blobOffset, y.blobOffset)
	})
	var groups [][]*File
	var total int64
	for _, file := range files {
		total += file.entry.size
		same := false
		if len(groups) > 0 {
			previous := groups[len(groups)-1][0].location
			current := file.location
			same = previous.archive == current.archive && previous.resource.offset == current.resource.offset && previous.blobOffset/int64(max(1, previous.resource.chunkSize)) == current.blobOffset/int64(max(1, current.resource.chunkSize))
		}
		if !same {
			groups = append(groups, nil)
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], file)
	}
	// Each worker traverses one solid chunk's files together. Parallelism is
	// across independent chunks, never a storm of duplicate prefix decodes.
	jobs := make(chan []*File, len(groups))
	for _, group := range groups {
		jobs <- group
	}
	close(jobs)
	workers := min(4, len(groups))
	errors := make(chan error, workers)
	var failed atomic.Bool
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			for group := range jobs {
				if failed.Load() {
					return
				}
				for _, file := range group {
					for offset := int64(0); offset < file.entry.size; offset += min(solidBlobSegmentSize, file.entry.size-offset) {
						if _, err := file.ReadAt(make([]byte, 1), offset); err != nil {
							failed.Store(true)
							errors <- err
							return
						}
					}
				}
			}
		}()
	}
	done.Wait()
	close(errors)
	if err := <-errors; err != nil {
		return nil, err
	}
	return starlark.MakeInt64(total), nil
}

func compareInt64(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
