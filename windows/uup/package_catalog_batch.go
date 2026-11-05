package uup

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"sync"
	"sync/atomic"
)

// OpenCatalogMany captures exact companion catalogs on bounded workers. The
// source must support concurrent reads. Optional manifests must be exact owned
// snapshots from this index; nil entries retain ordinary identity validation.
// No signature or trust decision is made here. All workers join before return.
// Results own their bytes and preserve input order (including duplicates).
func (index *PackageMetadataIndex) OpenCatalogMany(names []string, manifests []*ParsedAssemblyFile, workers int) ([]storage.Reader, error) {
	if len(names) > 4096 || workers < 1 || workers > 8 || manifests != nil && len(manifests) != len(names) {
		return nil, fmt.Errorf("catalog batch requires at most 4096 paired entries and 1..8 workers")
	}
	results := make([]storage.Reader, len(names))
	failures := make([]error, len(names))
	var reserved atomic.Int64
	var group sync.WaitGroup
	workers = min(workers, len(names))
	for w := 0; w < workers; w++ {
		group.Add(1)
		go func(start int) {
			defer group.Done()
			for i := start; i < len(names); i += workers {
				var manifest *ParsedAssemblyFile
				if manifests != nil {
					manifest = manifests[i]
				}
				file, err := index.OpenCatalogWithManifest(names[i], manifest)
				if err != nil {
					failures[i] = err
					continue
				}
				size := file.Size()
				if size < 0 || size > 64<<20 {
					failures[i] = fmt.Errorf("catalog size exceeds bound")
					continue
				}
				if reserved.Add(size) > 256<<20 {
					failures[i] = fmt.Errorf("catalog batch exceeds 256 MiB")
					continue
				}
				data := make([]byte, int(size))
				if _, err := io.ReadFull(io.NewSectionReader(file, 0, size), data); err != nil {
					failures[i] = err
					continue
				}
				results[i] = bytes.NewReader(data)
			}
		}(w)
	}
	group.Wait()
	for i, err := range failures {
		if err != nil {
			return nil, fmt.Errorf("catalog input %d: %w", i, err)
		}
	}
	return results, nil
}
