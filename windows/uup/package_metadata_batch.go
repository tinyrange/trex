package uup

import (
	"fmt"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// OpenMany validates exact package identities on bounded native workers. The
// index must have a concurrent-safe source, as native update stages do. Results
// preserve input order and duplicates, with fresh owned snapshots for each entry.
// Errors return no partial result, after all workers join; the first failing
// input, not the first worker to finish, determines the reported error.
func (index *PackageMetadataIndex) OpenMany(names []string, workers int) ([]storage.Reader, error) {
	if workers < 1 || workers > 8 || len(names) > 4096 {
		return nil, fmt.Errorf("package metadata batch requires at most 4096 names and 1..8 workers")
	}
	result := make([]storage.Reader, len(names))
	errors := make([]error, len(names))
	workers = min(workers, len(names))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(start int) {
			defer group.Done()
			for i := start; i < len(names); i += workers {
				result[i], errors[i] = index.Open(names[i])
			}
		}(worker)
	}
	group.Wait()
	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("package metadata input %d: %w", i, err)
		}
	}
	return result, nil
}
