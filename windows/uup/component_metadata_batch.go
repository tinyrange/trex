package uup

import (
	"fmt"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// OpenMany resolves explicit exact identities with bounded parallel native reads.
// Results preserve input order, including duplicates and nil for unavailable
// identities. Invalid metadata fails the entire request after all workers join;
// the lowest failing input index determines the error. The index's underlying
// reader must support concurrent reads. No applicability or ownership is inferred.
func (index *ComponentMetadataIndex) OpenMany(identities [][]byte, workers int) ([]storage.Reader, error) {
	if workers < 1 || workers > 8 {
		return nil, fmt.Errorf("component metadata workers must be between 1 and 8")
	}
	if len(identities) > 65536 {
		return nil, fmt.Errorf("component metadata batch exceeds 65536 identities")
	}
	result := make([]storage.Reader, len(identities))
	errors := make([]error, len(identities))
	workers = min(workers, len(identities))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(start int) {
			defer group.Done()
			for i := start; i < len(identities); i += workers {
				result[i], _, errors[i] = index.Open(identities[i])
			}
		}(worker)
	}
	group.Wait()
	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("component metadata identity %d: %w", i, err)
		}
	}
	return result, nil
}
