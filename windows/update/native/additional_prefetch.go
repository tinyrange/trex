package native

import (
	"sync"

	"github.com/tinyrange/trex/windows/uup"
)

// Additional packages are immutable, independently verified inputs. Only their
// parsing may overlap: predecessor binding and publication remain on the caller
// in the declared stage order. No worker invokes Starlark or touches the planner.
type additionalStageResult struct {
	done  chan struct{}
	stage *uup.CumulativeStage
	err   error
}

type additionalStageBatch struct {
	results map[string]*additionalStageResult
	workers sync.WaitGroup
}

// Two parsers share the existing bounded metadata cache. The caller must join
// on every exit, including errors, before releasing sources or read caches.
func prefetchAdditionalStages(inputs []additionalCabinet, open func(additionalCabinet) (*uup.CumulativeStage, error)) *additionalStageBatch {
	batch := &additionalStageBatch{results: make(map[string]*additionalStageResult, len(inputs))}
	jobs := make(chan additionalCabinet, len(inputs))
	for _, input := range inputs {
		batch.results[input.feature] = &additionalStageResult{done: make(chan struct{})}
		jobs <- input
	}
	close(jobs)
	for range min(2, len(inputs)) {
		batch.workers.Add(1)
		go func() {
			defer batch.workers.Done()
			for input := range jobs {
				result := batch.results[input.feature]
				result.stage, result.err = open(input)
				close(result.done)
			}
		}()
	}
	return batch
}

func (b *additionalStageBatch) get(feature string) (*uup.CumulativeStage, error) {
	result := b.results[feature]
	<-result.done
	return result.stage, result.err
}

func (b *additionalStageBatch) join() { b.workers.Wait() }
