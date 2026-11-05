package wim

import (
	"fmt"
	"sync"
	"testing"
)

// Image preparation traverses directories while the update planner opens hives
// from the same archive. Both operations must safely populate the lazy indexes.
func TestConcurrentDirectoryTraversalAndLookup(t *testing.T) {
	names := make([]string, 512)
	for i := range names {
		names[i] = fmt.Sprintf("file%03d", i)
	}
	a := indexedLookupFixture(names)
	start := make(chan struct{})
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			<-start
			for n := 0; n < 64; n++ {
				if worker%2 == 0 {
					entries, err := a.dirEntries("/image1")
					if err != nil || len(entries) != len(names) {
						t.Errorf("directory: len=%d err=%v", len(entries), err)
						return
					}
				} else {
					name := names[(worker+n)%len(names)]
					entry, err := a.lookupPath("/IMAGE1/" + name)
					if err != nil || entry.name != name {
						t.Errorf("lookup %s: %s, %v", name, entry.name, err)
						return
					}
				}
			}
		}(worker)
	}
	close(start)
	group.Wait()
}
