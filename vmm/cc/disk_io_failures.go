package cc

import (
	"fmt"
	"sync"
)

// diskIOFailures retains bounded backing-store diagnostics without changing I/O
// results. Controller/DMA validation errors are separate from these observations.
type diskIOFailures struct {
	mu     sync.Mutex
	count  uint64
	recent []diskIOFailure
}
type diskIOFailure struct {
	operation            string
	offset               int64
	requested, completed int
	message              string
}

func (d *diskIOFailures) record(operation string, offset int64, requested, completed int, err error) {
	if d == nil || (err == nil && requested == completed) {
		return
	}
	message := fmt.Sprintf("short %s", operation)
	if err != nil {
		message = err.Error()
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.count++
	if len(d.recent) == 16 {
		copy(d.recent, d.recent[1:])
		d.recent = d.recent[:15]
	}
	d.recent = append(d.recent, diskIOFailure{operation, offset, requested, completed, message})
}

func (d *diskIOFailures) snapshot() (uint64, []any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]any, len(d.recent))
	for i, f := range d.recent {
		result[i] = map[string]any{"operation": f.operation, "offset": f.offset,
			"requested": f.requested, "completed": f.completed, "error": f.message}
	}
	return d.count, result
}
