package cc

import (
	"sync"
	"time"
)

// diskIOTiming bounds slow backing-operation observations independently of
// success/error diagnostics. Guest timeouts can precede successful backing I/O.
type diskIOTiming struct {
	mu      sync.Mutex
	maximum time.Duration
	slow    uint64
	recent  []map[string]any
}

func (d *diskIOTiming) record(operation string, offset int64, size int, elapsed time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if elapsed > d.maximum {
		d.maximum = elapsed
	}
	if elapsed < time.Second {
		return
	}
	d.slow++
	if len(d.recent) == 16 {
		copy(d.recent, d.recent[1:])
		d.recent = d.recent[:15]
	}
	d.recent = append(d.recent, map[string]any{"operation": operation, "offset": offset, "requested": size, "nanoseconds": uint64(elapsed)})
}
func (d *diskIOTiming) snapshot() (uint64, uint64, []any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	recent := make([]any, len(d.recent))
	for i, row := range d.recent {
		copied := make(map[string]any, len(row))
		for key, value := range row {
			copied[key] = value
		}
		recent[i] = copied
	}
	return uint64(d.maximum), d.slow, recent
}
