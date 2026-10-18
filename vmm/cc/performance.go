package cc

import (
	"fmt"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

// Optional, bounded counters owned by the device coordinator. Durations are
// host wall time, not guest CPU time. Inspection stops and joins all CPUs.
type latencyCounter struct {
	Count, Bytes, Nanoseconds, MaxNanoseconds uint64
	Buckets                                   [24]uint64 // <=1us, <=2us, ... <=4194304us, then overflow
}

func (c *latencyCounter) add(elapsed time.Duration, bytes int) {
	if elapsed < 0 {
		elapsed = 0
	}
	n := uint64(elapsed)
	c.Count++
	c.Bytes += uint64(max(bytes, 0))
	c.Nanoseconds += n
	c.MaxNanoseconds = max(c.MaxNanoseconds, n)
	b, limit := 0, uint64(1000)
	for b < len(c.Buckets)-1 && n > limit {
		b++
		limit *= 2
	}
	c.Buckets[b]++
}
func (c *latencyCounter) value() any {
	buckets := make([]any, len(c.Buckets))
	for i, n := range c.Buckets {
		buckets[i] = n
	}
	return map[string]any{"count": c.Count, "bytes": c.Bytes, "ns": c.Nanoseconds, "max_ns": c.MaxNanoseconds, "buckets": buckets}
}

type pcPerformance struct {
	started                               time.Time
	IO                                    map[string]*latencyCounter
	Completion, Read, ReadDelivery, Write latencyCounter
}

func (p *pcPerformance) io(key string, elapsed time.Duration) {
	c := p.IO[key]
	if c == nil {
		if len(p.IO) >= 256 {
			key = "other"
			c = p.IO[key]
		}
		if c == nil {
			c = &latencyCounter{}
			p.IO[key] = c
		}
	}
	c.add(elapsed, 0)
}
func (i inspection) performance(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	enable := false
	if err := starlark.UnpackArgs("cc.performance", args, kwargs, "enable?", &enable); err != nil {
		return nil, err
	}
	var out starlark.Value
	err := i.driver.call(i.ctx, func() error {
		p := i.driver.pc
		if enable && p.performance == nil {
			p.performance = &pcPerformance{started: time.Now(), IO: make(map[string]*latencyCounter)}
		}
		stats := p.performance
		if stats == nil {
			out = starlark.None
			return nil
		}
		io := map[string]any{}
		for key, c := range stats.IO {
			io[key] = c.value()
		}
		var err error
		out, err = starvalue.Starlark(map[string]any{"elapsed_ns": uint64(time.Since(stats.started)), "io": io, "completion": stats.Completion.value(), "dma_read": stats.Read.value(), "dma_delivery": stats.ReadDelivery.value(), "dma_write": stats.Write.value()})
		return err
	})
	return out, err
}
func performanceIOKey(write bool, address uint64, mmio bool) string {
	kind := "io"
	if mmio {
		kind = "mmio"
		// VGA aperture probing must not consume the bounded register table.
		if address >= 0xa0000 && address < 0xc0000 {
			address = 0xa0000
		}
	}
	direction := "read"
	if write {
		direction = "write"
	}
	return fmt.Sprintf("%s_%s_%x", kind, direction, address)
}
