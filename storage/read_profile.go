package storage

import (
	"container/heap"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ReadProfileClock supplies concurrency-safe monotonic time. Native and virtual
// clocks can both be used; the profiler has no OS, path, or socket dependencies.
type ReadProfileClock interface{ Now() time.Duration }

type ReadStat struct {
	Label                           string
	Calls, Requested, Bytes, Errors int64
	Total, Max                      time.Duration
}
type ReadEvent struct {
	Label             string
	Offset            int64
	Requested, Bytes  int
	Started, Duration time.Duration
	Error             string
}
type ReadSnapshot struct {
	Elapsed                 time.Duration
	Total                   ReadStat
	Files                   []ReadStat
	Events                  []ReadEvent
	Unattributed, SlowReads int64
	TrackedFiles            int
}

// ReadProfiler records completed ReadAt calls, with bounded per-label statistics
// and the slowest individual calls. Nested wrappers are inclusive, not additive.
// It never executes scripting callbacks on an I/O worker or locks across I/O.
type ReadProfiler struct {
	mu                      sync.Mutex
	clock                   ReadProfileClock
	started                 time.Duration
	generation              atomic.Uint64
	maxFiles, maxEvents     int
	minimum                 time.Duration
	files                   map[string]*ReadStat
	events                  readEvents
	total                   ReadStat
	unattributed, slowReads int64
}

func NewReadProfiler(clock ReadProfileClock, maxFiles, maxEvents int, minimum time.Duration) (*ReadProfiler, error) {
	if clock == nil || maxFiles < 1 || maxFiles > 1000000 || maxEvents < 0 || maxEvents > 65536 || minimum < 0 {
		return nil, fmt.Errorf("read profiler: invalid clock or bounds")
	}
	return &ReadProfiler{clock: clock, started: clock.Now(), maxFiles: maxFiles, maxEvents: maxEvents, minimum: minimum, files: make(map[string]*ReadStat)}, nil
}
func (p *ReadProfiler) Wrap(source Reader, label string) (Reader, error) {
	if source == nil || label == "" || len(label) > 4096 {
		return nil, fmt.Errorf("read profiler: source and 1..4096-byte label required")
	}
	return &profiledReader{source: source, profile: p, label: label}, nil
}

type profiledReader struct {
	source  Reader
	profile *ReadProfiler
	label   string
}

func (r *profiledReader) Size() int64 { return r.source.Size() }
func (r *profiledReader) ReadAt(b []byte, off int64) (int, error) {
	p := r.profile
	generation := p.generation.Load()
	started := p.clock.Now()
	n, err := r.source.ReadAt(b, off)
	elapsed := max(time.Duration(0), p.clock.Now()-started)
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.generation.Load() {
		return n, err
	}
	update := func(s *ReadStat) {
		s.Calls++
		s.Requested += int64(len(b))
		s.Bytes += int64(n)
		s.Total += elapsed
		s.Max = max(s.Max, elapsed)
		if err != nil && err != io.EOF {
			s.Errors++
		}
	}
	update(&p.total)
	stat := p.files[r.label]
	if stat == nil && len(p.files) < p.maxFiles {
		stat = &ReadStat{Label: r.label}
		p.files[r.label] = stat
	}
	if stat != nil {
		update(stat)
	} else {
		p.unattributed++
	}
	if elapsed >= p.minimum {
		p.slowReads++
		if p.maxEvents > 0 && (len(p.events) < p.maxEvents || elapsed > p.events[0].Duration) {
			e := ReadEvent{Label: r.label, Offset: off, Requested: len(b), Bytes: n, Started: started - p.started, Duration: elapsed}
			if err != nil {
				e.Error = err.Error()
				if len(e.Error) > 4096 {
					// Do not retain a substring backed by an unbounded error string.
					e.Error = strings.Clone(e.Error[:4093]) + "..."
				}
			}
			if len(p.events) == p.maxEvents {
				heap.Pop(&p.events)
			}
			heap.Push(&p.events, e)
		}
	}
	return n, err
}

// Reset starts a new observation phase. Calls already in flight are discarded
// when they complete rather than being attributed to the new phase.
func (p *ReadProfiler) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = p.clock.Now()
	p.files = make(map[string]*ReadStat)
	p.events = nil
	p.total = ReadStat{}
	p.unattributed = 0
	p.slowReads = 0
	p.generation.Add(1)
}

// Snapshot returns detached statistics. limit=0 includes all tracked labels;
// otherwise only the labels with greatest cumulative latency are returned.
func (p *ReadProfiler) Snapshot(limit int) ReadSnapshot {
	p.mu.Lock()
	s := ReadSnapshot{Elapsed: p.clock.Now() - p.started, Total: p.total, Unattributed: p.unattributed, SlowReads: p.slowReads, TrackedFiles: len(p.files)}
	for _, v := range p.files {
		s.Files = append(s.Files, *v)
	}
	s.Events = append([]ReadEvent(nil), p.events...)
	p.mu.Unlock()
	sort.Slice(s.Files, func(i, j int) bool {
		if s.Files[i].Total == s.Files[j].Total {
			return s.Files[i].Label < s.Files[j].Label
		}
		return s.Files[i].Total > s.Files[j].Total
	})
	if limit > 0 && len(s.Files) > limit {
		s.Files = s.Files[:limit]
	}
	sort.Slice(s.Events, func(i, j int) bool { return s.Events[i].Started < s.Events[j].Started })
	return s
}

type readEvents []ReadEvent

func (e readEvents) Len() int           { return len(e) }
func (e readEvents) Less(i, j int) bool { return e[i].Duration < e[j].Duration }
func (e readEvents) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e *readEvents) Push(v any)        { *e = append(*e, v.(ReadEvent)) }
func (e *readEvents) Pop() any          { old := *e; v := old[len(old)-1]; *e = old[:len(old)-1]; return v }
