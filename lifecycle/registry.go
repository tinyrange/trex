package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

const ResourcesKey = "trex.runtime.resources"

type Metrics struct {
	SourceReadBytes atomic.Uint64
	Decompressed    atomic.Uint64
	Streamed        atomic.Uint64
	NBDReadBytes    atomic.Uint64
	NBDWriteBytes   atomic.Uint64
}

type metricsContextKey struct{}

type Resource interface {
	Close() error
}

// Resources owns long-lived protocol and VM sessions created by one
// Starlark execution. Resources are closed in reverse registration order.
type Resources struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	next      uint64
	resources map[uint64]Resource
	order     []uint64
	closed    bool
	cache     *bytecache.Cache
	cacheNext uint64
	metrics   *Metrics
}

func New() *Resources {
	base, cancel := context.WithCancel(context.Background())
	metrics := &Metrics{}
	ctx := context.WithValue(base, metricsContextKey{}, metrics)
	return &Resources{
		ctx:       ctx,
		cancel:    cancel,
		resources: make(map[uint64]Resource),
		cache: bytecache.NewObserved(bytecache.DefaultBytes, func(count uint64) {
			metrics.Decompressed.Add(count)
		}),
		metrics: metrics,
	}
}

func (r *Resources) Context() context.Context { return r.ctx }
func (r *Resources) Metrics() *Metrics        { return r.metrics }

func MetricsFromContext(ctx context.Context) *Metrics {
	metrics, _ := ctx.Value(metricsContextKey{}).(*Metrics)
	return metrics
}

func (r *Resources) NewCacheSource() (*bytecache.Cache, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cacheNext++
	return r.cache, r.cacheNext
}

func (r *Resources) CacheStats() bytecache.Stats { return r.cache.Stats() }

func (r *Resources) Add(resource Resource) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, context.Canceled
	}
	r.next++
	id := r.next
	r.resources[id] = resource
	r.order = append(r.order, id)
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.resources, id)
			r.mu.Unlock()
		})
	}, nil
}

func (r *Resources) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.cancel()
	resources := make([]Resource, 0, len(r.resources))
	for index := len(r.order) - 1; index >= 0; index-- {
		if resource, ok := r.resources[r.order[index]]; ok {
			resources = append(resources, resource)
		}
	}
	r.resources = nil
	r.order = nil
	r.mu.Unlock()

	var errs []error
	for _, resource := range resources {
		if err := resource.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func Install(thread *starlark.Thread) *Resources {
	resources := New()
	thread.SetLocal(ResourcesKey, resources)
	return resources
}

func ForThread(thread *starlark.Thread) (*Resources, error) {
	if thread == nil {
		return nil, fmt.Errorf("Starlark runtime is unavailable")
	}
	resources, ok := thread.Local(ResourcesKey).(*Resources)
	if !ok || resources == nil {
		return nil, fmt.Errorf("runtime resource registry is unavailable")
	}
	return resources, nil
}
