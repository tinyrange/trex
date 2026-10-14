// Package objects provides portable, verified, on-demand immutable object
// retrieval. Sources are injected capabilities, never ambient networking. It
// can sit over local storage, an RPC service, or another cache using the same API.
package objects

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/tinyrange/trex/storage"
)

type ID string

func Identity(kind byte, data []byte) ID {
	h := sha256.New()
	h.Write([]byte{kind})
	h.Write(data)
	return ID(hex.EncodeToString(h.Sum(nil)))
}

type Object struct {
	Kind byte
	Data storage.Reader
}
type Source interface {
	Fetch(context.Context, ID) (Object, error)
}
type Limits struct {
	CacheBytes, ObjectBytes int64
	Entries                 int
}
type Stats struct {
	Hits, Misses, Fetches, FetchedBytes uint64
	CachedBytes                         int64
	Entries                             int
}
type cached struct {
	id   ID
	kind byte
	data []byte
}
type flight struct {
	done  chan struct{}
	value cached
	err   error
}
type Cache struct {
	mu      sync.Mutex
	source  Source
	limits  Limits
	lru     *list.List
	entries map[ID]*list.Element
	pending map[ID]*flight
	stats   Stats
}

var ErrLimit = errors.New("immutable object retrieval limit exceeded")

func NewCache(source Source, limits Limits) (*Cache, error) {
	if source == nil || limits.CacheBytes < 0 || limits.ObjectBytes < 1 || limits.ObjectBytes > 1<<30 || limits.Entries < 1 {
		return nil, errors.New("invalid object cache configuration")
	}
	return &Cache{source: source, limits: limits, lru: list.New(), entries: map[ID]*list.Element{}, pending: map[ID]*flight{}}, nil
}
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Entries = len(c.entries)
	return s
}

// Fetch verifies kind-prefixed SHA-256 before exposing bytes. Cache failures are
// not retained. Concurrent requests share one fetch; a waiter's cancellation
// does not cancel the owner. The owner's context governs that source request.
func (c *Cache) Fetch(ctx context.Context, id ID) (Object, error) {
	raw, err := hex.DecodeString(string(id))
	if err != nil || len(raw) != 32 {
		return Object{}, errors.New("invalid object ID")
	}
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	c.mu.Lock()
	if e := c.entries[id]; e != nil {
		c.stats.Hits++
		c.lru.MoveToFront(e)
		v := e.Value.(cached)
		c.mu.Unlock()
		return Object{Kind: v.kind, Data: bytes.NewReader(v.data)}, nil
	}
	if f := c.pending[id]; f != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return Object{}, ctx.Err()
		case <-f.done:
		}
		if f.err != nil {
			return Object{}, f.err
		}
		return Object{Kind: f.value.kind, Data: bytes.NewReader(f.value.data)}, nil
	}
	if len(c.pending) >= c.limits.Entries {
		c.mu.Unlock()
		return Object{}, ErrLimit
	}
	f := &flight{done: make(chan struct{})}
	c.pending[id] = f
	c.stats.Misses++
	c.stats.Fetches++
	c.mu.Unlock()
	v, err := c.fetch(ctx, id)
	c.mu.Lock()
	f.value, f.err = v, err
	if err == nil {
		c.stats.FetchedBytes += uint64(len(v.data))
		if int64(len(v.data)) <= c.limits.CacheBytes {
			for c.lru.Len() > 0 && (c.lru.Len() >= c.limits.Entries || int64(len(v.data)) > c.limits.CacheBytes-c.stats.CachedBytes) {
				e := c.lru.Back()
				old := e.Value.(cached)
				delete(c.entries, old.id)
				c.lru.Remove(e)
				c.stats.CachedBytes -= int64(len(old.data))
			}
			c.entries[id] = c.lru.PushFront(v)
			c.stats.CachedBytes += int64(len(v.data))
		}
	}
	delete(c.pending, id)
	close(f.done)
	c.mu.Unlock()
	if err != nil {
		return Object{}, err
	}
	return Object{Kind: v.kind, Data: bytes.NewReader(v.data)}, nil
}
func (c *Cache) fetch(ctx context.Context, id ID) (cached, error) {
	object, err := c.source.Fetch(ctx, id)
	if err != nil {
		return cached{}, err
	}
	if object.Kind == 0 || object.Data == nil {
		return cached{}, ErrLimit
	}
	size := object.Data.Size()
	if size < 0 || size > c.limits.ObjectBytes {
		return cached{}, ErrLimit
	}
	data := make([]byte, int(size))
	for off := 0; off < len(data); {
		if err := ctx.Err(); err != nil {
			return cached{}, err
		}
		chunk := data[off:min(len(data), off+65536)]
		n, err := object.Data.ReadAt(chunk, int64(off))
		if n < 0 || n > len(chunk) {
			return cached{}, errors.New("invalid object read count")
		}
		if n == 0 && err == nil {
			return cached{}, io.ErrNoProgress
		}
		if n != len(chunk) {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return cached{}, err
		}
		if err != nil && err != io.EOF {
			return cached{}, err
		}
		off += n
	}
	if err := ctx.Err(); err != nil {
		return cached{}, err
	}
	if Identity(object.Kind, data) != id {
		return cached{}, errors.New("immutable object identity mismatch")
	}
	return cached{id: id, kind: object.Kind, data: data}, nil
}

// Reader creates a lazy file version with an expected kind and size. No source
// request occurs until a nonempty ReadAt. Whole-object verification can still
// fetch the whole object; use ChunkedReader to bound small-read amplification.
func (c *Cache) Reader(ctx context.Context, id ID, kind byte, size int64) (storage.Reader, error) {
	if size < 0 || size > c.limits.ObjectBytes || kind == 0 {
		return nil, ErrLimit
	}
	raw, err := hex.DecodeString(string(id))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid object ID")
	}
	if size == 0 && Identity(kind, nil) != id {
		return nil, errors.New("object manifest mismatch")
	}
	return &lazyReader{cache: c, ctx: ctx, id: id, kind: kind, size: size}, nil
}

type lazyReader struct {
	cache *Cache
	ctx   context.Context
	id    ID
	kind  byte
	size  int64
}

func (r *lazyReader) Size() int64 { return r.size }
func (r *lazyReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	object, err := r.cache.Fetch(r.ctx, r.id)
	if err != nil {
		return 0, err
	}
	if object.Kind != r.kind || object.Data.Size() != r.size {
		return 0, errors.New("object manifest mismatch")
	}
	return object.Data.ReadAt(p, off)
}
