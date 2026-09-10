package native

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/tinyrange/trex/storage"
	starvalue "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// The full Windows 11 servicing output previously retained about 5.3 GiB of
// compressed chunks. Allow that working set to fit without repeatedly applying
// deltas during disk reads. This is a lazy ceiling, not an eager allocation;
// native run limits must separately budget the source caches and guest memory.
const maximumVerifiedFileCache = 6 << 30

// verifiedFileCache keeps a bounded working set of reconstructed disk files.
// The initial construction pass still verifies every target. Eviction discards
// only reusable bytes, never a file's reconstruction recipe or expected hash.
type verifiedFileCache struct {
	mu            sync.Mutex
	codec         *retainedFileStore
	maximum, used int64
	entries       map[*verifiedFile]*list.Element
	lru           list.List
}

type verifiedFileEntry struct {
	owner  *verifiedFile
	file   starvalue.File
	weight int64
}

func newVerifiedFileCache(maximum int64) (*verifiedFileCache, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("negative verified file cache limit")
	}
	codec, err := newRetainedFileStore()
	if err != nil {
		return nil, err
	}
	// A cross-file dedup index would pin evicted chunks. Each cached file owns
	// its encoded chunks; only the independently bounded decoded cache is shared.
	codec.chunks = nil
	return &verifiedFileCache{codec: codec, maximum: maximum, entries: make(map[*verifiedFile]*list.Element)}, nil
}

type verifiedFile struct {
	name   string
	length int64
	hash   [sha256.Size]byte
	open   func() (storage.Reader, error)
	cache  *verifiedFileCache
}

func newVerifiedFile(cache *verifiedFileCache, name string, verified []byte, open func() (storage.Reader, error)) (*verifiedFile, error) {
	file := &verifiedFile{name: name, length: int64(len(verified)), hash: sha256.Sum256(verified), open: open, cache: cache}
	// Construction has already paid for reconstruction and mandatory target
	// verification. Admit a compressed immutable copy to the same bounded LRU
	// used by reads instead of throwing it away and repeating that work at boot.
	if cache.maximum != 0 {
		cache.mu.Lock()
		_, err := cache.retainLocked(file, verified)
		cache.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return file, nil
}

func (c *verifiedFileCache) get(owner *verifiedFile) (starvalue.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[owner]; entry != nil {
		c.lru.MoveToFront(entry)
		return entry.Value.(verifiedFileEntry).file, nil
	}
	// Serialize misses to bound simultaneous full-target reconstruction peaks.
	source, err := owner.open()
	if err != nil {
		return nil, err
	}
	if source.Size() != owner.length {
		return nil, fmt.Errorf("verified file %q changed length", owner.name)
	}
	var data []byte
	if decoded, ok := source.(*starvalue.Bytes); ok {
		data = decoded.Data
	} else {
		data = make([]byte, owner.length)
		if _, err := io.ReadFull(io.NewSectionReader(source, 0, source.Size()), data); err != nil {
			return nil, err
		}
	}
	if int64(len(data)) != owner.length || sha256.Sum256(data) != owner.hash {
		return nil, fmt.Errorf("verified file %q changed SHA-256 during reconstruction", owner.name)
	}
	return c.retainLocked(owner, data)
}

// retainLocked copies verified bytes and enforces the compressed-byte budget.
// The caller holds c.mu and has checked the input's content identity.
func (c *verifiedFileCache) retainLocked(owner *verifiedFile, data []byte) (starvalue.File, error) {
	packed, err := c.codec.pack(owner.name, data)
	if err != nil {
		return nil, err
	}
	weight := packed.Size()
	if chunks, ok := packed.(*retainedFile); ok {
		weight = int64(len(chunks.chunks)) * 32
		for _, chunk := range chunks.chunks {
			weight += int64(len(chunk.data))
		}
	}
	weight += 128 // File/entry/index bookkeeping, including empty files.
	if weight <= c.maximum {
		for c.used > c.maximum-weight {
			old := c.lru.Back()
			entry := old.Value.(verifiedFileEntry)
			delete(c.entries, entry.owner)
			c.used -= entry.weight
			c.lru.Remove(old)
		}
		c.entries[owner] = c.lru.PushFront(verifiedFileEntry{owner: owner, file: packed, weight: weight})
		c.used += weight
	}
	return packed, nil
}

func (f *verifiedFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative verified file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.length {
		return 0, io.EOF
	}
	file, err := f.cache.get(f)
	if err != nil {
		return 0, err
	}
	return file.ReadAt(p, off)
}
func (*verifiedFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("verified file is read-only")
}
func (f *verifiedFile) Size() int64 { return f.length }
func (f *verifiedFile) String() string {
	return fmt.Sprintf("<verified file %s size=%d>", f.name, f.length)
}
func (*verifiedFile) Type() string                               { return "file" }
func (*verifiedFile) Freeze()                                    {}
func (*verifiedFile) Truth() starlark.Bool                       { return starlark.True }
func (*verifiedFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *verifiedFile) Attr(name string) (starlark.Value, error) { return starvalue.Attr(f, name), nil }
func (*verifiedFile) AttrNames() []string                        { return starvalue.AttrNames() }
