package storage

import (
	"errors"
	"io"
	"math"
	"sync"
)

const memoryPageBytes = 64 << 10

var ErrStoreLimit = errors.New("memory store byte limit exceeded")
var ErrStoreClosed = errors.New("memory store is closed")

type memoryPage struct {
	data   []byte
	shared bool
}

// MemoryStore is a bounded, paged, volatile Store. Snapshots share immutable
// pages; subsequent writes copy only touched shared pages. Sync is a no-op,
// not a promise of survival beyond process lifetime. Close releases ownership,
// but already returned snapshots remain readable.
type MemoryStore struct {
	mu          sync.Mutex
	pages       map[int64]*memoryPage
	size, limit int64
	closed      bool
}

func NewMemoryStore(limit int64) *MemoryStore {
	return &MemoryStore{pages: map[int64]*memoryPage{}, limit: limit}
}
func (m *MemoryStore) Length() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrStoreClosed
	}
	return m.size, nil
}
func (m *MemoryStore) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrStoreClosed
	}
	return nil
}
func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.pages = nil
	return nil
}
func (m *MemoryStore) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrStoreClosed
	}
	if off < 0 || int64(len(p)) > math.MaxInt64-off {
		return 0, errors.New("invalid write range")
	}
	if len(p) == 0 {
		return 0, nil
	}
	end := off + int64(len(p))
	if m.limit < 0 || end > m.limit {
		return 0, ErrStoreLimit
	}
	n := len(p)
	for len(p) > 0 {
		index := off / memoryPageBytes
		page := m.pages[index]
		if page == nil {
			page = &memoryPage{data: make([]byte, memoryPageBytes)}
			m.pages[index] = page
		} else if page.shared {
			page = &memoryPage{data: append([]byte(nil), page.data...)}
			m.pages[index] = page
		}
		count := copy(page.data[off%memoryPageBytes:], p)
		p = p[count:]
		off += int64(count)
	}
	m.size = max(m.size, end)
	return n, nil
}
func readMemory(pages map[int64]*memoryPage, size int64, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= size {
		return 0, io.EOF
	}
	count := min(int64(len(p)), size-off)
	done := int64(0)
	for done < count {
		n := min(count-done, memoryPageBytes-off%memoryPageBytes)
		dst := p[done : done+n]
		if page := pages[off/memoryPageBytes]; page != nil {
			copy(dst, page.data[off%memoryPageBytes:off%memoryPageBytes+n])
		} else {
			clear(dst)
		}
		done += n
		off += n
	}
	if done < int64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}
func (m *MemoryStore) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrStoreClosed
	}
	return readMemory(m.pages, m.size, p, off)
}
func (m *MemoryStore) Truncate(size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrStoreClosed
	}
	if size < 0 {
		return errors.New("negative store length")
	}
	if m.limit < 0 || size > m.limit {
		return ErrStoreLimit
	}
	if size < m.size {
		for index, page := range m.pages {
			if index*memoryPageBytes >= size {
				delete(m.pages, index)
			} else if size-index*memoryPageBytes < memoryPageBytes {
				if page.shared {
					page = &memoryPage{data: append([]byte(nil), page.data...)}
					m.pages[index] = page
				}
				clear(page.data[size%memoryPageBytes:])
			}
		}
	}
	m.size = size
	return nil
}

type memorySnapshot struct {
	pages map[int64]*memoryPage
	size  int64
}

func (s *memorySnapshot) Size() int64 { return s.size }
func (s *memorySnapshot) ReadAt(p []byte, off int64) (int, error) {
	return readMemory(s.pages, s.size, p, off)
}
func (m *MemoryStore) Snapshot() (Reader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrStoreClosed
	}
	pages := make(map[int64]*memoryPage, len(m.pages))
	for index, page := range m.pages {
		page.shared = true
		pages[index] = page
	}
	return &memorySnapshot{pages: pages, size: m.size}, nil
}
