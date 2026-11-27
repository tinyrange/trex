package channel

import (
	"errors"
	"io"
	"slices"
	"sync"
	"sync/atomic"
)

// ErrWouldBlock means a cooperative channel has no bytes or capacity available.
var ErrWouldBlock = errors.New("channel would block")

// AvailableReader supports polling without a host clock or blocking a scheduler.
type AvailableReader interface {
	ReadAvailable([]byte) (int, error)
}

// Fork copies both ends of the in-memory connection into an independent pair.
// The first result corresponds to the receiver.
func (m *Memory) Fork() (*Memory, *Memory) {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	a, b, _ := NewMemoryPair(m.pair.maximum)
	a.pair.state.closed = m.pair.state.closed
	for side, data := range m.pair.state.data {
		a.pair.state.data[side] = slices.Clone(data)
		a.pair.queued[side].Store(int64(len(data)))
	}
	if m.side == 0 {
		return a, b
	}
	return b, a
}

// AvailableWriter never waits for capacity or a host event.
type AvailableWriter interface {
	WriteAvailable([]byte) (int, error)
}

type memoryState struct {
	data   [2][]byte
	closed [2]bool
}

type memoryPair struct {
	mu      sync.Mutex
	maximum int
	state   memoryState
	changed [2]chan struct{}
	queued  [2]atomic.Int64
}

var memoryReady = func() <-chan struct{} {
	ready := make(chan struct{})
	close(ready)
	return ready
}()

func (p *memoryPair) notifyLocked(side int) {
	close(p.changed[side])
	p.changed[side] = make(chan struct{})
}

// Memory is one endpoint of a bounded, cooperative, entirely in-memory stream.
// An empty open stream returns ErrWouldBlock; closing the peer produces EOF
// after its queued bytes have been read.
type Memory struct {
	pair *memoryPair
	side int
}

func NewMemoryPair(maximum int) (*Memory, *Memory, error) {
	if maximum <= 0 {
		return nil, nil, errors.New("memory channel requires a positive capacity")
	}
	pair := &memoryPair{maximum: maximum, changed: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
	return &Memory{pair: pair}, &Memory{pair: pair, side: 1}, nil
}

func (m *Memory) ReadAvailable(p []byte) (int, error)  { return m.Read(p) }
func (m *Memory) WriteAvailable(p []byte) (int, error) { return m.Write(p) }

// HasInput reports whether bytes are queued, independently of closure.
func (m *Memory) HasInput() bool { return m.pair.queued[m.side].Load() != 0 }

// ReadReady does not change the cooperative behavior of Read or ReadAvailable.
// Closing either endpoint makes reads ready to return data or a terminal error.
func (m *Memory) ReadReady() <-chan struct{} {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	if len(m.pair.state.data[m.side]) != 0 || m.pair.state.closed[m.side] || m.pair.state.closed[1-m.side] {
		return memoryReady
	}
	return m.pair.changed[m.side]
}

func (m *Memory) WriteCapacity() (int, <-chan struct{}, error) {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	peer := 1 - m.side
	if m.pair.state.closed[m.side] || m.pair.state.closed[peer] {
		return 0, nil, io.ErrClosedPipe
	}
	return m.pair.maximum - len(m.pair.state.data[peer]), m.pair.changed[peer], nil
}

func (m *Memory) Read(p []byte) (int, error) {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if m.pair.state.closed[m.side] {
		return 0, io.ErrClosedPipe
	}
	data := m.pair.state.data[m.side]
	if len(data) == 0 {
		if m.pair.state.closed[1-m.side] {
			return 0, io.EOF
		}
		return 0, ErrWouldBlock
	}
	n := copy(p, data)
	m.pair.state.data[m.side] = data[n:]
	m.pair.queued[m.side].Store(int64(len(data) - n))
	if n == len(data) {
		m.pair.state.data[m.side] = nil
	}
	m.pair.notifyLocked(m.side)
	return n, nil
}

func (m *Memory) Write(p []byte) (int, error) {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	peer := 1 - m.side
	if m.pair.state.closed[m.side] || m.pair.state.closed[peer] {
		return 0, io.ErrClosedPipe
	}
	if len(p) > m.pair.maximum-len(m.pair.state.data[peer]) {
		return 0, ErrWouldBlock
	}
	m.pair.state.data[peer] = append(m.pair.state.data[peer], p...)
	if len(p) != 0 {
		m.pair.queued[peer].Store(int64(len(m.pair.state.data[peer])))
		m.pair.notifyLocked(peer)
	}
	return len(p), nil
}

func (m *Memory) Close() error {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	if !m.pair.state.closed[m.side] {
		m.pair.state.closed[m.side] = true
		m.pair.notifyLocked(0)
		m.pair.notifyLocked(1)
	}
	return nil
}

// CaptureCheckpoint captures both ends atomically. Restore copies the saved
// buffers so the same checkpoint can be reused for independent experiments.
func (m *Memory) CaptureCheckpoint() (func() error, error) {
	m.pair.mu.Lock()
	saved := m.pair.state
	for i := range saved.data {
		saved.data[i] = append([]byte(nil), saved.data[i]...)
	}
	m.pair.mu.Unlock()
	return func() error {
		m.pair.mu.Lock()
		defer m.pair.mu.Unlock()
		m.pair.state = saved
		for i := range saved.data {
			m.pair.state.data[i] = append([]byte(nil), saved.data[i]...)
			m.pair.queued[i].Store(int64(len(saved.data[i])))
			// Observers belong to the live stream, not the captured state.
			// Wake them even when restoration makes the stream empty again.
			m.pair.notifyLocked(i)
		}
		return nil
	}, nil
}
