package channel

import (
	"errors"
	"io"
	"sync"
)

// ErrWouldBlock means a cooperative channel has no bytes available yet.
var ErrWouldBlock = errors.New("channel would block")

// AvailableReader supports polling without a host clock or blocking a scheduler.
type AvailableReader interface {
	ReadAvailable([]byte) (int, error)
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
	pair := &memoryPair{maximum: maximum}
	return &Memory{pair: pair}, &Memory{pair: pair, side: 1}, nil
}

func (m *Memory) ReadAvailable(p []byte) (int, error)  { return m.Read(p) }
func (m *Memory) WriteAvailable(p []byte) (int, error) { return m.Write(p) }

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
	if n == len(data) {
		m.pair.state.data[m.side] = nil
	}
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
	return len(p), nil
}

func (m *Memory) Close() error {
	m.pair.mu.Lock()
	defer m.pair.mu.Unlock()
	m.pair.state.closed[m.side] = true
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
		}
		return nil
	}, nil
}
