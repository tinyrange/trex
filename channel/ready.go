package channel

import (
	"io"
	"os"
	"sync"
	"time"
)

const defaultReadyChannelBuffer = 8 << 20

// ReadyByteChannel adapts a stream to the portable debug.select readiness
// contract. The backend reader is bounded so an unattached serial consumer
// cannot grow memory without limit or stall the guest on a small socket buffer.
type ReadyByteChannel struct {
	channel ByteChannel
	maximum int

	mu       sync.Mutex
	buffer   []byte
	offset   int
	terminal error
	deadline time.Time
	changed  chan struct{}
	ready    chan struct{}
	close    sync.Once
}

func NewReadyByteChannel(channel ByteChannel, maximum int) *ReadyByteChannel {
	value := &ReadyByteChannel{
		channel: channel,
		maximum: maximum,
		changed: make(chan struct{}),
		ready:   make(chan struct{}, 1),
	}
	go value.readLoop()
	return value
}

func (c *ReadyByteChannel) bufferedLocked() int { return len(c.buffer) - c.offset }

func (c *ReadyByteChannel) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
	select {
	case c.ready <- struct{}{}:
	default:
	}
}

func (c *ReadyByteChannel) clearReadyLocked() {
	for {
		select {
		case <-c.ready:
		default:
			return
		}
	}
}

func (c *ReadyByteChannel) readLoop() {
	buffer := make([]byte, 64<<10)
	for {
		c.mu.Lock()
		for c.bufferedLocked() >= c.maximum && c.terminal == nil {
			changed := c.changed
			c.mu.Unlock()
			<-changed
			c.mu.Lock()
		}
		if c.terminal != nil {
			c.mu.Unlock()
			return
		}
		available := c.maximum - c.bufferedLocked()
		c.mu.Unlock()
		if available > len(buffer) {
			available = len(buffer)
		}

		read, err := c.channel.Read(buffer[:available])
		c.mu.Lock()
		if read > 0 {
			if c.offset == len(c.buffer) {
				c.buffer = c.buffer[:0]
				c.offset = 0
			}
			c.buffer = append(c.buffer, buffer[:read]...)
			c.notifyLocked()
		}
		if err != nil {
			c.terminal = err
			c.notifyLocked()
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}

func (c *ReadyByteChannel) ReadReady() <-chan struct{} {
	c.mu.Lock()
	if c.bufferedLocked() > 0 || c.terminal != nil {
		select {
		case c.ready <- struct{}{}:
		default:
		}
	}
	ready := c.ready
	c.mu.Unlock()
	return ready
}

func (c *ReadyByteChannel) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if available := c.bufferedLocked(); available > 0 {
			if available > len(p) {
				available = len(p)
			}
			copy(p, c.buffer[c.offset:c.offset+available])
			c.offset += available
			if c.offset == len(c.buffer) {
				c.buffer = c.buffer[:0]
				c.offset = 0
				c.clearReadyLocked()
			} else {
				select {
				case c.ready <- struct{}{}:
				default:
				}
			}
			close(c.changed)
			c.changed = make(chan struct{})
			c.mu.Unlock()
			return available, nil
		}
		if c.terminal != nil {
			err := c.terminal
			c.mu.Unlock()
			return 0, err
		}
		deadline := c.deadline
		changed := c.changed
		c.mu.Unlock()

		if deadline.IsZero() {
			<-changed
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case <-changed:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *ReadyByteChannel) Write(p []byte) (int, error) { return c.channel.Write(p) }

func (c *ReadyByteChannel) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *ReadyByteChannel) Close() error {
	var err error
	c.close.Do(func() {
		err = c.channel.Close()
		c.mu.Lock()
		if c.terminal == nil {
			c.terminal = io.ErrClosedPipe
		}
		c.notifyLocked()
		c.mu.Unlock()
	})
	return err
}
