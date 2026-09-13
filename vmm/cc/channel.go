package cc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tinyrange/trex/channel"
)

// A dedicated shared-memory aperture, independent of the display ABI. Each
// side owns one producer and one consumer counter; payload precedes publication.
const channelAddress = 0xe1000000
const channelSize = 4096
const channelCapacity = 1024

type memoryChannel struct {
	driver   *driver
	mu       sync.Mutex
	deadline time.Time
	closed   bool
}

func (d *driver) Channel(ctx context.Context, name string) (channel.ByteChannel, error) {
	if d.pc.channelName == "" || name != d.pc.channelName {
		return nil, fmt.Errorf("unknown cc channel %q", name)
	}
	return &memoryChannel{driver: d}, nil
}
func (c *memoryChannel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}
func (c *memoryChannel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// transfer runs while the vCPU is stopped, making guest and host updates
// ordered without atomic operations on the guest's mapped memory.
func transfer(memory, data []byte, write bool) (int, error) {
	producer, consumer, base := 40, 44, 1088
	if write {
		producer, consumer, base = 32, 36, 64
	}
	w := binary.LittleEndian.Uint32(memory[producer:])
	r := binary.LittleEndian.Uint32(memory[consumer:])
	used := w - r
	if used > channelCapacity {
		return 0, fmt.Errorf("invalid shared-memory channel counters")
	}
	available := used
	if write {
		available = channelCapacity - used
	}
	n := min(len(data), int(available))
	for i := 0; i < n; i++ {
		if write {
			memory[base+int((w+uint32(i))%channelCapacity)] = data[i]
		} else {
			data[i] = memory[base+int((r+uint32(i))%channelCapacity)]
		}
	}
	if write {
		binary.LittleEndian.PutUint32(memory[producer:], w+uint32(n))
	} else {
		binary.LittleEndian.PutUint32(memory[consumer:], r+uint32(n))
	}
	return n, nil
}
func (c *memoryChannel) operation(data []byte, write bool) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		closed, deadline := c.closed, c.deadline
		c.mu.Unlock()
		if closed {
			return 0, io.ErrClosedPipe
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, context.DeadlineExceeded
		}
		ctx := c.driver.ctx
		cancel := func() {}
		if !deadline.IsZero() {
			ctx, cancel = context.WithDeadline(ctx, deadline)
		}
		n := 0
		err := c.driver.call(ctx, func() error {
			var err error
			n, err = transfer(c.driver.pc.channelMemory, data, write)
			return err
		})
		cancel()
		if err != nil || n != 0 {
			return n, err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-c.driver.ctx.Done():
			timer.Stop()
			return 0, c.driver.ctx.Err()
		case <-timer.C:
		}
	}
}
func (c *memoryChannel) Read(data []byte) (int, error) { return c.operation(data, false) }
func (c *memoryChannel) Write(data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := c.operation(data[written:], true)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
