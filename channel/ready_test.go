package channel

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func waitReadyBuffer(t *testing.T, c *ReadyByteChannel, size int) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		c.mu.Lock()
		got, changed := c.bufferedLocked(), c.changed
		c.mu.Unlock()
		if got == size {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatalf("queued bytes = %d, want %d", got, size)
		}
	}
}

func TestReadyChannelPartialDrainsBoundStorage(t *testing.T) {
	for _, maximum := range []int{8, 257, 65537} {
		t.Run(strconv.Itoa(maximum), func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			c := NewReadyByteChannel(client, maximum)
			defer c.Close()
			block := make([]byte, maximum)
			for i := range block {
				block[i] = byte(i)
			}
			if _, err := peer.Write(block); err != nil {
				t.Fatal(err)
			}
			waitReadyBuffer(t, c, maximum)
			want := append([]byte(nil), block...)
			for iteration := 0; iteration < 100; iteration++ {
				read := make([]byte, maximum-1)
				if _, err := io.ReadFull(c, read); err != nil || !bytes.Equal(read, want[:len(read)]) {
					t.Fatalf("partial drain: %x, %v", read[:min(len(read), 16)], err)
				}
				want = append(want[len(read):], block[:len(read)]...)
				if _, err := peer.Write(block[:len(read)]); err != nil {
					t.Fatal(err)
				}
				waitReadyBuffer(t, c, maximum)
				c.mu.Lock()
				length, capacity := len(c.buffer), cap(c.buffer)
				c.mu.Unlock()
				if length > maximum || capacity > maximum {
					t.Fatalf("maximum=%d retained length=%d capacity=%d", maximum, length, capacity)
				}
			}
			peer.Close()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("EOF drain: %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestReadyChannelDefaultCapacity(t *testing.T) {
	for _, maximum := range []int{0, -1} {
		client, peer := net.Pipe()
		c := NewReadyByteChannel(client, maximum)
		if c.maximum != defaultReadyChannelBuffer {
			t.Fatalf("capacity %d: got %d", maximum, c.maximum)
		}
		if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = peer.Write([]byte("x")) }()
		data := make([]byte, 1)
		if _, err := io.ReadFull(c, data); err != nil || string(data) != "x" {
			t.Fatalf("default capacity read: %q, %v", data, err)
		}
		c.Close()
		peer.Close()
	}
}
