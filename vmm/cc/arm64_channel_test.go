package cc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/storage"
	"j5.nz/cc/hypervisor"
)

type arm64ChannelCPU struct {
	hypervisor.ARM64
	cancels, closes int
	cancelErr       error
	onClose         func()
}

func (c *arm64ChannelCPU) Cancel() error { c.cancels++; return c.cancelErr }
func (c *arm64ChannelCPU) Close() error {
	c.closes++
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func newARM64TestChannel(t *testing.T, d *arm64Driver, name string) (channel.ByteChannel, *channel.Memory) {
	t.Helper()
	host, guest, err := channel.NewMemoryPair(4)
	if err != nil {
		t.Fatal(err)
	}
	if d.channels == nil {
		d.channels = make(map[string]channel.ByteChannel)
	}
	d.channels[name] = &arm64Channel{stream: host, wake: d.wake}
	c, err := d.Channel(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return c, guest
}

func TestARM64ChannelWakesOnInputOutputSpaceAndClose(t *testing.T) {
	cpu := &arm64ChannelCPU{cancelErr: errors.New("injected wake failure")}
	d := &arm64Driver{cpu: cpu, done: make(chan struct{})}
	host, guest := newARM64TestChannel(t, d, "usb")
	defer guest.Close()
	reader, ok := host.(channel.AvailableReader)
	if !ok {
		t.Fatal("host channel lost cooperative reads")
	}
	writer, ok := host.(channel.AvailableWriter)
	if !ok {
		t.Fatal("host channel lost cooperative writes")
	}
	if n, err := writer.WriteAvailable([]byte("host")); n != 4 || err != nil || cpu.cancels != 1 {
		t.Fatalf("input consumed once even if wake fails: n=%d err=%v wakes=%d", n, err, cpu.cancels)
	}
	if n, err := writer.WriteAvailable([]byte("x")); n != 0 || err != channel.ErrWouldBlock {
		t.Fatalf("full input buffer: %d %v", n, err)
	}
	if n, err := writer.WriteAvailable(nil); n != 0 || err != nil {
		t.Fatalf("empty write: %d %v", n, err)
	}
	var buf [4]byte
	if _, err := reader.ReadAvailable(buf[:]); err != channel.ErrWouldBlock || cpu.cancels != 1 {
		t.Fatalf("empty output must not wake: err=%v wakes=%d", err, cpu.cancels)
	}
	if n, err := guest.Read(buf[:]); n != 4 || err != nil || string(buf[:]) != "host" {
		t.Fatalf("guest input: %d %v %q", n, err, buf)
	}
	if _, err := guest.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Write([]byte("x")); err != channel.ErrWouldBlock {
		t.Fatalf("output should be full: %v", err)
	}
	if n, err := reader.ReadAvailable(buf[:2]); n != 2 || err != nil || string(buf[:2]) != "da" || cpu.cancels != 2 {
		t.Fatalf("output capacity wake: n=%d err=%v wakes=%d", n, err, cpu.cancels)
	}
	if _, err := guest.Write([]byte("xy")); err != nil {
		t.Fatalf("read did not release output space: %v", err)
	}
	if n, err := host.Read(buf[:]); n != 4 || err != nil || string(buf[:]) != "taxy" || cpu.cancels != 3 {
		t.Fatalf("ordinary read: n=%d err=%v wakes=%d bytes=%q", n, err, cpu.cancels, buf)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	_ = host.Close()
	if _, err := guest.Read(buf[:]); err != io.EOF || cpu.cancels != 4 {
		t.Fatalf("close must wake EOF exactly once: err=%v wakes=%d", err, cpu.cancels)
	}
}

func TestARM64ChannelCanDrainAfterStopWithoutWakingClosedCPU(t *testing.T) {
	cpu := &arm64ChannelCPU{}
	ctx, cancel := context.WithCancel(context.Background())
	d := &arm64Driver{cpu: cpu, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	host, guest := newARM64TestChannel(t, d, "usb")
	if _, err := guest.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	_ = guest.Close()
	close(d.done)
	var buf [4]byte
	if n, err := host.Read(buf[:]); n != 4 || err != nil || string(buf[:]) != "last" {
		t.Fatalf("final bytes must remain readable: %d %v %q", n, err, buf)
	}
	for range 2 {
		if err := d.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	d.wake()
	if cpu.cancels != 0 || cpu.closes != 1 || !d.resourcesClosed {
		t.Fatalf("stopped channel touched CPU: wakes=%d closes=%d closed=%v", cpu.cancels, cpu.closes, d.resourcesClosed)
	}
}

func TestARM64ChannelConcurrentCloseDoesNotWaitForWake(t *testing.T) {
	host, guest, err := channel.NewMemoryPair(4)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	c := &arm64Channel{stream: host, wake: func() { close(entered); <-release }}
	first := make(chan struct{})
	go func() { _ = c.Close(); close(first) }()
	defer func() { close(release); <-first }()
	<-entered
	second := make(chan struct{})
	go func() { _ = c.Close(); close(second) }()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("VM resource close waits for a channel wake that may need its own lock")
	}
}

func TestARM64FailedStartClosesAllocatedResourcesBeforeCPU(t *testing.T) {
	cpu := &arm64ChannelCPU{}
	ctx, cancel := context.WithCancel(context.Background())
	d := &arm64Driver{cpu: cpu, ctx: ctx, cancel: cancel, done: make(chan struct{}), ram: make([]byte, 16)}
	store := storage.NewMemoryStore(4096)
	device := &arm64CloseDevice{store: store}
	d.device = device
	host, guest := newARM64TestChannel(t, d, "usb")
	d.guestChannels = map[string]channel.ByteChannel{"usb": guest}
	cpu.onClose = func() {
		if ctx.Err() != context.Canceled {
			t.Fatal("startup context remains active at CPU close")
		}
		select {
		case <-d.done:
		default:
			t.Fatal("channel wake guard must be closed before CPU")
		}
		if _, err := store.Length(); err != storage.ErrStoreClosed {
			t.Fatalf("utility storage remains live: %v", err)
		}
		for _, c := range []channel.ByteChannel{host, guest} {
			if _, err := c.Write([]byte("x")); err != io.ErrClosedPipe {
				t.Fatalf("channel remains live: %v", err)
			}
		}
	}
	d.abortStart()
	if cpu.closes != 1 || cpu.cancels != 0 || d.ram != nil {
		t.Fatalf("failed-start cleanup: closes=%d wakes=%d ram=%v", cpu.closes, cpu.cancels, d.ram)
	}
}

type arm64CloseDevice struct{ store *storage.MemoryStore }

func (*arm64CloseDevice) Contains(uint64, int) bool        { return false }
func (*arm64CloseDevice) Read(uint64, int) (uint64, error) { return 0, nil }
func (*arm64CloseDevice) Write(uint64, int, uint64) error  { return nil }
func (d *arm64CloseDevice) Close() error                   { return d.store.Close() }
