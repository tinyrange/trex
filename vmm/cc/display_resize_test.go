package cc

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm/ramfb"
)

func resizeDriverFixture(t *testing.T) (*driver, context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	m := make([]byte, ramfb.Size)
	for offset, value := range map[int]uint32{0: ramfb.Magic, 4: 1, 8: 1280, 12: 720, 16: 5120, 20: 1, 24: ramfb.ResizeMagic, 28: 1, 52: ramfb.MaxWidth, 56: ramfb.MaxHeight} {
		binary.LittleEndian.PutUint32(m[offset:], value)
	}
	d := &driver{ctx: ctx, pc: &pc{cpu: inputTestCPU{}, framebuffer: m}, requests: make(chan request, 16), done: make(chan struct{}), finished: make(chan struct{})}
	return d, ctx, cancel
}

func nextResizeRequest(t *testing.T, d *driver, ctx context.Context) request {
	t.Helper()
	select {
	case r := <-d.requests:
		return r
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return request{}
	}
}

func TestDisplayResizeWaitsForGuestWithCPURequestsReleased(t *testing.T) {
	d, ctx, cancel := resizeDriverFixture(t)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- d.Resize(ctx, 800, 600) }()
	nextResizeRequest(t, d, ctx).execute() // Publish request while CPUs are stopped.
	nextResizeRequest(t, d, ctx).execute() // Not acknowledged yet; releases CPU loop.
	select {
	case err := <-result:
		t.Fatalf("resize completed before the guest ran: %v", err)
	default:
	}
	// Model a guest mode change between serialized host requests.
	m := d.pc.framebuffer
	for offset, value := range map[int]uint32{8: 800, 12: 600, 16: 3200, 44: binary.LittleEndian.Uint32(m[40:])} {
		binary.LittleEndian.PutUint32(m[offset:], value)
	}
	nextResizeRequest(t, d, ctx).execute()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestDisplayResizeCancellationAndReset(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "reset"}[reset], func(t *testing.T) {
			d, ctx, cancel := resizeDriverFixture(t)
			defer cancel()
			operation, stop := context.WithCancel(ctx)
			defer stop()
			result := make(chan error, 1)
			go func() { result <- d.Resize(operation, 800, 600) }()
			nextResizeRequest(t, d, ctx).execute()
			if reset {
				// Even identical newly allocated mailbox contents belong to a new VM.
				d.cpuMu.Lock()
				next := *d.pc
				d.pc = &next
				d.cpuMu.Unlock()
				nextResizeRequest(t, d, ctx).execute()
			} else {
				stop()
			}
			select {
			case err := <-result:
				if err == nil || (!reset && !errors.Is(err, context.Canceled)) {
					t.Fatalf("resize result: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestDisplayResizeHonorsCallerDeadline(t *testing.T) {
	d, ctx, cancel := resizeDriverFixture(t)
	defer cancel()
	deadline := time.Now().Add(time.Minute)
	operation, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- d.Resize(operation, 800, 600) }()
	r := nextResizeRequest(t, d, ctx)
	actual, bounded := r.ctx.Deadline()
	if !bounded || !actual.Equal(deadline) {
		t.Errorf("resize shortened the caller deadline: got %v, want %v", actual, deadline)
	}
	stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled slow resize: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
