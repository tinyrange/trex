package cc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

type inputTestCPU struct{ hypervisor.X86 }

func (inputTestCPU) Cancel() error { return nil }

func TestWindowsKeyScanCodes(t *testing.T) {
	for name, code := range map[string]byte{"meta_l": 0x5b, "meta_r": 0x5c} {
		keyboard := newKeyboard(func(uint32, bool) error { return nil })
		for _, down := range []bool{true, false} {
			if err := keyboard.key(name, down); err != nil {
				t.Fatal(err)
			}
		}
		want := []byte{0xe0, code, 0xe0, code | 0x80}
		if len(keyboard.queue) != len(want) {
			t.Fatalf("%s scan codes: %+v", name, keyboard.queue)
		}
		for i, value := range want {
			if keyboard.queue[i].value != value {
				t.Fatalf("%s byte %d: got %x, want %x", name, i, keyboard.queue[i].value, value)
			}
		}
	}
}

func TestChordReleaseWaitsForBusyDeviceLoop(t *testing.T) {
	keyboard := newKeyboard(func(uint32, bool) error { return nil })
	d := &driver{
		pc:       &pc{cpu: inputTestCPU{}, keyboard: keyboard},
		requests: make(chan request, 16),
		done:     make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- d.Input(ctx, vmm.Input{Kind: "keys", Keys: []string{"f"}}) }()
	select {
	case request := <-d.requests:
		request.execute()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Model a serialized cold disk read after the guest accepts the press.
	// A live caller must not acquire the cancelled-call cleanup deadline.
	select {
	case request := <-d.requests:
		time.Sleep(1200 * time.Millisecond)
		request.execute()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if len(keyboard.queue) != 2 || keyboard.queue[0].value != 0x21 || keyboard.queue[1].value != 0xa1 {
		t.Fatalf("press/release scan codes: %+v", keyboard.queue)
	}
}

func TestCancelledChordReleasesAcceptedPresses(t *testing.T) {
	keyboard := newKeyboard(func(uint32, bool) error { return nil })
	d := &driver{
		pc:       &pc{cpu: inputTestCPU{}, keyboard: keyboard},
		requests: make(chan request, 16),
		done:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- d.Input(ctx, vmm.Input{Kind: "keys", Keys: []string{"alt", "f"}}) }()
	for i := 0; i < 2; i++ {
		select {
		case request := <-d.requests:
			request.execute()
			cancel()
		case <-time.After(5 * time.Second):
			t.Fatal("missing key transition request")
		}
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("input error: %v", err)
	}
	want := []byte{0x38, 0x21, 0xa1, 0xb8}
	if len(keyboard.queue) != len(want) {
		t.Fatalf("press/release scan codes: %+v", keyboard.queue)
	}
	for i, value := range want {
		if keyboard.queue[i].value != value {
			t.Fatalf("scan code %d: got %x, want %x", i, keyboard.queue[i].value, value)
		}
	}
}

func TestChordCancellationWhileReleaseIsQueued(t *testing.T) {
	keyboard := newKeyboard(func(uint32, bool) error { return nil })
	d := &driver{pc: &pc{cpu: inputTestCPU{}, keyboard: keyboard}, requests: make(chan request, 16), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- d.Input(ctx, vmm.Input{Kind: "keys", Keys: []string{"f"}}) }()
	(<-d.requests).execute()
	release := <-d.requests
	cancel()
	release.execute()
	select {
	case cleanup := <-d.requests:
		cleanup.execute()
	case err := <-result:
		t.Fatalf("returned before releasing accepted press: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("missing cancelled-release cleanup")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("input error: %v", err)
	}
	if len(keyboard.queue) != 2 || keyboard.queue[1].value != 0xa1 {
		t.Fatalf("press/release scan codes: %+v", keyboard.queue)
	}
}
