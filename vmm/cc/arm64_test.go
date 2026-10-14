package cc

import (
	"context"
	"testing"

	"github.com/tinyrange/trex/vmm"
)

func TestARM64FinalEventsAndNonblockingDrain(t *testing.T) {
	d := &arm64Driver{events: make(chan vmm.Event, 32), ready: make(chan struct{}, 1)}
	for i := 0; i < 64; i++ {
		d.emit("apple.error", i)
	}
	for _, kind := range []string{"arm64.stop", "serial", "exit"} {
		d.emit(kind, nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	seen := make(map[string]bool)
	for len(d.events) > 0 {
		event, err := d.NextEvent(ctx)
		if err != nil {
			t.Fatal("queued events must precede a zero timeout:", err)
		}
		seen[event.Kind] = true
	}
	for _, kind := range []string{"arm64.stop", "serial", "exit"} {
		if !seen[kind] {
			t.Fatal("lost final event", kind)
		}
	}
	if _, err := d.NextEvent(ctx); err != context.Canceled {
		t.Fatalf("empty queue: %v", err)
	}
}
