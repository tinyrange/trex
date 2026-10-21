package channel

import (
	"errors"
	"io"
	"testing"
)

func TestMemoryPairBoundariesAndCheckpoint(t *testing.T) {
	a, b, err := NewMemoryPair(4)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 4)
	if _, err := b.Read(p); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("empty read: %v", err)
	}
	if n, err := a.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatalf("write: %d %v", n, err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("overflow: %v", err)
	}
	restore, err := a.CaptureCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if n, err := b.Read(p[:2]); err != nil || n != 2 || string(p[:2]) != "ab" {
			t.Fatalf("partial: %d %q %v", n, p, err)
		}
		a.Close()
		if n, err := b.Read(p); err != nil || n != 2 || string(p[:2]) != "cd" {
			t.Fatalf("drain: %d %q %v", n, p, err)
		}
		if _, err := b.Read(p); err != io.EOF {
			t.Fatalf("EOF: %v", err)
		}
		if err := restore(); err != nil {
			t.Fatal(err)
		}
	}
}

func assertMemoryNotification(t *testing.T, notification <-chan struct{}, ready bool) {
	t.Helper()
	select {
	case <-notification:
		if !ready {
			t.Fatal("unexpected readiness notification")
		}
	default:
		if ready {
			t.Fatal("missing readiness notification")
		}
	}
}

func TestMemoryReadinessAndAtomicCapacity(t *testing.T) {
	a, b, _ := NewMemoryPair(4)
	read := b.ReadReady()
	assertMemoryNotification(t, read, false)
	capacity, changed, err := a.WriteCapacity()
	if capacity != 4 || err != nil {
		t.Fatalf("initial capacity: %d %v", capacity, err)
	}
	if n, err := a.WriteAvailable([]byte("abcde")); n != 0 || err != ErrWouldBlock {
		t.Fatalf("oversized write: %d %v", n, err)
	}
	assertMemoryNotification(t, changed, false)
	assertMemoryNotification(t, read, false)
	a.Write([]byte("abc"))
	assertMemoryNotification(t, changed, true)
	// Notifications are broadcasts; checking one does not consume readiness.
	assertMemoryNotification(t, read, true)
	assertMemoryNotification(t, read, true)
	assertMemoryNotification(t, b.ReadReady(), true)
	capacity, changed, err = a.WriteCapacity()
	if capacity != 1 || err != nil {
		t.Fatalf("partial capacity: %d %v", capacity, err)
	}
	if n, err := a.WriteAvailable([]byte("de")); n != 0 || err != ErrWouldBlock {
		t.Fatalf("atomic write: %d %v", n, err)
	}
	assertMemoryNotification(t, changed, false)
	data := make([]byte, 4)
	if n, err := b.ReadAvailable(data[:2]); n != 2 || err != nil || string(data[:2]) != "ab" {
		t.Fatalf("partial read: %d %q %v", n, data, err)
	}
	assertMemoryNotification(t, changed, true)
	assertMemoryNotification(t, b.ReadReady(), true)
	capacity, _, err = a.WriteCapacity()
	if capacity != 3 || err != nil {
		t.Fatalf("drained capacity: %d %v", capacity, err)
	}
	b.Read(data)
	read = b.ReadReady()
	assertMemoryNotification(t, read, false)
	if n, err := b.ReadAvailable(data); n != 0 || err != ErrWouldBlock {
		t.Fatalf("empty read remains nonblocking: %d %v", n, err)
	}
	_, changed, _ = a.WriteCapacity()
	a.Close()
	assertMemoryNotification(t, changed, true)
	assertMemoryNotification(t, read, true)
	assertMemoryNotification(t, a.ReadReady(), true)
	if _, err := b.Read(data); err != io.EOF {
		t.Fatalf("peer closed: %v", err)
	}
	for _, endpoint := range []*Memory{a, b} {
		if _, _, err := endpoint.WriteCapacity(); err != io.ErrClosedPipe {
			t.Fatalf("closed capacity: %v", err)
		}
	}
}

func TestMemoryCheckpointRestoresReadiness(t *testing.T) {
	a, b, _ := NewMemoryPair(4)
	empty, _ := a.CaptureCheckpoint()
	a.Write([]byte("abcd"))
	full, _ := b.CaptureCheckpoint()
	for iteration := 0; iteration < 2; iteration++ {
		capacity, fullWait, err := a.WriteCapacity()
		if capacity != 0 || err != nil {
			t.Fatalf("full capacity: %d %v", capacity, err)
		}
		assertMemoryNotification(t, fullWait, false)
		empty()
		assertMemoryNotification(t, fullWait, true)
		emptyWait := b.ReadReady()
		assertMemoryNotification(t, emptyWait, false)
		// Even an empty-to-empty restore wakes existing observers; the newly
		// queried readiness must still describe the restored empty stream.
		empty()
		assertMemoryNotification(t, emptyWait, true)
		emptyWait = b.ReadReady()
		assertMemoryNotification(t, emptyWait, false)
		full()
		assertMemoryNotification(t, emptyWait, true)
		assertMemoryNotification(t, b.ReadReady(), true)
		data := make([]byte, 4)
		if n, err := b.Read(data); n != 4 || err != nil || string(data) != "abcd" {
			t.Fatalf("restored bytes: %d %q %v", n, data, err)
		}
		a.Close()
		b.Close()
		full()
		if _, _, err := a.WriteCapacity(); err != nil {
			t.Fatalf("restore did not reopen endpoints: %v", err)
		}
	}
}
