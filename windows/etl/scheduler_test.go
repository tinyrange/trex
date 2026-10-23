package etl

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func TestSchedulerOrderingReadyAndReuse(t *testing.T) {
	ready := make([]byte, 8)
	binary.LittleEndian.PutUint32(ready, 100)
	// File order differs from event order. An unrelated owner later reuses TID100.
	data := testBuffer(0, testHeader(3), testThread(1, 10, 100, 1100), testThread(1, 20, 200, 1100), testSwitch(0, 100, 1200), testSwitch(100, 200, 1300))
	data = append(data, testBuffer(0, testSwitch(200, 100, 1500), testSwitch(100, 0, 1600), testThread(2, 10, 100, 1700), testThread(1, 30, 100, 1800), testSwitch(0, 100, 1900))...)
	data = append(data, testBuffer(0, testEvent(5, 50, 2, 1400, ready))...)
	r, err := SchedulerTrace(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"thread_start", "in", "out", "ready", "in", "out", "thread_end"}
	if len(r.Records) != len(want) {
		t.Fatalf("records: %+v", r.Records)
	}
	for i, e := range r.Records {
		if e.Kind != want[i] || e.TID != 100 {
			t.Fatal(r.Records)
		}
	}
	near(t, "ready time", r.Records[3].Seconds, .4)
	if r.Records[3].PeerTID != 200 || r.Records[3].PeerPID != 20 {
		t.Fatal("lost observed ready context", r.Records[3])
	}
	if r.Discontinuities != 0 {
		t.Fatal(r.Discontinuities)
	}
	if _, err := SchedulerTrace(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{}, 10, 2); err == nil {
		t.Fatal("accepted result overflow")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SchedulerTrace(ctx, bytes.NewReader(data), int64(len(data)), Limits{}, 10, 100); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestSchedulerRundownDoesNotInventOwner(t *testing.T) {
	data := testBuffer(0, testHeader(1), testSwitch(0, 100, 1200), testSwitch(100, 0, 1300), testThread(4, 10, 100, 1500))
	r, err := SchedulerTrace(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records) != 0 {
		t.Fatal("invented thread lifetime", r.Records)
	}
	// Corruption must not be hidden by selecting an absent PID.
	if _, err := SchedulerTrace(context.Background(), bytes.NewReader(data[:len(data)-1]), int64(len(data)-1), Limits{}, 999, 100); err == nil {
		t.Fatal("accepted truncation")
	}
}
