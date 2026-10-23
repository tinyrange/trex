package etl

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"testing"
)

// Independently assembled records using the documented field layout. One QPC
// tick is a millisecond here, so accounting assertions need no parser helpers.
func testEvent(group, op, version byte, tick uint64, payload []byte) []byte {
	n := 16 + len(payload)
	b := make([]byte, (n+7)&^7)
	b[0] = version
	b[2] = 0x11
	b[3] = 0xc0
	b[6] = op
	b[7] = group
	binary.LittleEndian.PutUint16(b[4:], uint16(n))
	binary.LittleEndian.PutUint64(b[8:], tick)
	copy(b[16:], payload)
	return b
}
func testBuffer(cpu uint16, records ...[]byte) []byte {
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint32(b, 4096)
	binary.LittleEndian.PutUint16(b[40:], cpu)
	n := 72
	for _, r := range records {
		copy(b[n:], r)
		n += len(r)
	}
	binary.LittleEndian.PutUint32(b[48:], uint32(n))
	return b
}
func testHeader(buffers uint32) []byte {
	b := make([]byte, 280)
	binary.LittleEndian.PutUint32(b, 4096)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint64(b[16:], 100_000_000)
	binary.LittleEndian.PutUint32(b[32:], 1)
	binary.LittleEndian.PutUint32(b[36:], buffers)
	binary.LittleEndian.PutUint32(b[44:], 8)
	binary.LittleEndian.PutUint64(b[256:], 1000)
	binary.LittleEndian.PutUint64(b[264:], 1)
	binary.LittleEndian.PutUint32(b[272:], 1)
	return testEvent(0, 0, 2, 1000, b)
}
func testThread(op byte, pid, tid uint32, t uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, pid)
	binary.LittleEndian.PutUint32(b[4:], tid)
	return testEvent(5, op, 3, t, b)
}
func testSwitch(cpuOld, cpuNew uint32, t uint64) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, cpuNew)
	binary.LittleEndian.PutUint32(b[4:], cpuOld)
	return testEvent(5, 36, 5, t, b)
}
func near(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("%s = %.9f, want %.9f", name, got, want)
	}
}
func TestAccountingSortsBuffersAndSeparatesIdleUnknownGaps(t *testing.T) {
	// CPU1's later buffer is physically before CPU0's earlier switch records.
	data := append(testBuffer(0, testHeader(3), testThread(1, 10, 100, 1000)), testBuffer(1, testSwitch(0, 0, 1000), testSwitch(0, 0, 4000))...)
	data = append(data, testBuffer(0, testSwitch(0, 100, 1000), testSwitch(100, 0, 2000), testSwitch(0, 999, 3000), testSwitch(999, 0, 4000))...)
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	near(t, "elapsed", r.ElapsedSeconds, 3)
	near(t, "scheduled", r.ScheduledSeconds, 1)
	near(t, "idle", r.IdleSeconds, 4)
	near(t, "unknown", r.UnknownThreadSeconds, 1)
	near(t, "uncovered", r.UncoveredSeconds, 0)
	if len(r.Processes) != 1 || r.Processes[0].PID != 10 {
		t.Fatalf("processes: %+v", r.Processes)
	}
	near(t, "bucket0 busy", r.Timeline[0].Busy, 1)
	near(t, "bucket2 unknown", r.Timeline[2].Unknown, 1)
}
func TestThreadReuseDoesNotRelabelEarlierCPU(t *testing.T) {
	data := testBuffer(0, testHeader(1), testThread(1, 10, 100, 1000), testSwitch(0, 100, 1000), testSwitch(100, 0, 2000), testThread(2, 10, 100, 2000), testThread(1, 20, 100, 3000), testSwitch(0, 100, 3000), testSwitch(100, 0, 4000))
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Processes) != 2 {
		t.Fatalf("%+v", r.Processes)
	}
	for _, p := range r.Processes {
		near(t, "reused thread process", p.CPUSeconds, 1)
	}
	near(t, "unobserved other CPU", r.UncoveredSeconds, 3)
}
func TestDiscontinuityExcluded(t *testing.T) {
	data := testBuffer(0, testHeader(1), testThread(1, 10, 100, 1000), testSwitch(0, 100, 1000), testSwitch(888, 0, 3000))
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.SwitchDiscontinuities != 1 {
		t.Fatal(r.SwitchDiscontinuities)
	}
	near(t, "gap not assigned", r.ScheduledSeconds, 0)
}
func TestFramingRejectsMalformedAndUnfinished(t *testing.T) {
	valid := testBuffer(0, testHeader(1))
	cases := map[string]func([]byte){
		"buffer too big":   func(b []byte) { binary.LittleEndian.PutUint32(b, 2<<20) },
		"filled too big":   func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 4097) },
		"compressed":       func(b []byte) { b[52] = 0x40 },
		"record too short": func(b []byte) { binary.LittleEndian.PutUint16(b[76:], 8) },
		"record too long":  func(b []byte) { binary.LittleEndian.PutUint16(b[76:], 65535) },
		"unknown header":   func(b []byte) { b[74] = 0x77 },
		"unfinalized":      func(b []byte) { binary.LittleEndian.PutUint64(b[88+16:], 0) },
		"missing buffer":   func(b []byte) { binary.LittleEndian.PutUint32(b[88+36:], 2) },
		"circular":         func(b []byte) { binary.LittleEndian.PutUint32(b[88+32:], 2) },
		"clock":            func(b []byte) { binary.LittleEndian.PutUint32(b[88+272:], 3) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(valid)
			change(b)
			if _, err := Analyze(context.Background(), bytes.NewReader(b), int64(len(b)), Limits{}); err == nil {
				t.Fatal("accepted invalid trace")
			}
		})
	}
	for _, n := range []int{0, 71, 72, 100, 4095} {
		if _, err := Analyze(context.Background(), bytes.NewReader(valid[:n]), int64(n), Limits{}); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
}
func TestLossLimitsAndCancellation(t *testing.T) {
	data := testBuffer(0, testHeader(1), testThread(1, 10, 100, 1000))
	data[52] = 2
	binary.LittleEndian.PutUint32(data[88+48:], 4)
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Header.EventsLost != 4 || r.Header.LossFlaggedBuffers != 1 || len(r.Warnings) < 2 {
		t.Fatal("lost loss diagnostics")
	}
	if _, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{MaxEvents: 1}); err == nil {
		t.Fatal("ignored event limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, bytes.NewReader(data), int64(len(data)), Limits{}); err != context.Canceled {
		t.Fatal(err)
	}
}
func FuzzReader(f *testing.F) {
	f.Add(testBuffer(0, testHeader(1)))
	f.Add(testBuffer(0, testHeader(1), testThread(1, 10, 100, 1001), testImage(1002, 0x10000, 10, 10, "sample.dll"), testSample(1003, 0x10010, 100, false)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = Analyze(context.Background(), bytes.NewReader(b), int64(len(b)), Limits{MaxBytes: 1 << 20, MaxEvents: 1000})
		_, _ = ProfileTrace(context.Background(), bytes.NewReader(b), int64(len(b)), Limits{MaxBytes: 1 << 20, MaxEvents: 1000})
	})
}
