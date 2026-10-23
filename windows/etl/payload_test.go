package etl

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func TestWaitReadyAndInterruptIntervals(t *testing.T) {
	out := testSwitch(100, 0, 2000)
	out[16+12] = 6
	out[16+14] = 5
	ready := make([]byte, 8)
	binary.LittleEndian.PutUint32(ready, 100)
	dpc := make([]byte, 16)
	binary.LittleEndian.PutUint64(dpc, 2500)
	data := testBuffer(0, testHeader(1), testThread(1, 10, 100, 1000), testSwitch(0, 100, 1000), out, testEvent(15, 68, 2, 2600, dpc), testEvent(5, 50, 2, 3000, ready), testSwitch(0, 100, 4000), testSwitch(100, 0, 5000))
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	p := r.Processes[0]
	near(t, "CPU", p.CPUSeconds, 2)
	near(t, "blocked", p.BlockedSeconds, 1)
	near(t, "ready", p.ReadySeconds, 1)
	near(t, "wait reason", p.WaitReasons[6], 1)
	near(t, "DPC", r.DPCSeconds, .1)
}
func TestDiskResponseUsesQPCNotEventClock(t *testing.T) {
	b := make([]byte, 52)
	binary.LittleEndian.PutUint32(b[8:], 8192)
	binary.LittleEndian.PutUint64(b[40:], 500)
	binary.LittleEndian.PutUint32(b[48:], 100)
	header := testHeader(1)
	binary.LittleEndian.PutUint32(header[16+272:], 2)
	data := testBuffer(0, header, testThread(1, 10, 100, 1000), testEvent(1, 10, 3, 10_001_000, b))
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	near(t, "FILETIME event span", r.ElapsedSeconds, 1)
	near(t, "QPC I/O latency", r.Processes[0].DiskResponseSeconds, .5)
	if r.Processes[0].ReadBytes != 8192 {
		t.Fatal(r.Processes[0])
	}
}
func TestProcessSchemasAndSIDBounds(t *testing.T) {
	for _, pointer := range []int{4, 8} {
		fixed := 28 + 2*(pointer-4)
		b := make([]byte, fixed+4)
		binary.LittleEndian.PutUint32(b[pointer:], 42)
		binary.LittleEndian.PutUint32(b[pointer+4:], 4)
		b = append(b, []byte("worker.exe\x00")...)
		b = append(b, []byte{'x', 0, 0, 0}...)
		it, ok, err := decode(Event{Group: 3, Opcode: 1, Version: 4, Payload: b}, pointer)
		if err != nil || !ok || it.x != 42 || it.y != 4 || it.name != "worker.exe" || it.command != "x" {
			t.Fatalf("pointer %d: %+v %v %v", pointer, it, ok, err)
		}
		// A non-null TOKEN_USER with a SID authority count extending past payload.
		binary.LittleEndian.PutUint32(b[fixed:], 1)
		if len(b) > fixed+2*pointer+1 {
			b[fixed+2*pointer+1] = 15
		}
		if _, _, err := decode(Event{Group: 3, Opcode: 1, Version: 4, Payload: b}, pointer); err == nil {
			t.Fatal("accepted out-of-bounds SID")
		}
	}
}
func TestZeroTimestampAndFutureSchema(t *testing.T) {
	header := testHeader(1)
	binary.LittleEndian.PutUint64(header[8:], 0)
	future := testEvent(5, 36, 99, 2000, []byte{1})
	data := testBuffer(0, header, testThread(1, 10, 100, 0), testSwitch(0, 100, 0), testSwitch(100, 0, 1000), future)
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	near(t, "zero-origin CPU", r.ScheduledSeconds, 1)
	near(t, "span", r.ElapsedSeconds, 2)
	found := false
	for _, s := range r.Schemas {
		if s.Version == 99 {
			found = true
			if s.Decoded != 0 {
				t.Fatal("guessed future schema")
			}
		}
	}
	if !found {
		t.Fatal("omitted future schema")
	}
}
func Test32BitLogfileHeaderAndFraming(t *testing.T) {
	header := testHeader(1)
	payload := bytes.Clone(header[16 : 16+280])
	copy(payload[240:], payload[248:280])
	payload = payload[:272]
	binary.LittleEndian.PutUint32(payload[44:], 4)
	data := testBuffer(0, testEvent(0, 0, 2, 1000, payload))
	h, err := Walk(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{}, nil)
	if err != nil || h.PointerSize != 4 || h.QPCFrequency != 1000 {
		t.Fatalf("%+v %v", h, err)
	}
	for _, typ := range []byte{1, 2, 3, 4, 0x10, 0x11, 0x0a, 0x14, 0x12, 0x13} {
		b := make([]byte, 96)
		b[2] = typ
		b[3] = 0xc0
		if typ == 1 || typ == 2 || typ == 3 || typ == 4 || typ == 0x10 || typ == 0x11 {
			binary.LittleEndian.PutUint16(b[4:], 96)
		} else {
			binary.LittleEndian.PutUint16(b, 96)
		}
		e, n, err := record(b)
		if err != nil || n != 96 || e.HeaderType != typ {
			t.Fatalf("type %x: %+v %d %v", typ, e, n, err)
		}
		// Every truncation of the declared record must be rejected, never panicked.
		for end := 0; end < 96; end++ {
			if _, _, err := record(b[:end]); err == nil {
				t.Fatalf("type %x accepted %d bytes", typ, end)
			}
		}
	}
}
