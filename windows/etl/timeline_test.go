package etl

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func TestProcessTimelineBoundariesReuseAndCompletion(t *testing.T) {
	process := func(op byte, tick uint64) []byte {
		p := make([]byte, 48)
		binary.LittleEndian.PutUint32(p[8:], 10)
		p = append(p, []byte("worker.exe\x00")...)
		return testEvent(3, op, 4, tick, p)
	}
	disk := make([]byte, 52)
	binary.LittleEndian.PutUint32(disk[8:], 8192)
	binary.LittleEndian.PutUint32(disk[48:], 100)
	data := testBuffer(0, testHeader(2), process(1, 1000), testThread(1, 10, 100, 1000),
		testSwitch(0, 100, 1250), testEvent(1, 10, 3, 2100, disk), testSwitch(100, 0, 2500),
		testThread(2, 10, 100, 2600), process(2, 2600))
	data = append(data, testBuffer(0, process(1, 3000), testThread(1, 10, 100, 3000),
		testSwitch(0, 100, 3250), testSwitch(100, 0, 3750),
		testEvent(1, 11, 3, 4000, disk), testSwitch(999, 0, 5000))...)
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Processes) != 2 {
		t.Fatalf("lifetimes: %+v", r.Processes)
	}
	a, b := r.Processes[0], r.Processes[1]
	if a.PID != b.PID || len(a.Timeline) != 2 || len(b.Timeline) != 2 {
		t.Fatal("lost sparse lifetime boundaries")
	}
	// Disk completion created second 1 before the spanning CPU interval added
	// second 0. Output must still be chronological, with exact fractional CPU.
	if a.Timeline[0].Second != 0 || a.Timeline[1].Second != 1 {
		t.Fatal(a.Timeline)
	}
	near(t, "first CPU bucket", a.Timeline[0].CPUSeconds, .75)
	near(t, "second CPU bucket", a.Timeline[1].CPUSeconds, .5)
	if a.Timeline[0].ReadBytes != 0 || a.Timeline[1].ReadBytes != 8192 {
		t.Fatal("I/O not charged at completion")
	}
	if b.Timeline[0].Second != 2 || b.Timeline[1].Second != 3 || b.Timeline[1].WriteBytes != 8192 {
		t.Fatal(b.Timeline)
	}
	near(t, "reused PID", b.Timeline[0].CPUSeconds, .5)
	near(t, "IO-only bucket", b.Timeline[1].CPUSeconds, 0)
	if r.SwitchDiscontinuities != 1 {
		t.Fatal("gap not detected")
	}
	for _, p := range r.Processes {
		var cpu float64
		var read, write uint64
		for _, v := range p.Timeline {
			cpu += v.CPUSeconds
			read += v.ReadBytes
			write += v.WriteBytes
		}
		near(t, "bucket conservation", cpu, p.CPUSeconds)
		if read != p.ReadBytes || write != p.WriteBytes {
			t.Fatal("I/O not conserved")
		}
	}
}
