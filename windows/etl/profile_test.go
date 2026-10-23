package etl

import (
	"bytes"
	"context"
	"testing"
)

func testSample(tick, ip uint64, tid uint32, interrupt bool) []byte {
	b := make([]byte, 16)
	le.PutUint64(b, ip)
	le.PutUint32(b[8:], tid)
	le.PutUint16(b[12:], 9)
	if interrupt {
		b[14] = 1
	}
	return testEvent(15, 46, 2, tick, b)
}
func testImage(tick, base uint64, pid uint32, op byte, name string) []byte {
	b := make([]byte, 56+2*(len(name)+1))
	le.PutUint64(b, base)
	le.PutUint64(b[8:], 256)
	le.PutUint32(b[16:], pid)
	le.PutUint32(b[20:], 7)
	le.PutUint32(b[24:], 8)
	for i, c := range name {
		le.PutUint16(b[56+2*i:], uint16(c))
	}
	group := byte(20)
	if op == 10 {
		group = 3
	}
	return testEvent(group, op, 3, tick, b)
}
func TestProfileLifetimesImagesAndInterrupts(t *testing.T) {
	// Physical buffers are out of time order. TID reuse must not relabel old IPs;
	// unload/reload changes module identity, and end rundown cannot fill gaps.
	data := testBuffer(0, testHeader(2), testThread(1, 10, 100, 1000), testImage(1001, 0x10000, 10, 10, "a.dll"), testSample(1002, 0x10010, 100, false), testSample(1003, 0x10100, 100, false), testImage(1004, 0x10000, 10, 2, "a.dll"), testSample(1005, 0x10010, 100, false), testImage(1006, 0x10000, 10, 10, "b.dll"), testSample(1007, 0x10010, 100, false))
	data = append(data, testBuffer(1, testThread(2, 10, 100, 1010), testSample(1011, 0x10010, 100, false), testThread(1, 20, 100, 1012), testImage(1013, 0x20000, 20, 10, "c.dll"), testSample(1014, 0x20020, 100, false), testImage(1015, 0xffff800000000000, 0, 3, "kernel"), testSample(1016, 0xffff800000000030, 100, true), testImage(1020, 0x10000, 20, 4, "end.dll"))...)
	p, err := ProfileTrace(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Samples != 7 || p.UnknownProcess != 1 || p.UnknownImage != 3 {
		t.Fatalf("samples=%d unknown process=%d image=%d", p.Samples, p.UnknownProcess, p.UnknownImage)
	}
	seen := map[string]uint32{}
	interrupts := 0
	for _, s := range p.Points {
		if s.Module >= 0 {
			seen[p.Modules[s.Module].Path] = p.Processes[s.Process].PID
		}
		if s.Interrupt {
			interrupts++
			if p.Modules[s.Module].Path != "kernel" {
				t.Fatal("interrupt image")
			}
		}
	}
	if seen["a.dll"] != 10 || seen["b.dll"] != 10 || seen["c.dll"] != 20 || interrupts != 1 || len(p.Modules) != 4 {
		t.Fatalf("%v modules=%v interrupts=%d", seen, p.Modules, interrupts)
	}
}
func TestProfileRejectsMalformedPayloads(t *testing.T) {
	for _, e := range []Event{{Group: 15, Opcode: 46, Version: 2, Payload: make([]byte, 15)}, {Group: 3, Opcode: 10, Version: 3, Payload: make([]byte, 58)}} {
		if _, _, err := decodeProfile(e, 8); err == nil {
			t.Fatal("accepted malformed payload")
		}
	}
}
