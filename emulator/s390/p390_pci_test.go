package s390

import (
	"bytes"
	"github.com/tinyrange/trex/vmm/device"
	"testing"
)

func TestP390MemoryAndUnsupportedIO(t *testing.T) {
	d := newP390PCI()
	for _, v := range []byte{0x80, 0, 3} {
		if err := d.Access(device.Access{BAR: 0, Offset: 5, Write: true, Data: []byte{v}}); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte{0, 0x50, 0x22, 0x20}
	if err := d.Access(device.Access{BAR: 1, Offset: 0x200000, Write: true, Data: payload}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.memory[0x200000:0x200004], payload) || d.memory[0x20040] != 0 {
		t.Fatal("changed upload bytes or fabricated completion")
	}
	for _, a := range []device.Access{
		{BAR: 1, Offset: 0x3fffff, Data: []byte{1, 2}, Write: true},
		{BAR: 1, Offset: 0x200000, Data: []byte{1, 2, 3}, Write: true},
		{BAR: 0, Offset: 3, Data: []byte{0}},
		{BAR: 0, Offset: 4, Data: []byte{1}, Write: true},
		{BAR: 0, Offset: 5, Data: []byte{1, 2}, Write: true},
		{BAR: 2, Data: []byte{0}},
	} {
		if err := d.Access(a); err == nil {
			t.Fatalf("unsupported access accepted: %+v", a)
		}
	}
	d.WriteConfig(4, 1)
	if len(d.Regions()) != 1 || d.Regions()[0].Space != device.IO {
		t.Fatal("disabled memory decoder")
	}
	for _, space := range []string{"aperture", "main", "unknown"} {
		if err := d.ReadMemory(space, ^uint64(0), make([]byte, 2)); err == nil {
			t.Fatal("invalid inspection read accepted", space)
		}
	}
}

func TestP390PollingTraceIsBounded(t *testing.T) {
	d := newP390PCI()
	d.record("memory", 0x20043, true, []byte{2})
	for range 10000 {
		d.record("memory", 0x20040, false, []byte{0})
	}
	if len(d.trace) != 2 || d.trace[1].(map[string]any)["count"] != int64(10000) {
		t.Fatal("polling erased request or lost repeat count")
	}
	for i := range 1000 {
		d.record("memory", uint64(i), true, []byte{byte(i)})
	}
	if len(d.trace) != 64 || d.transfers != 11001 {
		t.Fatal("trace exceeded bound or lost transfer count")
	}
}

func TestP390InterruptMaskAcknowledgmentAndReset(t *testing.T) {
	d := newP390PCI()
	io := func(off uint64, write bool, v byte) byte {
		t.Helper()
		data := []byte{v}
		if err := d.Access(device.Access{BAR: 0, Offset: off, Write: write, Data: data}); err != nil {
			t.Fatal(err)
		}
		return data[0]
	}
	d.service.InterruptPending, d.service.InterruptReason = true, 1
	io(5, true, 0)
	if _, on := d.Interrupt(); on || io(7, false, 0) != 2 {
		t.Fatal("masked request lost/delivered")
	}
	io(5, true, 3)
	if line, on := d.Interrupt(); !on || line != 11 || io(6, false, 0) != 1 {
		t.Fatal("interrupt not delivered")
	}
	io(4, true, 0xe0)
	if _, on := d.Interrupt(); on || io(7, false, 0) != 0 {
		t.Fatal("ack did not deassert")
	}
	d.service.Initialized = true
	io(5, true, 0x80)
	if d.service.Initialized || !d.service.Machine.CPUs[0].Stopped {
		t.Fatal("reset had no effect")
	}
}
