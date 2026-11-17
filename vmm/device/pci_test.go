package device_test

import (
	"errors"
	"fmt"
	"github.com/tinyrange/trex/vmm/device"
	"testing"
	"time"
)

type registerDevice struct {
	config        [256]byte
	data          [64]byte
	writes        []byte
	line          uint32
	pending       bool
	next          time.Time
	polls, closed int
	fail          error
}

func fresh() *registerDevice {
	d := &registerDevice{line: 11}
	d.config[0] = 0x34
	d.config[1] = 0x12
	d.config[2] = 0x78
	d.config[3] = 0x56
	d.config[4] = 3
	d.config[0x11] = 0x20
	d.config[0x17] = 0xd4
	return d
}
func (d *registerDevice) ReadConfig(o uint16) byte { return d.config[o] }
func (d *registerDevice) WriteConfig(o uint16, v byte) {
	if o >= 4 {
		d.config[o] = v
	}
}
func (d *registerDevice) Regions() []device.Region {
	out := []device.Region{}
	if d.config[4]&1 != 0 {
		out = append(out, device.Region{BAR: 0, Space: device.IO, Base: uint64(d.config[0x11]) << 8, Size: 8})
	}
	if d.config[4]&2 != 0 {
		out = append(out, device.Region{BAR: 1, Space: device.Memory, Base: uint64(d.config[0x17]) << 24, Size: 64})
	}
	return out
}
func (d *registerDevice) Access(a device.Access) error {
	if d.fail != nil {
		return d.fail
	}
	if a.Write {
		copy(d.data[a.Offset:], a.Data)
		d.writes = append(d.writes, a.Data...)
	} else {
		copy(a.Data, d.data[a.Offset:])
	}
	return nil
}
func (d *registerDevice) Poll(time.Time) error      { d.polls++; return d.fail }
func (d *registerDevice) Deadline() time.Time       { return d.next }
func (d *registerDevice) Interrupt() (uint32, bool) { return d.line, d.pending }
func (d *registerDevice) State() any                { return d.polls }
func (d *registerDevice) ReadMemory(s string, a uint64, b []byte) error {
	if s != "ram" || a > 64 || uint64(len(b)) > 64-a {
		return fmt.Errorf("bad memory read")
	}
	copy(b, d.data[a:])
	return nil
}
func (d *registerDevice) ReadBAR(bar uint8, a uint64, b []byte) error {
	if bar != 1 {
		return fmt.Errorf("bad BAR")
	}
	return d.ReadMemory("ram", a, b)
}
func (d *registerDevice) Close() error { d.closed++; return nil }
func spec(name string, bdf uint16, d *registerDevice) device.Spec {
	return device.Spec{Name: name, BDF: bdf, New: func() (device.PCI, error) { return d, nil }}
}
func attach(t *testing.T, b *device.Bus, specs ...device.Spec) {
	t.Helper()
	if err := b.Attach(specs, device.Profile{Architecture: "i386", CPUs: 1}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
}

func TestPortablePCIIndependentFactoriesAndValidation(t *testing.T) {
	made := []*registerDevice{}
	s := device.Spec{Name: "experiment", BDF: 7 << 3, New: func() (device.PCI, error) { d := fresh(); made = append(made, d); return d, nil }}
	var a, b device.Bus
	attach(t, &a, s)
	attach(t, &b, s)
	if made[0] == made[1] {
		t.Fatal("model shared between machines")
	}
	for _, ss := range [][]device.Spec{{s, s}, {s, {Name: "other", BDF: s.BDF, New: s.New}}, {s, {Name: "bad", BDF: 256, New: s.New}}, {s, {Name: "empty", BDF: 9 << 3}}} {
		if err := b.Attach(ss, device.Profile{}, nil); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
	if len(made) != 2 || b.Len() != 1 {
		t.Fatal("invalid specs constructed models or damaged bus")
	}
	if err := device.Validate([]device.Spec{s}, device.Profile{}, map[uint16]bool{s.BDF: true}); err == nil {
		t.Fatal("reserved slot accepted")
	}
	if v, ok := a.Config(s.BDF, 0, false, 0); !ok || v != 0x34 {
		t.Fatal("configuration routing")
	}
	if v, ok := a.Config(s.BDF+1, 0, false, 0); ok || v != 0xff {
		t.Fatal("unattached function did not float high")
	}
	a.Config(s.BDF, 4, true, 0)
	if made[1].config[4] != 3 {
		t.Fatal("configuration leaked between machines")
	}
}

func TestPortablePCIRelocationAndStrictTransfers(t *testing.T) {
	d := fresh()
	var b device.Bus
	attach(t, &b, spec("registers", 7<<3, d))
	transfer := func(space device.Space, address uint64, width, count int, write bool, data []byte) (bool, error) {
		return b.Transfer(space, address, width, count, write, data, nil)
	}
	if handled, err := transfer(device.IO, 0x2003, 1, 3, true, []byte{1, 2, 3}); err != nil || !handled {
		t.Fatal(handled, err)
	}
	if d.data[3] != 3 || len(d.writes) != 3 {
		t.Fatal("REP must repeat same port, not increment address")
	}
	b.Config(7<<3, 0x11, true, 0x30)
	if handled, err := transfer(device.IO, 0x2003, 1, 1, true, []byte{9}); err != nil || handled {
		t.Fatal("stale BAR decoder", handled, err)
	}
	if handled, err := transfer(device.IO, 0x3003, 1, 1, false, []byte{0}); err != nil || !handled {
		t.Fatal("relocated BAR not decoded")
	}
	for _, tc := range []struct {
		space        device.Space
		address      uint64
		width, count int
		data         []byte
	}{
		{device.IO, 0x3007, 2, 1, make([]byte, 2)},
		{device.IO, 0xffff, 2, 1, make([]byte, 2)},
		{device.Memory, ^uint64(0), 2, 1, make([]byte, 2)},
		{device.Memory, 0xd4000000, 3, 1, make([]byte, 3)},
		{device.IO, 0x3000, 1, 2, []byte{1}},
		{device.IO, 0x3000, 0, 1, nil},
		{device.Memory, 0xd4000000, 1, 2, []byte{1, 2}},
	} {
		if _, err := transfer(tc.space, tc.address, tc.width, tc.count, true, tc.data); err == nil {
			t.Fatalf("invalid transfer accepted %+v", tc)
		}
	}
	if len(d.writes) != 3 {
		t.Fatal("invalid transfer had side effects")
	}
	b.Config(7<<3, 4, true, 0)
	if h, e := transfer(device.IO, 0x3000, 1, 1, true, []byte{9}); e != nil || h {
		t.Fatal("disabled I/O decode", h, e)
	}
	b.Config(7<<3, 4, true, 2)
	if _, e := transfer(device.Memory, 0xd4000004, 4, 1, true, []byte{4, 3, 2, 1}); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 4)
	if h, e := b.ReadPhysical(0xd4000004, data); e != nil || !h || data[0] != 4 || data[3] != 1 {
		t.Fatal("observational memory read", h, e, data)
	}
	if e := b.ReadMemory("registers", "ram", 4, data); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"missing", "registers"} {
		if e := b.ReadMemory(name, "unknown", 0, data); e == nil {
			t.Fatal("invalid inspection accepted")
		}
	}
}

func TestPortablePCIRejectsAmbiguousAndReservedBARs(t *testing.T) {
	a, c := fresh(), fresh()
	c.config[0x11] = 0x21
	c.config[0x17] = 0xd5
	var b device.Bus
	attach(t, &b, spec("a", 5<<3, a), spec("c", 6<<3, c))
	c.config[0x11] = 0x20
	if _, e := b.Transfer(device.IO, 0x2000, 1, 1, true, []byte{1}, nil); e == nil {
		t.Fatal("overlapping attachment BARs accepted")
	}
	c.config[4] = 0
	b.Reserved = func() []device.Region { return []device.Region{{Space: device.Memory, Base: 0xd4000020, Size: 64}} }
	// Even the non-overlapping start of the conflicting BAR must fail.
	if _, e := b.Transfer(device.Memory, 0xd4000000, 1, 1, true, []byte{1}, nil); e == nil {
		t.Fatal("partially overlapping platform BAR accepted")
	}
	if len(a.writes) != 0 || len(c.writes) != 0 {
		t.Fatal("conflict had side effects")
	}
}

func TestPortablePCIPollingSharedIRQErrorAndTeardown(t *testing.T) {
	a, c := fresh(), fresh()
	c.config[0x11] = 0x21
	c.config[0x17] = 0xd5
	now := time.Unix(100, 0)
	a.next = now.Add(time.Second)
	c.next = now.Add(time.Millisecond)
	levels := map[uint32]bool{}
	changes := 0
	b := device.Bus{SetIRQ: func(line uint32, on bool) error { levels[line] = on; changes++; return nil }}
	attach(t, &b, spec("a", 5<<3, a), spec("c", 6<<3, c))
	a.pending, c.pending = true, true
	if e := b.Poll(now); e != nil {
		t.Fatal(e)
	}
	if changes != 1 || !levels[11] || !b.Deadline().Equal(c.next) || a.polls != 1 || c.polls != 1 {
		t.Fatal("poll/deadline/IRQ failed")
	}
	a.pending = false
	b.SyncIRQ()
	if !levels[11] || changes != 1 {
		t.Fatal("one shared source cleared another")
	}
	c.line = 7
	b.SyncIRQ()
	if levels[11] || !levels[7] || changes != 3 {
		t.Fatal("IRQ relocation lost level")
	}
	if len(b.States()) != 2 || b.State("a") != 1 {
		t.Fatal("named inspection missing")
	}
	sentinel := errors.New("device failure")
	a.fail = sentinel
	if e := b.Poll(now); !errors.Is(e, sentinel) {
		t.Fatal("poll error swallowed", e)
	}
	if _, e := b.Transfer(device.IO, 0x2000, 1, 1, true, []byte{1}, nil); !errors.Is(e, sentinel) {
		t.Fatal("access error swallowed", e)
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	if levels[7] || a.closed != 1 || c.closed != 1 || b.Len() != 0 {
		t.Fatal("close did not release models/IRQ")
	}
	b.Close()
	if a.closed != 1 || c.closed != 1 {
		t.Fatal("close not idempotent")
	}
	// A failed factory must close both prior and partially constructed models.
	partial := fresh()
	first := fresh()
	e := b.Attach([]device.Spec{spec("first", 5<<3, first), {Name: "partial", BDF: 6 << 3, New: func() (device.PCI, error) { return partial, sentinel }}}, device.Profile{}, nil)
	if !errors.Is(e, sentinel) || first.closed != 1 || partial.closed != 1 || b.Len() != 0 {
		t.Fatal("failed construction leaked models", e)
	}
}
