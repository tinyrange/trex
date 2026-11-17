package cc

import (
	"encoding/binary"
	"github.com/tinyrange/trex/vmm/device"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
	"time"
)

// Deliberately unrelated to P/390: registering a second native model must not
// require a new field or case in the PC's discovery, exit, or scheduler code.
type doorbellDevice struct {
	config  [256]byte
	value   byte
	pending bool
	polls   int
	next    time.Time
}

func (d *doorbellDevice) ReadConfig(o uint16) byte { return d.config[o] }
func (d *doorbellDevice) WriteConfig(o uint16, v byte) {
	if o >= 4 {
		d.config[o] = v
	}
}
func (d *doorbellDevice) Regions() []device.Region {
	if d.config[4]&3 != 3 {
		return nil
	}
	return []device.Region{{BAR: 0, Space: device.IO, Base: uint64(d.config[0x11]) << 8, Size: 16}, {BAR: 1, Space: device.Memory, Base: uint64(d.config[0x17]) << 24, Size: 16}}
}
func (d *doorbellDevice) Access(a device.Access) error {
	if a.Write {
		d.value = a.Data[0]
		d.pending = true
	} else {
		for i := range a.Data {
			a.Data[i] = d.value
		}
	}
	return nil
}
func (d *doorbellDevice) Poll(time.Time) error      { d.polls++; return nil }
func (d *doorbellDevice) Deadline() time.Time       { return d.next }
func (d *doorbellDevice) Interrupt() (uint32, bool) { return 11, d.pending }

type attachmentCPU struct {
	hypervisor.X86
	value   uint64
	width   uint32
	cancels int
	levels  map[uint32]bool
}

func (c *attachmentCPU) CompleteMMIORead(value uint64, width uint32) { c.value, c.width = value, width }
func (c *attachmentCPU) SetIRQ(line uint32, on bool) error           { c.levels[line] = on; return nil }
func (c *attachmentCPU) Cancel() error                               { c.cancels++; return nil }

func TestExperimentalDeviceUsesGenericPCDiscoveryRoutingAndScheduling(t *testing.T) {
	now := time.Unix(100, 0)
	d := &doorbellDevice{next: now.Add(time.Millisecond)}
	binary.LittleEndian.PutUint32(d.config[:], 0xbabecafe)
	d.config[4] = 3
	d.config[0x11] = 0x24
	d.config[0x17] = 0xd6
	cpu := &attachmentCPU{levels: map[uint32]bool{}}
	p := &pc{cpu: cpu, now: func() time.Time { return now }}
	p.devices.Reserved = p.deviceReservations
	p.devices.SetIRQ = p.setDeviceIRQ
	if err := p.devices.Attach([]device.Spec{{Name: "doorbell", BDF: 7 << 3, New: func() (device.PCI, error) { return d, nil }}}, device.Profile{Architecture: "i386", CPUs: 1}, reservedPCISlots()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.devices.Close() })
	r := x86state.Registers{Rax: 0xb102, Rcx: 0xbabe, Rdx: 0xcafe}
	if status, err := p.pciBIOS(&r); err != nil || status != 0 || r.Rbx != 7<<3 {
		t.Fatal("BIOS did not discover generic device", status, err, r)
	}
	latch := make([]byte, 4)
	binary.LittleEndian.PutUint32(latch, 0x80003800)
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xcf8, Size: 4, Count: 1, Write: true, Data: latch}); err != nil {
		t.Fatal(err)
	}
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xcfc, Size: 4, Count: 1, Data: latch}); err != nil || binary.LittleEndian.Uint32(latch) != 0xbabecafe {
		t.Fatal("CF8 did not discover generic device", err, latch)
	}
	if err := p.handleIO(hypervisor.X86Exit{Port: 0x2400, Size: 1, Count: 2, Write: true, Data: []byte{3, 7}}); err != nil {
		t.Fatal(err)
	}
	if err := p.handleMMIO(hypervisor.X86Exit{Address: 0xd6000000, Size: 4}); err != nil || cpu.value != 0x07070707 || cpu.width != 4 {
		t.Fatal("MMIO read completion", err, cpu)
	}
	next, deliver, commit, err := p.pollDevices()
	if err != nil || !next.Equal(d.next) || !cpu.levels[11] || d.polls != 1 {
		t.Fatal("generic polling/IRQ/deadline", next, err)
	}
	if err := deliver(); err != nil {
		t.Fatal(err)
	}
	commit()
	if cpu.cancels != 1 {
		t.Fatal("deadline must wake CPU, not mutate model concurrently")
	}
	// Guest relocation immediately changes the decoder.
	if _, err := p.pciBIOSConfig(7<<3, 0x17, 1, true, 0xd7); err != nil {
		t.Fatal(err)
	}
	if err := p.handleMMIO(hypervisor.X86Exit{Address: 0xd7000000, Size: 1, Write: true, Data: []byte{9}}); err != nil || d.value != 9 {
		t.Fatal("relocated MMIO", err)
	}
	// A relocation into platform RAM/ROM must not steal its accesses.
	d.config[0x17] = 0
	if err := p.handleMMIO(hypervisor.X86Exit{Address: 0, Size: 1, Write: true, Data: []byte{5}}); err == nil || d.value != 9 {
		t.Fatal("platform conflict not rejected before side effect")
	}
	if err := p.setDeviceIRQ(4, true); err == nil {
		t.Fatal("shared planar serial IRQ accepted")
	}
}

func TestPCIDeviceStarlarkConfigurationAndIsolation(t *testing.T) {
	thread := &starlark.Thread{Name: "device-config"}
	call := func(name string, args ...starlark.Tuple) (starlark.Value, error) {
		return starlark.Call(thread, Builtins()[name], nil, args)
	}
	d, err := call("p390", starlark.Tuple{starlark.String("name"), starlark.String("coprocessor")}, starlark.Tuple{starlark.String("slot"), starlark.MakeInt(7)}, starlark.Tuple{starlark.String("s370"), starlark.True})
	if err != nil {
		t.Fatal(err)
	}
	value, err := call("backend", starlark.Tuple{starlark.String("devices"), starlark.NewList([]starlark.Value{d})})
	if err != nil {
		t.Fatal(err)
	}
	specs := value.(*Backend).deviceSpecs()
	if len(specs) != 1 || specs[0].Name != "coprocessor" || specs[0].BDF != 7<<3 {
		t.Fatal("lost attachment policy", specs)
	}
	a, _ := specs[0].New()
	b, _ := specs[0].New()
	if a == b {
		t.Fatal("factory shared mutable model")
	}
	if err := a.Access(device.Access{BAR: 1, Offset: 0x200000, Write: true, Data: []byte{0x12}}); err != nil {
		t.Fatal(err)
	}
	data := []byte{0xff}
	if err := b.(device.MemoryReader).ReadMemory("aperture", 0x200000, data); err != nil || data[0] != 0 {
		t.Fatal("factory model memory not isolated", err, data)
	}
	for _, opts := range [][]starlark.Tuple{
		{{starlark.String("devices"), starlark.NewList([]starlark.Value{d, d})}},
		{{starlark.String("devices"), starlark.NewList([]starlark.Value{starlark.String("not a device")})}},
		{{starlark.String("devices"), starlark.None}},
	} {
		if _, err := call("backend", opts...); err == nil {
			t.Fatal("invalid attachment accepted")
		}
	}
	for _, slot := range []int{-1, 0, 1, 4, 32} {
		if _, err := call("p390", starlark.Tuple{starlark.String("slot"), starlark.MakeInt(slot)}); err == nil {
			t.Fatal("invalid/reserved slot", slot)
		}
	}
	// Structural parsing must not guess i386 when another model requires x86_64.
	custom := NewPCIDeviceValue(device.Spec{Name: "custom", BDF: 8 << 3, New: func() (device.PCI, error) { return &doorbellDevice{}, nil }, Check: func(p device.Profile) error {
		if p.Architecture != "x86_64" {
			return errorsForTest("requires x86_64")
		}
		return nil
	}})
	if _, err := call("backend", starlark.Tuple{starlark.String("devices"), starlark.Tuple{custom}}); err != nil {
		t.Fatal("device profile guessed at parse time", err)
	}
}

type errorsForTest string

func (e errorsForTest) Error() string { return string(e) }
