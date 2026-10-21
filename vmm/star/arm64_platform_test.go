package star

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/channel"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

type platformTestRuntime struct {
	ctx       context.Context
	ram       []byte
	registers [31]uint64
	events    []string
}

func (r *platformTestRuntime) Context() context.Context { return r.ctx }
func (r *platformTestRuntime) Machine() vmmapi.Machine {
	return vmmapi.Machine{Architecture: "arm64", Memory: int64(len(r.ram)), CPUs: 1, ARM64Boot: &vmmapi.ARM64Boot{MemoryBase: 0x1000, Address: 0x1000, Entry: 0x1000, Image: bytes.NewReader([]byte{0, 0, 0, 0})}}
}
func (r *platformTestRuntime) Memory(a, n uint64, w bool) ([]byte, error) {
	if a < 0x1000 || a-0x1000 > uint64(len(r.ram)) || n > uint64(len(r.ram))-(a-0x1000) {
		return nil, fmt.Errorf("outside RAM")
	}
	return r.ram[a-0x1000 : a-0x1000+n], nil
}
func (*platformTestRuntime) Protect(uint64, uint64, bool, bool, bool) error { return nil }
func (*platformTestRuntime) Counter() (uint64, uint64, error)               { return 7, 100, nil }
func (*platformTestRuntime) EpochMicroseconds() uint64                      { return 123 }
func (*platformTestRuntime) SetSPI(uint32, bool) error                      { return nil }
func (r *platformTestRuntime) Register(i uint32) (uint64, error)            { return r.registers[i], nil }
func (r *platformTestRuntime) SetRegister(i uint32, v uint64) error         { r.registers[i] = v; return nil }
func (*platformTestRuntime) GuestChannel(string) (channel.ByteChannel, error) {
	return nil, fmt.Errorf("no channel")
}
func (r *platformTestRuntime) Emit(kind string, payload any) { r.events = append(r.events, kind) }

func testPlatform(t *testing.T, source string) *vmmapi.ARM64Platform {
	t.Helper()
	g, err := starlark.ExecFileOptions(&syntax.FileOptions{While: true}, &starlark.Thread{}, "platform.star", source, starlark.StringDict{"vmm": &starlarkstruct.Module{Name: "vmm", Members: Builtins()}})
	if err != nil {
		t.Fatal(err)
	}
	p := g["platform"].(*arm64PlatformValue).platform
	return &p
}

func TestARM64PlatformMMIOIsolationRoutingAndHypercall(t *testing.T) {
	p := testPlatform(t, `
def create(ctx):
    state = [7]
    def read(offset, size):
        return state[0] + offset
    def write(offset, size, value):
        state[0] = value
        ctx.write_memory(0x1000, "AB")
    def hvc(immediate, function):
        if immediate == 9 and function == 0x1234:
            ctx.write_register(0, state[0])
            ctx.emit("service", {"function": function})
            return True
        return False
    return {"devices": [vmm.mmio(0x9000, 16, read, write, widths=[4]), vmm.mmio(0x9000, 256, read=lambda o,s: 99, widths=[4])], "hvc": hvc}
platform = vmm.arm64_platform(create, gic_distributor=0x20000, gic_redistributor=0x40000)
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &platformTestRuntime{ctx: ctx, ram: make([]byte, 4096)}
	one, err := p.New(r)
	if err != nil {
		t.Fatal(err)
	}
	two, err := p.New(r)
	if err != nil {
		t.Fatal(err)
	}
	if p.GICDistributor != 0x20000 || p.GICRedistributor != 0x40000 || one.Contains(0x9001, 4) || one.Contains(0x9000, 8) || one.Contains(0x9100, 4) {
		t.Fatal("platform placement/width validation")
	}
	if err := one.Write(0x9000, 4, 42); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.ram[:2], []byte("AB")) {
		t.Fatal("callback RAM write lost")
	}
	if v, err := one.Read(0x9004, 4); err != nil || v != 46 {
		t.Fatal(v, err)
	}
	if v, err := two.Read(0x9000, 4); err != nil || v != 7 {
		t.Fatal("device state shared across VMs", v, err)
	}
	if v, err := one.Read(0x9010, 4); err != nil || v != 99 {
		t.Fatal("ordered overlap routing", v, err)
	}
	h := one.(vmmapi.ARM64HypercallHandler)
	if handled, err := h.HVC(9, 0x1234); err != nil || !handled || r.registers[0] != 42 || len(r.events) != 1 {
		t.Fatal("HVC callback failed", handled, err)
	}
	if handled, err := h.HVC(0, 0x8300feff); err != nil || handled {
		t.Fatal("unrequested OEM service handled", handled, err)
	}
	owner := one.(*starARM64Devices).thread
	escaped := &arm64RuntimeValue{runtime: r, thread: owner}
	read, _ := escaped.Attr("read_memory")
	if _, err := starlark.Call(&starlark.Thread{}, read, starlark.Tuple{starlark.MakeUint64(0x1000), starlark.MakeInt(1)}, nil); err == nil || !strings.Contains(err.Error(), "callback thread") {
		t.Fatal("runtime escaped execution ownership", err)
	}
	cancel()
	if err := one.Write(0x9000, 4, 2); err == nil {
		t.Fatal("runtime operations remain available after stop")
	}
}

func TestARM64PlatformCallbackCancellationAndErrors(t *testing.T) {
	p := testPlatform(t, `
def create(ctx):
    def read(o,s):
        return 1 << 40
    def write(o,s,v):
        while True:
            pass
    return {"devices":[vmm.mmio(0x8000,8,read,write)]}
platform=vmm.arm64_platform(create)
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &platformTestRuntime{ctx: ctx, ram: make([]byte, 4096)}
	dev, err := p.New(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Read(0x8000, 4); err == nil || !strings.Contains(err.Error(), "width") {
		t.Fatal("oversized MMIO result", err)
	}
	done := make(chan error, 1)
	go func() { done <- dev.Write(0x8000, 4, 1) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("infinite callback was not canceled")
		}
	case <-time.After(time.Second):
		t.Fatal("callback prevents VM cancellation")
	}
}

type closeTestDevice struct{ closes *int }

func (*closeTestDevice) Contains(uint64, int) bool        { return false }
func (*closeTestDevice) Read(uint64, int) (uint64, error) { return 0, nil }
func (*closeTestDevice) Write(uint64, int, uint64) error  { return nil }
func (d *closeTestDevice) Close() error                   { *d.closes++; return nil }

func TestARM64NativeDeviceOwnershipAndFactoryCleanup(t *testing.T) {
	closes := 0
	RegisterARM64Device("test-close", func(vmmapi.ARM64Runtime, *starlark.Thread, *starlark.Dict) (vmmapi.ARM64Device, error) {
		return &closeTestDevice{&closes}, nil
	})
	t.Cleanup(func() { arm64Factories.Lock(); delete(arm64Factories.factories, "test-close"); arm64Factories.Unlock() })
	p := testPlatform(t, `
def definition():
    cached=[]
    def create(ctx):
        if not cached:
            cached.append(ctx.device("test-close",{}))
            ctx.device("test-close",{})
        return {"devices":cached}
    return vmm.arm64_platform(create)
platform=definition()
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &platformTestRuntime{ctx: ctx, ram: make([]byte, 4096)}
	d, err := p.New(r)
	if err != nil || closes != 1 {
		t.Fatalf("unused device cleanup: closes=%d err=%v", closes, err)
	}
	if _, err := p.New(r); err == nil || !strings.Contains(err.Error(), "another platform") {
		t.Fatal("reused native device accepted", err)
	}
	if closes != 1 {
		t.Fatal("foreign platform closed the first VM's device")
	}
	d.(interface{ Close() error }).Close()
	if closes != 2 {
		t.Fatal("retained device not closed")
	}
	bad := testPlatform(t, `
def create(ctx):
    used=ctx.device("test-close",{})
    unused=ctx.device("test-close",{})
    return {"devices":[used, 1]}
platform=vmm.arm64_platform(create)
`)
	if _, err := bad.New(r); err == nil || closes != 4 {
		t.Fatalf("failed factory leaked resources: closes=%d err=%v", closes, err)
	}
}
