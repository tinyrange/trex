package rfe

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	shared "github.com/tinyrange/trex/vmm/cc"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestBIOSMouseIRQ12CallsGuestAndPreservesState(t *testing.T) {
	data := make([]byte, 2048)
	code := []byte{0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0, 0x7c, 0xe4, 0x21, 0xa2, 0x1e, 0x50}
	var failFix []int
	for _, pair := range [][2]uint16{{0xc205, 0x0300}, {0xc207, 0x7d00}, {0xc200, 0x0100}} {
		code = append(code, 0xb8, byte(pair[0]), byte(pair[0]>>8), 0xbb, byte(pair[1]), byte(pair[1]>>8), 0xcd, 0x15, 0x72, 0)
		failFix = append(failFix, len(code)-1)
	}
	// Win3 restores the saved master mask after calling BIOS mouse services.
	code = append(code, 0xa0, 0x1e, 0x50, 0xe6, 0x21, 0xc7, 6, 0, 0x50, 0xcd, 0xab, 0x66, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x66, 0xb9, 0x21, 0x43, 0x65, 0x87, 0x68, 0x46, 0x02, 0x9d, 0xf4, 0xeb, 0xfd)
	fail := len(code)
	code = append(code, 0x0f, 0x0b)
	for _, i := range failFix {
		code[i] = byte(fail - i - 1)
	}
	copy(data, code)
	callback := []byte{0x55, 0x89, 0xe5, 0x1e, 0x31, 0xc0, 0x8e, 0xd8}
	for i := byte(0); i < 4; i++ {
		callback = append(callback, 0x8b, 0x46, 6+i*2, 0xa3, 0x10+i*2, 0x50)
	}
	callback = append(callback, 0xff, 6, 2, 0x50, 0x1f, 0x5d, 0x66, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x66, 0xb9, 0xce, 0xfa, 0xed, 0xfe, 0xcb)
	copy(data[0x100:], callback)
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	disk, e := block.NewFileDevice(&starfile.Bytes{Data: data}, block.FileDeviceOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var raw *cpu
	b := &shared.Backend{Name: "rfe.v1", CPUFactory: func(ctx context.Context) (hypervisor.X86, error) {
		c, e := newCPU(ctx)
		if e == nil {
			raw = c.(*cpu)
		}
		return c, e
	}}
	d, e := b.Start(ctx, vmm.Machine{Architecture: "i386", CPUs: 1, Memory: 16 << 20, Disks: []vmm.Disk{{Device: disk, ReadOnly: true, CHS: &vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}}}})
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close(context.Background())
	ext, e := d.(interface {
		Extension(context.Context, string) (starlark.Value, error)
	}).Extension(ctx, "rfe.v1")
	if e != nil {
		t.Fatal(e)
	}
	read, _ := ext.(starlark.HasAttrs).Attr("read_physical")
	memory := func() []byte {
		v, e := starlark.Call(&starlark.Thread{}, read, starlark.Tuple{starlark.MakeInt(0x5000), starlark.MakeInt(32)}, nil)
		if e != nil {
			t.Fatal(e)
		}
		return []byte(v.(starlark.Bytes))
	}
	wait := func(offset int, want uint16) {
		for ctx.Err() == nil {
			m := memory()
			if binary.LittleEndian.Uint16(m[offset:]) == want {
				return
			}
			status, _ := d.Status(ctx)
			if !status.Running {
				r, _ := d.Wait(ctx)
				t.Fatalf("stopped before mouse callback: %+v", r)
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("mouse firmware timed out")
	}
	wait(0, 0xabcd)
	if e = d.(interface {
		Input(context.Context, vmm.Input) error
	}).Input(ctx, vmm.Input{Kind: "pointer", X: -7, Y: 9}); e != nil {
		t.Fatal(e)
	}
	wait(2, 1)
	if e = d.(interface{ Pause(context.Context) error }).Pause(ctx); e != nil {
		t.Fatal(e)
	}
	m := memory()
	for i, want := range []uint16{0, 0xf7, 0xf9, 0x38} {
		if got := binary.LittleEndian.Uint16(m[16+i*2:]); got != want {
			t.Fatalf("callback word%d=%x want%x", i, got, want)
		}
	}
	r, e := raw.Registers()
	if e != nil {
		t.Fatal(e)
	}
	if r.Rax != 0x12345678 || r.Rcx != 0x87654321 || r.Rsp != 0x7c00 || r.Rflags&0xffff != 0x246 {
		t.Fatalf("callback damaged interrupted state %+v", r)
	}
	if raw.pics[0].isr != 0 || raw.pics[1].isr != 0 {
		t.Fatal("IRQ12 left PIC in service")
	}
}
