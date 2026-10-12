//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"strings"
	"testing"
	"time"
)

func debugFixture(t *testing.T, code []byte) (*driver, inspection) {
	t.Helper()
	requireKVM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ram, err := cpu.MapRAM(0, 16<<20)
	if err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	data := make([]byte, 512)
	copy(data, code)
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data)}, time.Now)
	if err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	d := newDriver(ctx, p, true)
	t.Cleanup(func() { d.Close(context.Background()) })
	return d, inspection{driver: d, ctx: ctx}
}
func TestExecutionBreakpointSkipsOnlySelectedOccurrences(t *testing.T) {
	d, i := debugFixture(t, []byte{0xff, 0x06, 0, 0x80, 0xeb, 0xfa})
	if _, err := i.breakpoint(nil, nil, starlark.Tuple{starlark.MakeInt(0x7c00)}, []starlark.Tuple{{starlark.String("skip"), starlark.MakeInt(2)}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint16{2, 3} {
		if err := d.Resume(i.ctx); err != nil {
			t.Fatal(err)
		}
		for {
			state, _ := d.Status(i.ctx)
			if state.Name == "paused" {
				break
			}
			select {
			case <-i.ctx.Done():
				t.Fatal(i.ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
		var rip uint64
		var counter uint16
		if err := d.call(i.ctx, func() error {
			r, err := d.pc.cpu.Registers()
			if err != nil {
				return err
			}
			rip = r.Rip
			counter = binary.LittleEndian.Uint16(d.pc.ram[0x8000:])
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if rip != 0x7c00 || counter != want {
			t.Fatalf("wrong occurrence: rip=%x counter=%d want=%d", rip, counter, want)
		}
	}
}
func TestNativeStepRetainsTraceAndStopsOnGuestFailure(t *testing.T) {
	d, i := debugFixture(t, []byte{0xb8, 0x34, 0x12, 0x0f, 0x0b})
	v, err := i.step(nil, nil, starlark.Tuple{starlark.MakeInt(256)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := v.(*starlark.Dict)
	reason, _, _ := result.Get(starlark.String("reason"))
	detail, _, _ := result.Get(starlark.String("detail"))
	rows, _, _ := result.Get(starlark.String("steps"))
	if reason != starlark.String("guest_failure") || !strings.Contains(string(detail.(starlark.String)), "INT 06") || rows.(*starlark.List).Len() < 2 {
		t.Fatalf("lost fault evidence: %s", v)
	}
	state, _ := d.Status(i.ctx)
	if state.Name != "stopped" {
		t.Fatal("guest fault was masked", state)
	}
}
