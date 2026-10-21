package rfe

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"testing"
	"time"
)

func TestBootThroughSharedBIOSDiskAndTimer(t *testing.T) {
	data := make([]byte, 2048)
	// Read sector two with INT 13, then install a timer hook and wait for it.
	code := []byte{0xb8, 1, 2, 0xbb, 0, 0x80, 0xb9, 2, 0, 0xba, 0x80, 0, 0xcd, 0x13, 0x72, 34, 0x81, 0x3e, 0, 0x80, 0x34, 0x12, 0x75, 26,
		0xc7, 6, 0x70, 0, 0, 0x7d, 0xc7, 6, 0x72, 0, 0, 0, 0x83, 0x3e, 0, 0x81, 0, 0x74, 0xf9,
		0xb8, 'R', 0x0e, 0xcd, 0x10, 0xeb, 0xfe, 0x0f, 0x0b}
	// Successful branch prints R through the shared VGA BIOS and loops.
	copy(data, code)
	copy(data[0x100:], []byte{0x2e, 0xc7, 6, 0, 0x81, 1, 0, 0xcf})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	binary.LittleEndian.PutUint16(data[512:], 0x1234)
	disk, err := block.NewFileDevice(&starfile.Bytes{Data: data}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := vmm.Machine{Architecture: "i386", CPUs: 1, Memory: 16 << 20, Disks: []vmm.Disk{{Device: disk, CHS: &vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}, ReadOnly: true}}, StartPaused: true}
	b := &Backend{}
	if issues := b.Validate(m); len(issues) != 0 {
		t.Fatal(issues)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := b.Start(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())
	if d.BackendID() != "rfe.v1" {
		t.Fatal(d.BackendID())
	}
	ext, err := d.(interface {
		Extension(context.Context, string) (starlark.Value, error)
	}).Extension(ctx, "rfe.v1")
	if err != nil {
		t.Fatal(err)
	}
	stateFn, _ := ext.(starlark.HasAttrs).Attr("state")
	if err := d.(interface{ Resume(context.Context) error }).Resume(ctx); err != nil {
		t.Fatal(err)
	}
	var last starlark.Value
	for ctx.Err() == nil {
		state, err := starlark.Call(&starlark.Thread{}, stateFn, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		last = state
		dict := state.(*starlark.Dict)
		v, _, _ := dict.Get(starlark.String("last_bios"))
		if v != nil && v.String() == "\"INT 10 AX=0e52\"" {
			return
		}
		status, _ := d.Status(ctx)
		if !status.Running {
			result, _ := d.Wait(ctx)
			t.Fatalf("stopped: %+v state=%s", result, state)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timer/BIOS disk smoke timed out: %s", last)
}
