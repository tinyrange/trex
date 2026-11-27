package r3000

import (
	"context"
	"image"
	"slices"
	"testing"

	"github.com/tinyrange/trex/vmm"
)

func TestIP24DisplayInput(t *testing.T) {
	m, err := newIP24(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.keyboard.mouseEnabled = true
	ctx := context.Background()
	d := &ip24Display{owner: &ip24Value{m: m, ctx: ctx}, ctx: ctx}
	for _, input := range []vmm.Input{
		{Kind: "pointer", X: 130, Y: -7, Buttons: []string{"right", "middle"}},
		{Kind: "pointer"},
		{Kind: "key", Key: "minus", Down: true},
		{Kind: "key", Key: "up"},
	} {
		if err := d.Input(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	var bytes []byte
	for _, b := range m.keyboard.queue[:m.keyboard.length] {
		bytes = append(bytes, b.value)
	}
	want := []byte{14, 127, 7, 14, 3, 0, 8, 0, 0, 0x4e, 0xe0, 0xf0, 0x75}
	if !slices.Equal(bytes, want) {
		t.Fatalf("PS/2 packets = % x, want % x", bytes, want)
	}
}

func TestIP24WorkspaceDisplay(t *testing.T) {
	m, err := newIP24(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v := &ip24Value{m: m, ctx: ctx}
	t.Cleanup(func() { _ = v.Close() })
	d, err := v.VMMDisplay()
	if err != nil {
		t.Fatal(err)
	}
	again, err := v.VMMDisplay()
	if again != d || err != nil {
		t.Fatalf("second display registration = %v, %v", again, err)
	}
	dst := image.NewRGBA(image.Rect(0, 0, newportWidth, newportHeight))
	if got, err := d.(vmm.ReusableDisplaySource).CaptureInto(ctx, dst); err != nil || got != dst || got.Pix[3] != 255 {
		t.Fatalf("capture reused framebuffer = %t, error %v", got == dst, err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Capture(ctx); err == nil {
		t.Fatal("capture accepted after closing the workspace machine")
	}
}
