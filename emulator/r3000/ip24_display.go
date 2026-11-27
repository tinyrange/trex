package r3000

import (
	"context"
	"errors"
	"fmt"
	"image"
	"math"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm"
)

const ip24DisplaySlice = 250_000

// The workspace owns the machine through its ordinary Starlark lifecycle.
// The same lock serializes emulation, inspection, capture, and PS/2 input.
type ip24Display struct {
	owner   *ip24Value
	ctx     context.Context
	cancel  context.CancelFunc
	stop    error
	buttons byte
}

func (v *ip24Value) VMMDisplay() (vmm.DisplaySource, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m.closed || v.m.newport == nil {
		return nil, fmt.Errorf("ip24: no active Newport display")
	}
	if err := v.ctx.Err(); err != nil {
		return nil, err
	}
	if v.display == nil {
		ctx, cancel := context.WithCancel(v.ctx)
		v.display = &ip24Display{owner: v, ctx: ctx, cancel: cancel}
		go v.display.run()
	}
	return v.display, v.display.stop
}

func (d *ip24Display) run() {
	v := d.owner
	for d.ctx.Err() == nil {
		v.mu.Lock()
		err := d.advance(d.ctx)
		if err != nil {
			d.stop = err
		}
		v.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (d *ip24Display) advance(ctx context.Context) error {
	stop, err := d.owner.m.Run(ctx, ip24DisplaySlice, false)
	if err != nil {
		return err
	}
	if stop.Kind != "budget" {
		return fmt.Errorf("ip24: %s at %#x while running the desktop", stop.Kind, stop.PC)
	}
	return nil
}

func (d *ip24Display) Capture(ctx context.Context) (*image.RGBA, error) {
	return d.CaptureInto(ctx, nil)
}

func (d *ip24Display) CaptureInto(ctx context.Context, dst *image.RGBA) (*image.RGBA, error) {
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if err := d.ready(ctx); err != nil {
		return nil, err
	}
	return d.owner.m.newport.screenInto(dst), nil
}

var ip24DisplayKeys = map[string]string{
	"esc": "escape", "ret": "enter", "ctrl": "control", "space": " ", "minus": "-", "equal": "=",
	"bracket_left": "[", "bracket_right": "]", "semicolon": ";", "apostrophe": "'",
	"grave_accent": "`", "backslash": "\\", "comma": ",", "dot": ".", "slash": "/",
}

func (d *ip24Display) Input(ctx context.Context, input vmm.Input) error {
	v := d.owner
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := d.ready(ctx); err != nil {
		return err
	}
	switch input.Kind {
	case "key":
		key := input.Key
		if alias := ip24DisplayKeys[key]; alias != "" {
			key = alias
		}
		return d.deliver(ctx, func() error { return v.m.Key(key, input.Down) })
	case "pointer":
		if input.Absolute || math.IsNaN(input.X) || math.IsNaN(input.Y) {
			return fmt.Errorf("ip24: Newport requires relative mouse motion")
		}
		return d.pointer(ctx, input)
	default:
		return fmt.Errorf("ip24: unsupported display input %q", input.Kind)
	}
}

func (d *ip24Display) pointer(ctx context.Context, input vmm.Input) error {
	var buttons byte
	for _, button := range input.Buttons {
		switch button {
		case "left":
			buttons |= 1
		case "right":
			buttons |= 2
		case "middle":
			buttons |= 4
		}
	}
	// A larger motion would already put the pointer at a display edge.
	x := int(max(-newportWidth, min(newportWidth, input.X)))
	y := int(max(-newportHeight, min(newportHeight, -input.Y)))
	for x != 0 || y != 0 || buttons != d.buttons {
		dx, dy := max(-127, min(127, x)), max(-127, min(127, y))
		if err := d.deliver(ctx, func() error { return d.owner.m.Mouse(dx, dy, buttons) }); err != nil {
			return err
		}
		d.buttons = buttons
		x, y = x-dx, y-dy
	}
	return nil
}

func (d *ip24Display) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	return d.stop
}

func (d *ip24Display) deliver(ctx context.Context, enqueue func() error) error {
	// A busy PS/2 controller needs emulated time to shift queued bytes out.
	// Bound the extra execution if the guest has stopped consuming input.
	m := d.owner.m
	limit := m.keyboard.frameCycles * uint64(len(m.keyboard.queue)+1)
	for elapsed := uint64(0); ; elapsed += ip24DisplaySlice {
		err := enqueue()
		if !errors.Is(err, channel.ErrWouldBlock) || elapsed >= limit {
			return err
		}
		if err := d.advance(ctx); err != nil {
			return err
		}
	}
}
