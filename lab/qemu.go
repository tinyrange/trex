package lab

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"io"

	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

// qemuDisplay adapts the native VM's bounded, in-memory capture and input
// methods. The lab always presents the same portable display to the editor.
type qemuDisplay struct {
	machine  starlark.HasAttrs
	absolute bool
}

func (d qemuDisplay) call(name string, args ...starlark.Value) (starlark.Value, error) {
	method, err := d.machine.Attr(name)
	if err != nil {
		return nil, err
	}
	return starlark.Call(&starlark.Thread{Name: "lab display"}, method, args, nil)
}

func (d qemuDisplay) Capture(ctx context.Context) (*image.RGBA, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := d.call("screenshot", starlark.String("png"), starlark.MakeInt(2))
	if err != nil {
		return nil, err
	}
	file, ok := result.(storage.Reader)
	if !ok {
		return nil, errors.New("QEMU did not return PNG bytes")
	}
	frame, err := png.Decode(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, err
	}
	if rgba, ok := frame.(*image.RGBA); ok {
		return rgba, nil
	}
	rgba := image.NewRGBA(frame.Bounds())
	draw.Draw(rgba, rgba.Bounds(), frame, frame.Bounds().Min, draw.Src)
	return rgba, nil
}

func (d qemuDisplay) AbsolutePointer(context.Context) (bool, error) { return d.absolute, nil }

func (d qemuDisplay) Input(ctx context.Context, event vmm.Input) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	list := func(values []string) *starlark.List {
		items := make([]starlark.Value, len(values))
		for i, value := range values {
			items[i] = starlark.String(value)
		}
		return starlark.NewList(items)
	}
	var err error
	switch event.Kind {
	case "key":
		_, err = d.call("key", starlark.String(event.Key), starlark.Bool(event.Down))
	case "keys":
		_, err = d.call("send_keys", list(event.Keys))
	case "text":
		_, err = d.call("send_text", starlark.String(event.Text))
	case "pointer":
		_, err = d.call("pointer", starlark.Float(event.X), starlark.Float(event.Y),
			starlark.Bool(event.Absolute), list(event.Buttons), starlark.MakeInt(event.Wheel))
	default:
		return fmt.Errorf("unsupported display input %q", event.Kind)
	}
	return err
}
