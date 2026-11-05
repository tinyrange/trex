package star

import (
	"context"
	"errors"
	"testing"

	"go.starlark.net/starlark"
)

type resizeTestDriver struct {
	minimalVMMDriver
	ready         bool
	width, height int
	err           error
}

func (d *resizeTestDriver) ResizeReady(context.Context) (bool, error) { return d.ready, nil }
func (d *resizeTestDriver) Resize(ctx context.Context, width, height int) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing resize deadline")
	}
	d.width, d.height = width, height
	return d.err
}

func TestResizeStarlarkReadinessAndGuestFailure(t *testing.T) {
	d := &resizeTestDriver{}
	vm := newVMMSession(VMMMachine{}, &fakeVMMBackend{}, d)
	defer vm.Close()
	ready, err := vm.Attr("resize_ready")
	if err != nil || ready != starlark.False {
		t.Fatal(ready, err)
	}
	d.ready = true
	ready, err = vm.Attr("resize_ready")
	if err != nil || ready != starlark.True {
		t.Fatal(ready, err)
	}
	method, _ := vm.Attr("resize")
	args := starlark.Tuple{starlark.MakeInt(800), starlark.MakeInt(600)}
	if _, err := starlark.Call(&starlark.Thread{}, method, args, nil); err != nil || d.width != 800 || d.height != 600 {
		t.Fatal(d.width, d.height, err)
	}
	d.err = errors.New("guest mode switch failed")
	if _, err := starlark.Call(&starlark.Thread{}, method, args, nil); err == nil {
		t.Fatal("guest rejection silently accepted")
	}
	plain := newVMMSession(VMMMachine{}, &fakeVMMBackend{}, &minimalVMMDriver{})
	defer plain.Close()
	ready, err = plain.Attr("resize_ready")
	if err != nil || ready != starlark.False {
		t.Fatal(ready, err)
	}
	method, _ = plain.Attr("resize")
	if _, err := starlark.Call(&starlark.Thread{}, method, args, nil); err == nil {
		t.Fatal("unsupported resize silently accepted")
	}
}
