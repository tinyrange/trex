package star

import (
	"context"
	"fmt"
	"sync"

	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type workspaceValue struct {
	mu       sync.RWMutex
	createMu sync.Mutex
	thread   *starlark.Thread
	factory  starlark.Callable
	vms      []vmm.DisplayVM
	// Keep sessions alive alongside their display adapters.
	sessions []starlark.Value
}

func (*workspaceValue) String() string                { return "<vmm.workspace>" }
func (*workspaceValue) Type() string                  { return "vmm_workspace" }
func (*workspaceValue) Freeze()                       {}
func (*workspaceValue) Truth() starlark.Bool          { return true }
func (*workspaceValue) Hash() (uint32, error)         { return 0, fmt.Errorf("unhashable workspace") }
func (w *workspaceValue) VMMWorkspace() vmm.Workspace { return w }
func (w *workspaceValue) CanCreate() bool             { return w.factory != nil }
func (w *workspaceValue) VMs() []vmm.DisplayVM {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]vmm.DisplayVM(nil), w.vms...)
}
func (w *workspaceValue) add(name string, value starlark.Value) (vmm.DisplayVM, error) {
	session, ok := value.(interface {
		VMMDisplay() (vmm.DisplaySource, error)
	})
	if !ok || name == "" {
		return vmm.DisplayVM{}, fmt.Errorf("workspace requires a name and display-capable VM")
	}
	display, err := session.VMMDisplay()
	if err != nil {
		return vmm.DisplayVM{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, vm := range w.vms {
		if vm.Name == name {
			return vmm.DisplayVM{}, fmt.Errorf("duplicate VM name %q", name)
		}
	}
	vm := vmm.DisplayVM{ID: fmt.Sprint(len(w.vms) + 1), Name: name, Display: display}
	w.vms = append(w.vms, vm)
	w.sessions = append(w.sessions, value)
	return vm, nil
}
func (w *workspaceValue) Create(ctx context.Context) (vmm.DisplayVM, error) {
	// A single Starlark runtime owns recipe state and allocates machine names.
	w.createMu.Lock()
	defer w.createMu.Unlock()
	if err := ctx.Err(); err != nil {
		return vmm.DisplayVM{}, err
	}
	if w.factory == nil {
		return vmm.DisplayVM{}, fmt.Errorf("VM creation unavailable")
	}
	value, err := starlark.Call(w.thread, w.factory, nil, nil)
	if err != nil {
		return vmm.DisplayVM{}, err
	}
	pair, ok := value.(starlark.Tuple)
	if !ok || len(pair) != 2 {
		return vmm.DisplayVM{}, fmt.Errorf("VM factory must return (name, vm)")
	}
	name, ok := starlark.AsString(pair[0])
	if !ok {
		return vmm.DisplayVM{}, fmt.Errorf("VM name must be a string")
	}
	vm, err := w.add(name, pair[1])
	if err != nil {
		// Rejecting a duplicate name must not strand a newly started VM, or
		// close an existing VM if a factory accidentally returns it again.
		if session, ok := pair[1].(*vmmSessionValue); ok {
			w.mu.RLock()
			known := false
			for _, value := range w.sessions {
				if value == session {
					known = true
					break
				}
			}
			w.mu.RUnlock()
			if !known {
				_ = session.Close()
			}
		}
	}
	return vm, err
}
func workspaceBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var initial *starlark.Dict
	var create starlark.Value = starlark.None
	if err := starlark.UnpackArgs("workspace", args, kwargs, "vms", &initial, "create?", &create); err != nil {
		return nil, err
	}
	var factory starlark.Callable
	if create != starlark.None {
		var ok bool
		factory, ok = create.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("workspace create must be callable or None")
		}
	}
	w := &workspaceValue{thread: thread, factory: factory}
	for _, pair := range initial.Items() {
		name, ok := starlark.AsString(pair[0])
		if !ok {
			return nil, fmt.Errorf("VM name must be a string")
		}
		if _, err := w.add(name, pair[1]); err != nil {
			return nil, err
		}
	}
	if len(w.vms) == 0 {
		return nil, fmt.Errorf("workspace needs at least one VM")
	}
	return w, nil
}
