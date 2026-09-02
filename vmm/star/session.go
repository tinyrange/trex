package star

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type VMMState = vmmapi.State
type VMMResult = vmmapi.Result
type VMMEvent = vmmapi.Event
type VMMInput = vmmapi.Input
type VMMDriver = vmmapi.Driver

type vmmControlDriver interface {
	Resume(context.Context) error
	Pause(context.Context) error
	Reset(context.Context) error
	Powerdown(context.Context) error
	Stop(context.Context) error
}

type vmmChannelDriver interface {
	Channel(context.Context, string) (channelpkg.ByteChannel, error)
}

type vmmDebuggerDriver interface {
	Debugger(context.Context, string, bool, bool) (channelpkg.ByteChannel, error)
}

type vmmInputDriver interface {
	Input(context.Context, VMMInput) error
}

type vmmScreenshotDriver interface {
	Screenshot(context.Context, string) (starfile.File, error)
}

type vmmExtensionDriver interface {
	Extension(context.Context, string) (starlark.Value, error)
}

type vmmDetachDriver interface {
	Detach(context.Context) error
}

type vmmReadyDriver interface {
	DebugReady() <-chan struct{}
}

type vmmSessionValue struct {
	machine VMMMachine
	backend VMMBackend
	driver  VMMDriver

	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closeErr   error
	mu         sync.Mutex
	detached   bool
	unregister func()
	result     *VMMResult
}

func (v *vmmSessionValue) VMMExtension(name string) (starlark.Value, error) {
	driver, ok := v.driver.(vmmExtensionDriver)
	if !ok {
		return nil, unsupportedVMM(name + " extension")
	}
	return driver.Extension(v.ctx, name)
}

func newVMMSession(machine VMMMachine, backend VMMBackend, driver VMMDriver) *vmmSessionValue {
	ctx, cancel := context.WithCancel(context.Background())
	return &vmmSessionValue{machine: machine, backend: backend, driver: driver, ctx: ctx, cancel: cancel}
}

func (v *vmmSessionValue) String() string {
	return fmt.Sprintf("<vm backend=%q>", v.driver.BackendID())
}
func (v *vmmSessionValue) DebugReady() <-chan struct{} {
	if driver, ok := v.driver.(vmmReadyDriver); ok {
		return driver.DebugReady()
	}
	return nil
}
func (v *vmmSessionValue) Type() string          { return "vm" }
func (v *vmmSessionValue) Freeze()               {}
func (v *vmmSessionValue) Truth() starlark.Bool  { return starlark.True }
func (v *vmmSessionValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }

func (v *vmmSessionValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "backend_id":
		return starlark.String(v.driver.BackendID()), nil
	case "capabilities":
		return stringListValue(normalizedCapabilities(v.driver.Capabilities())), nil
	case "has_capability":
		return starlark.NewBuiltin("has_capability", v.hasCapabilityBuiltin), nil
	case "result":
		v.mu.Lock()
		result := v.result
		v.mu.Unlock()
		if result == nil {
			return starlark.None, nil
		}
		return vmmResultValue(*result), nil
	case "status":
		state, err := v.driver.Status(v.ctx)
		if err != nil {
			return nil, normalizeVMMError(VMMErrorBackend, "query VM status", err)
		}
		return starlark.String(state.Name), nil
	case "running":
		state, err := v.driver.Status(v.ctx)
		if err != nil {
			return nil, normalizeVMMError(VMMErrorBackend, "query VM status", err)
		}
		return starlark.Bool(state.Running), nil
	case "resume", "pause", "reset", "powerdown", "stop":
		return starlark.NewBuiltin(name, v.controlBuiltin(name)), nil
	case "close":
		return starlark.NewBuiltin("close", v.closeBuiltin), nil
	case "wait":
		return starlark.NewBuiltin("wait", v.waitBuiltin), nil
	case "shutdown":
		return starlark.NewBuiltin("shutdown", v.shutdownBuiltin), nil
	case "next_event":
		return starlark.NewBuiltin("next_event", v.nextEventBuiltin), nil
	case "channel":
		return starlark.NewBuiltin("channel", v.channelBuiltin), nil
	case "debugger":
		return starlark.NewBuiltin("debugger", v.debuggerBuiltin), nil
	case "key":
		return starlark.NewBuiltin("key", v.keyBuiltin), nil
	case "send_keys":
		return starlark.NewBuiltin("send_keys", v.sendKeysBuiltin), nil
	case "send_text":
		return starlark.NewBuiltin("send_text", v.sendTextBuiltin), nil
	case "tap":
		return starlark.NewBuiltin("tap", v.tapBuiltin), nil
	case "chord":
		return starlark.NewBuiltin("chord", v.chordBuiltin), nil
	case "type_and_enter":
		return starlark.NewBuiltin("type_and_enter", v.typeAndEnterBuiltin), nil
	case "pointer":
		return starlark.NewBuiltin("pointer", v.pointerBuiltin), nil
	case "screenshot":
		return starlark.NewBuiltin("screenshot", v.screenshotBuiltin), nil
	case "extension":
		return starlark.NewBuiltin("extension", v.extensionBuiltin), nil
	case "detach":
		return starlark.NewBuiltin("detach", v.detachBuiltin), nil
	}
	return nil, nil
}

func (v *vmmSessionValue) AttrNames() []string {
	return []string{
		"backend_id", "capabilities", "channel", "chord", "close", "debugger", "detach", "extension",
		"has_capability", "key", "next_event", "pause", "pointer", "powerdown", "reset", "result", "resume",
		"running", "screenshot", "send_keys", "send_text", "shutdown", "status", "stop", "tap", "type_and_enter", "wait",
	}
}

func (v *vmmSessionValue) Close() error {
	v.closeOnce.Do(func() {
		v.mu.Lock()
		detached := v.detached
		unregister := v.unregister
		v.unregister = nil
		v.mu.Unlock()
		if detached {
			return
		}
		if unregister != nil {
			unregister()
		}
		v.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		v.closeErr = v.driver.Close(ctx)
	})
	return v.closeErr
}

func (v *vmmSessionValue) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
		return nil, err
	}
	if err := v.Close(); err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "close VM", err)
	}
	return starlark.None, nil
}

func (v *vmmSessionValue) controlBuiltin(operation string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		timeout := starvalue.Number(30)
		if err := starlark.UnpackArgs(operation, args, kwargs, "timeout?", &timeout); err != nil {
			return nil, err
		}
		driver, ok := v.driver.(vmmControlDriver)
		if !ok {
			return nil, unsupportedVMM(operation)
		}
		ctx, cancel, err := v.operationContext(float64(timeout))
		if err != nil {
			return nil, err
		}
		defer cancel()
		var operationErr error
		switch operation {
		case "resume":
			operationErr = driver.Resume(ctx)
		case "pause":
			operationErr = driver.Pause(ctx)
		case "reset":
			operationErr = driver.Reset(ctx)
		case "powerdown":
			operationErr = driver.Powerdown(ctx)
		case "stop":
			operationErr = driver.Stop(ctx)
		}
		if operationErr != nil {
			return nil, normalizeVMMError(VMMErrorBackend, operation+" VM", operationErr)
		}
		return starlark.None, nil
	}
}

func (v *vmmSessionValue) waitBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(-1)
	if err := starlark.UnpackArgs("wait", args, kwargs, "timeout?", &timeout); err != nil {
		return nil, err
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	result, err := v.waitResult(ctx)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "wait for VM", err)
	}
	return vmmResultValue(result), nil
}

func (v *vmmSessionValue) waitResult(ctx context.Context) (VMMResult, error) {
	v.mu.Lock()
	if v.result != nil {
		result := *v.result
		v.mu.Unlock()
		return result, nil
	}
	v.mu.Unlock()
	result, err := v.driver.Wait(ctx)
	if err != nil {
		return VMMResult{}, err
	}
	v.mu.Lock()
	if v.result == nil {
		copy := result
		v.result = &copy
	} else {
		result = *v.result
	}
	v.mu.Unlock()
	return result, nil
}

func (v *vmmSessionValue) shutdownBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(30)
	force := true
	forceTimeout := starvalue.Number(10)
	if err := starlark.UnpackArgs("shutdown", args, kwargs,
		"timeout?", &timeout, "force?", &force, "force_timeout?", &forceTimeout,
	); err != nil {
		return nil, err
	}
	control, ok := v.driver.(vmmControlDriver)
	if !ok {
		return nil, unsupportedVMM("shutdown")
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	state, statusErr := v.driver.Status(ctx)
	if statusErr != nil {
		// A backend control channel may close just before its process result is
		// published. Prefer the portable terminal result in that case.
		result, waitErr := v.waitResult(ctx)
		if waitErr == nil {
			cancel()
			return vmmResultValue(result), nil
		}
		statusErr = waitErr
	} else if state.Name != "stopped" {
		statusErr = control.Powerdown(ctx)
	}
	var result VMMResult
	if statusErr == nil {
		result, statusErr = v.waitResult(ctx)
	}
	cancel()
	if statusErr == nil {
		return vmmResultValue(result), nil
	}
	if !force || errors.Is(v.ctx.Err(), context.Canceled) {
		return nil, normalizeVMMError(VMMErrorBackend, "shut down VM", statusErr)
	}
	forceCtx, forceCancel, err := v.operationContext(float64(forceTimeout))
	if err != nil {
		return nil, err
	}
	defer forceCancel()
	if err := control.Stop(forceCtx); err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "force stop VM", err)
	}
	result, err = v.waitResult(forceCtx)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "wait for forced VM stop", err)
	}
	return vmmResultValue(result), nil
}

func (v *vmmSessionValue) hasCapabilityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("has_capability", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	for _, capability := range v.driver.Capabilities() {
		if capability == name {
			return starlark.True, nil
		}
	}
	return starlark.False, nil
}

func (v *vmmSessionValue) nextEventBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(-1)
	if err := starlark.UnpackArgs("next_event", args, kwargs, "timeout?", &timeout); err != nil {
		return nil, err
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	event, err := v.driver.NextEvent(ctx)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "wait for VM event", err)
	}
	return vmmEventValue(event), nil
}

func (v *vmmSessionValue) channelBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("channel", args, kwargs, "name", &name, "timeout?", &timeout); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmChannelDriver)
	if !ok {
		return nil, unsupportedVMM("channel")
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	channel, err := driver.Channel(ctx, name)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "open VM channel", err)
	}
	return channelstar.New(name, channel), nil
}

func (v *vmmSessionValue) debuggerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var protocol string
	create, paused := false, false
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("debugger", args, kwargs,
		"protocol", &protocol, "create?", &create, "paused?", &paused, "timeout?", &timeout,
	); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmDebuggerDriver)
	if !ok {
		return nil, unsupportedVMM("debugger")
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	channel, err := driver.Debugger(ctx, protocol, create, paused)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "open VM debugger", err)
	}
	return channelstar.New("debugger:"+protocol, channel), nil
}

func (v *vmmSessionValue) keyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	down := true
	if err := starlark.UnpackArgs("key", args, kwargs, "key", &key, "down?", &down); err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "key", Key: key, Down: down})
}

func (v *vmmSessionValue) sendKeysBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	if err := starlark.UnpackArgs("send_keys", args, kwargs, "keys", &values); err != nil {
		return nil, err
	}
	keys, err := starlarkStringList(values, "keys")
	if err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "keys", Keys: keys})
}

func (v *vmmSessionValue) sendTextBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("send_text", args, kwargs, "text", &value); err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "text", Text: value})
}

func (v *vmmSessionValue) tapBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs("tap", args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	// A tap is one timed backend operation. Splitting it into adjacent key-down
	// and key-up calls produces a zero-duration press that older guests can miss.
	return v.sendInput(VMMInput{Kind: "keys", Keys: []string{key}})
}

func (v *vmmSessionValue) chordBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	if err := starlark.UnpackArgs("chord", args, kwargs, "keys", &values); err != nil {
		return nil, err
	}
	keys, err := starlarkStringList(values, "keys")
	if err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "keys", Keys: keys})
}

func (v *vmmSessionValue) typeAndEnterBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	enter := "enter"
	if err := starlark.UnpackArgs("type_and_enter", args, kwargs, "text", &text, "enter?", &enter); err != nil {
		return nil, err
	}
	if _, err := v.sendInput(VMMInput{Kind: "text", Text: text}); err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "keys", Keys: []string{enter}})
}

func (v *vmmSessionValue) pointerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	x, y := 0.0, 0.0
	absolute := false
	wheel := 0
	var buttonsValue *starlark.List
	if err := starlark.UnpackArgs("pointer", args, kwargs,
		"x?", &x, "y?", &y, "absolute?", &absolute, "buttons?", &buttonsValue, "wheel?", &wheel,
	); err != nil {
		return nil, err
	}
	buttons, err := starlarkStringList(buttonsValue, "buttons")
	if err != nil {
		return nil, err
	}
	return v.sendInput(VMMInput{Kind: "pointer", X: x, Y: y, Absolute: absolute, Buttons: buttons, Wheel: wheel})
}

func (v *vmmSessionValue) sendInput(input VMMInput) (starlark.Value, error) {
	driver, ok := v.driver.(vmmInputDriver)
	if !ok {
		return nil, unsupportedVMM("input")
	}
	ctx, cancel := context.WithTimeout(v.ctx, 30*time.Second)
	defer cancel()
	if err := driver.Input(ctx, input); err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "send VM input", err)
	}
	return starlark.None, nil
}

func (v *vmmSessionValue) screenshotBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	format := "png"
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("screenshot", args, kwargs, "format?", &format, "timeout?", &timeout); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmScreenshotDriver)
	if !ok {
		return nil, unsupportedVMM("screenshot")
	}
	ctx, cancel, err := v.operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	file, err := driver.Screenshot(ctx, format)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "capture VM screenshot", err)
	}
	return file, nil
}

func (v *vmmSessionValue) extensionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("extension", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmExtensionDriver)
	if !ok {
		return nil, unsupportedVMM("extension " + name)
	}
	value, err := driver.Extension(v.ctx, name)
	if err != nil {
		return nil, normalizeVMMError(VMMErrorBackend, "open VM extension", err)
	}
	return value, nil
}

func (v *vmmSessionValue) detachBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("detach", args, kwargs); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmDetachDriver)
	if !ok {
		return nil, unsupportedVMM("detach")
	}
	v.mu.Lock()
	if v.detached {
		v.mu.Unlock()
		return starlark.None, nil
	}
	if err := driver.Detach(v.ctx); err != nil {
		v.mu.Unlock()
		return nil, normalizeVMMError(VMMErrorBackend, "detach VM", err)
	}
	v.detached = true
	unregister := v.unregister
	v.unregister = nil
	v.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	return starlark.None, nil
}

func (v *vmmSessionValue) operationContext(timeout float64) (context.Context, context.CancelFunc, error) {
	if timeout < 0 {
		ctx, cancel := context.WithCancel(v.ctx)
		return ctx, cancel, nil
	}
	if timeout > float64((24 * time.Hour).Seconds()) {
		return nil, nil, &VMMError{Code: VMMErrorInvalid, Message: "timeout exceeds 24 hours"}
	}
	ctx, cancel := context.WithTimeout(v.ctx, time.Duration(timeout*float64(time.Second)))
	return ctx, cancel, nil
}

func unsupportedVMM(operation string) error {
	return &VMMError{Code: VMMErrorUnsupported, Message: operation + " is not supported by this backend"}
}

func vmmResultValue(result VMMResult) starlark.Value {
	return starvalue.NewRecord(starlark.StringDict{
		"backend":          starlark.String(result.Backend),
		"clean":            starlark.Bool(result.Clean),
		"code":             starlark.MakeInt(result.Code),
		"detail":           starlark.String(result.Detail),
		"finished_unix_ns": starlark.MakeInt64(result.Finished.UnixNano()),
		"reason":           starlark.String(result.Reason),
	})
}

func vmmEventValue(event VMMEvent) starlark.Value {
	payload := starlark.Value(starlark.None)
	if event.Payload != nil {
		if value, ok := event.Payload.(starlark.Value); ok {
			payload = value
		} else if value, err := starvalue.Starlark(event.Payload); err == nil {
			payload = value
		} else {
			payload = starlark.String(fmt.Sprint(event.Payload))
		}
	}
	return starvalue.NewRecord(starlark.StringDict{
		"backend":           starlark.String(event.Backend),
		"kind":              starlark.String(event.Kind),
		"payload":           payload,
		"timestamp_unix_ns": starlark.MakeInt64(event.Timestamp.UnixNano()),
	})
}
