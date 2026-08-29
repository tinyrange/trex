package qemu

import (
	"context"
	"fmt"
	"strings"
	"time"

	nbdapi "github.com/tinyrange/trex/block/nbd"
	channelpkg "github.com/tinyrange/trex/channel"
	starvalue "github.com/tinyrange/trex/script/value"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (d *qemuDriver) BackendID() string           { return "qemu.v1" }
func (d *qemuDriver) Capabilities() []string      { return d.backend.Capabilities() }
func (d *qemuDriver) DebugReady() <-chan struct{} { return d.ready }

func (d *qemuDriver) Status(ctx context.Context) (vmmapi.State, error) {
	select {
	case <-d.done:
		return vmmapi.State{Name: "stopped"}, nil
	default:
	}
	value, err := d.qmp.Call(ctx, "query-status", nil)
	if err != nil {
		return vmmapi.State{}, err
	}
	status, ok := value.(map[string]any)
	if !ok {
		return vmmapi.State{}, fmt.Errorf("QMP query-status returned %T", value)
	}
	name, _ := status["status"].(string)
	running, _ := status["running"].(bool)
	return vmmapi.State{Name: name, Running: running}, nil
}

func (d *qemuDriver) Wait(ctx context.Context) (vmmapi.Result, error) {
	select {
	case <-d.done:
		d.mu.Lock()
		result := d.exit
		d.mu.Unlock()
		return result, nil
	case <-ctx.Done():
		return vmmapi.Result{}, ctx.Err()
	}
}

func (d *qemuDriver) NextEvent(ctx context.Context) (vmmapi.Event, error) {
	select {
	case event := <-d.events:
		return d.consumeEvent(event), nil
	default:
	}
	select {
	case event := <-d.events:
		return d.consumeEvent(event), nil
	case <-ctx.Done():
		return vmmapi.Event{}, ctx.Err()
	}
}

func (d *qemuDriver) consumeEvent(event vmmapi.Event) vmmapi.Event {
	select {
	case <-d.ready:
	default:
	}
	if len(d.events) != 0 {
		select {
		case d.ready <- struct{}{}:
		default:
		}
	}
	return event
}

func (d *qemuDriver) Resume(ctx context.Context) error {
	_, err := d.qmp.Call(ctx, "cont", nil)
	return err
}
func (d *qemuDriver) Pause(ctx context.Context) error {
	_, err := d.qmp.Call(ctx, "stop", nil)
	return err
}
func (d *qemuDriver) Reset(ctx context.Context) error {
	_, err := d.qmp.Call(ctx, "system_reset", nil)
	return err
}
func (d *qemuDriver) Powerdown(ctx context.Context) error {
	_, err := d.qmp.Call(ctx, "system_powerdown", nil)
	return err
}
func (d *qemuDriver) Stop(ctx context.Context) error {
	_, err := d.qmp.Call(ctx, "quit", nil)
	if err == nil {
		// A force-stop must also interrupt owned NBD requests. Waiting until
		// cmd.Wait returns creates a cycle when QEMU is draining its block
		// backend as part of quit.
		d.cancel()
	}
	return err
}

func (d *qemuDriver) Channel(_ context.Context, name string) (channelpkg.ByteChannel, error) {
	channel := d.channels[name]
	if channel == nil {
		return nil, &vmmapi.Error{Code: vmmapi.ErrorInvalid, Message: "unknown VM channel " + name}
	}
	return channel, nil
}

func (d *qemuDriver) Debugger(ctx context.Context, protocol string, create, paused bool) (channelpkg.ByteChannel, error) {
	if protocol != "gdb" {
		return nil, unsupportedVMM("debugger " + protocol)
	}
	if paused {
		if err := d.Pause(ctx); err != nil {
			return nil, err
		}
	}
	if d.gdb == nil {
		return nil, &vmmapi.Error{Code: vmmapi.ErrorState, Message: "GDB channel is unavailable"}
	}
	_ = create
	return d.gdb, nil
}

func (d *qemuDriver) Extension(_ context.Context, name string) (starlark.Value, error) {
	if name != "qemu.v1" {
		return nil, unsupportedVMM("extension " + name)
	}
	return &qemuExtensionValue{driver: d}, nil
}

func (d *qemuDriver) Detach(context.Context) error {
	if len(d.exports) != 0 {
		return &vmmapi.Error{Code: vmmapi.ErrorUnsupported, Message: "cannot detach a VM whose NBD exports are owned by this runtime"}
	}
	d.mu.Lock()
	d.detached = true
	d.mu.Unlock()
	return nil
}

func (d *qemuDriver) Close(ctx context.Context) error {
	d.closeOnce.Do(func() {
		select {
		case <-d.done:
		default:
			if d.qmp != nil {
				quitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, _ = d.qmp.Call(quitCtx, "quit", nil)
				cancel()
			}
			select {
			case <-d.done:
			case <-ctx.Done():
				d.cancel()
				if d.cmd != nil && d.cmd.Process != nil {
					d.closeErr = d.cmd.Process.Kill()
				}
				<-d.done
			}
		}
		d.releaseTransports()
	})
	return d.closeErr
}

type qemuExtensionValue struct{ driver *qemuDriver }

func (v *qemuExtensionValue) String() string       { return "<qemu.v1>" }
func (v *qemuExtensionValue) Type() string         { return "qemu.v1" }
func (v *qemuExtensionValue) Freeze()              {}
func (v *qemuExtensionValue) Truth() starlark.Bool { return starlark.True }
func (v *qemuExtensionValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", v.Type())
}
func (v *qemuExtensionValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "qmp":
		return starlark.NewBuiltin("qmp", v.qmpBuiltin), nil
	case "hmp":
		return starlark.NewBuiltin("hmp", v.hmpBuiltin), nil
	case "qmp_schema":
		return starlark.NewBuiltin("qmp_schema", v.schemaBuiltin), nil
	case "block_stats":
		return starlark.NewBuiltin("block_stats", v.blockStatsBuiltin), nil
	case "capabilities":
		return starvalue.NewRecord(starlark.StringDict{
			"accelerator": starlark.String(v.driver.backend.accelerator),
			"display":     starlark.String(v.driver.backend.displayFrontend),
			"machine":     starlark.String(v.driver.backend.machine),
		}), nil
	case "process":
		pid := 0
		if v.driver.cmd != nil && v.driver.cmd.Process != nil {
			pid = v.driver.cmd.Process.Pid
		}
		return starvalue.NewRecord(starlark.StringDict{
			"pid":    starlark.MakeInt(pid),
			"stderr": starlark.String(v.driver.stderr.String()),
		}), nil
	}
	return nil, nil
}
func (v *qemuExtensionValue) AttrNames() []string {
	return []string{"block_stats", "capabilities", "hmp", "process", "qmp", "qmp_schema"}
}

func (v *qemuExtensionValue) blockStatsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("block_stats", args, kwargs); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(v.driver.exports))
	for index, export := range v.driver.exports {
		stats := nbdapi.StatsStarlark(export.server.Stats())
		stats["index"] = starlark.MakeInt(index)
		values[index] = starvalue.NewRecord(stats)
	}
	return starlark.NewList(values), nil
}

func (v *qemuExtensionValue) qmpBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	var arguments *starlark.Dict
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("qmp", args, kwargs, "command", &command, "arguments?", &arguments, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if command == "" || strings.IndexByte(command, 0) >= 0 {
		return nil, fmt.Errorf("qmp: invalid command")
	}
	converted := map[string]any(nil)
	if arguments != nil {
		value, err := starvalue.Native(arguments)
		if err != nil {
			return nil, err
		}
		converted = value.(map[string]any)
	}
	ctx, cancel, err := operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	result, err := v.driver.qmp.Call(ctx, command, converted)
	if err != nil {
		return nil, err
	}
	return jsonValueToStarlark(result)
}

func (v *qemuExtensionValue) hmpBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("hmp", args, kwargs, "command", &command, "timeout?", &timeout); err != nil {
		return nil, err
	}
	ctx, cancel, err := operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	result, err := v.driver.qmp.Call(ctx, "human-monitor-command", map[string]any{"command-line": command})
	if err != nil {
		return nil, err
	}
	text := fmt.Sprint(result)
	if len(text) > 8<<20 {
		return nil, fmt.Errorf("hmp: result exceeds 8 MiB")
	}
	return starlark.String(text), nil
}

func (v *qemuExtensionValue) schemaBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	timeout := starvalue.Number(30)
	if err := starlark.UnpackArgs("qmp_schema", args, kwargs, "timeout?", &timeout); err != nil {
		return nil, err
	}
	ctx, cancel, err := operationContext(float64(timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	result, err := v.driver.qmp.Call(ctx, "query-qmp-schema", nil)
	if err != nil {
		return nil, err
	}
	return jsonValueToStarlark(result)
}
