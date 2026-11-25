package cc

import (
	"context"
	"fmt"
	"time"

	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
)

// rewindRun groups restore, patch and execution into one synchronous command.
// The driver remains paused and the installed execution breakpoint owns the
// completion. It publishes no transient resume/pause events.
func (i inspection) rewindRun(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var data starlark.Bytes
	if err := starlark.UnpackArgs("cc.rewind_run", args, kwargs, "address", &address, "data", &data); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 65536 {
		return nil, fmt.Errorf("rewind_run data size must be 1..65536")
	}
	d := i.driver
	err := d.call(i.ctx, func() error {
		worker, ok := d.pc.cpu.(interface{ OnWorker(func() error) error })
		if !ok || d.pc.rewind == nil || !d.breakpointHit || d.breakpointSkip != 0 {
			return fmt.Errorf("rewind_run requires a prepared VM paused at an execution breakpoint")
		}
		if address > uint64(len(d.pc.preparedTemplate)) || uint64(len(data)) > uint64(len(d.pc.preparedTemplate))-address {
			return fmt.Errorf("rewind_run patch is outside prepared RAM")
		}
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		defer cancel()
		stop := context.AfterFunc(i.ctx, cancel)
		defer stop()

		select {
		case d.runSlots <- struct{}{}:
			defer func() { <-d.runSlots }()
		case <-ctx.Done():
			return ctx.Err()
		}
		return worker.OnWorker(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := d.rewindPaused(); err != nil {
				return err
			}
			if err := d.pc.patchPhysical(address, string(data)); err != nil {
				return err
			}
			// The checkpoint fast path ends before device activity.
			// Leave any I/O exit for rejection here instead of dispatching it.
			exit, err := d.pc.cpu.Run(ctx)
			for err == nil && exit.Reason == 0 {
				exit, err = d.pc.cpu.Run(ctx)
			}
			if err != nil {
				d.pc.invalidateRewind()
				return err
			}
			if exit.Reason != hypervisor.X86ExitDebug {
				d.pc.invalidateRewind()
				return fmt.Errorf("rewound VM exited with reason %d before its breakpoint", exit.Reason)
			}
			d.breakpointHit = true
			return nil
		})
	})
	return starlark.None, err
}
