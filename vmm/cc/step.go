package cc

import (
	"context"
	"errors"
	"fmt"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"time"
)

// step is a bounded native debugger operation. It does not interpret or patch
// guest instructions. Devices and firmware retain their normal execution path.
func (i inspection) step(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	count := 1
	var stopBelow uint64
	if err := starlark.UnpackArgs("cc.step", args, kwargs, "count?", &count, "stop_below?", &stopBelow); err != nil {
		return nil, err
	}
	if count < 1 || count > 4096 {
		return nil, fmt.Errorf("step count must be 1..4096")
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() (retErr error) {
		d := i.driver
		state, _ := d.Status(i.ctx)
		if state.Name != "paused" {
			return fmt.Errorf("native stepping requires a paused VM")
		}
		debug, ok := d.pc.cpu.(interface{ SetSingleStep(bool) error })
		if !ok {
			return fmt.Errorf("native single stepping unavailable")
		}
		if err := debug.SetSingleStep(true); err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, debug.SetSingleStep(false)) }()
		d.breakpointSkip = 0
		d.breakpointHit = false // stepping replaces the single execution breakpoint
		ctx, cancel := context.WithTimeout(i.ctx, 5*time.Second)
		defer cancel()
		var rows []any
		defer func() {
			if retErr != nil {
				reason := "guest_failure"
				if errors.Is(retErr, context.DeadlineExceeded) || errors.Is(retErr, context.Canceled) {
					reason = "timeout"
				} else {
					d.finish("guest_failure", retErr.Error(), false)
				}
				result, _ = starvalue.Starlark(map[string]any{"steps": rows, "reason": reason, "detail": retErr.Error()})
				retErr = nil
			}
		}()
		reason := "limit"
		capture := func() (uint64, error) {
			r, err := d.pc.cpu.Registers()
			if err != nil {
				return 0, err
			}
			s, err := d.pc.cpu.SystemRegisters()
			if err != nil {
				return 0, err
			}
			pc := s.Cs.Base + r.Rip
			rows = append(rows, map[string]any{"pc": int64(pc), "ip": int64(r.Rip), "cs": int(s.Cs.Selector), "ss": int(s.Ss.Selector), "sp": int64(r.Rsp), "ax": int64(r.Rax), "bx": int64(r.Rbx), "cx": int64(r.Rcx), "dx": int64(r.Rdx)})
			return pc, nil
		}
		pc, err := capture()
		if err != nil {
			return err
		}
		for completed := 0; completed < count; {
			if stopBelow != 0 && pc < stopBelow {
				reason = "address-bound"
				break
			}
			// Firmware register commits and guest flag-restoring instructions
			// can clear the native trap flag. Re-arm debugger-owned stepping
			// before every run rather than allowing an unobserved continuation.
			if err := debug.SetSingleStep(true); err != nil {
				return err
			}
			ex, err := d.pc.run(ctx)
			if err != nil {
				return err
			}
			switch ex.Reason {
			case 0:
				continue
			case hypervisor.X86ExitDebug:
				completed++
				pc, err = capture()
				if err != nil {
					return err
				}
			case hypervisor.X86ExitIO:
				if err = d.pc.handleIO(ex); err != nil {
					return err
				}
				firmware := ex.Port == biosPort || (d.pc.efi != nil && ex.Port == efiPort)
				if !firmware {
					if err = d.pc.cpu.CompleteIO(); err != nil {
						return err
					}
				}
				completed++
				pc, err = capture()
				if err != nil {
					return err
				}
			case hypervisor.X86ExitMMIO:
				if err = d.pc.handleMMIO(ex); err != nil {
					return err
				}
				if err = d.pc.cpu.CompleteIO(); err != nil {
					return err
				}
				completed++
				pc, err = capture()
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("native step exit %d", ex.Reason)
			}
		}
		result, err = starvalue.Starlark(map[string]any{"steps": rows, "reason": reason})
		return err
	})
	return result, err
}
