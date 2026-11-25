package cc

import (
	"fmt"

	"go.starlark.net/starlark"
)

type ramRewind struct {
	restore   func([]uint64) (int, error)
	hostPages map[uint64]bool
	invalid   bool
}

func (i inspection) prepareRewind(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.prepare_rewind", args, kwargs); err != nil {
		return nil, err
	}
	d := i.driver
	err := d.call(i.ctx, func() error {
		state, _ := d.Status(i.ctx)
		if state.Name != "paused" || d.entered || d.pc.rewind != nil {
			return fmt.Errorf("prepare_rewind requires a fresh paused VM")
		}
		cpu, ok := d.pc.cpu.(interface {
			PrepareRewind([]byte, []byte) (func([]uint64) (int, error), error)
		})
		if !ok || len(d.pc.preparedTemplate) == 0 || d.pc.channelName != "" {
			return fmt.Errorf("prepare_rewind requires private RAM, shared direct workers and no channels")
		}
		restore, err := cpu.PrepareRewind(d.pc.ram[:len(d.pc.preparedTemplate)], d.pc.preparedTemplate)
		if err != nil {
			return err
		}
		d.pc.rewind = &ramRewind{restore: restore, hostPages: make(map[uint64]bool)}
		return nil
	})
	return starlark.None, err
}

func (i inspection) rewind(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.rewind", args, kwargs); err != nil {
		return nil, err
	}
	d := i.driver
	var count int
	err := d.call(i.ctx, func() error {
		var err error
		count, err = d.rewindPaused()
		return err
	})
	return starlark.MakeInt(count), err
}

func (d *driver) rewindPaused() (int, error) {
	state, _ := d.Status(d.ctx)
	checkpoint := d.pc.rewind
	if state.Name != "paused" || checkpoint == nil || checkpoint.invalid {
		return 0, fmt.Errorf("rewind requires a paused checkpoint without device activity")
	}
	pages := make([]uint64, 0, len(checkpoint.hostPages))
	for page := range checkpoint.hostPages {
		pages = append(pages, page)
	}
	count, err := checkpoint.restore(pages)
	if err != nil {
		checkpoint.invalid = true
		return 0, err
	}
	clear(checkpoint.hostPages)
	d.breakpointHit = false
	return count, nil
}

func (p *pc) invalidateRewind() {
	if p.rewind != nil {
		p.rewind.invalid = true
	}
}
