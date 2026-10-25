package cc

import (
	"context"
	"fmt"
	"time"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
)

func (d *driver) ResizeReady(ctx context.Context) (bool, error) {
	var ready bool
	err := d.call(ctx, func() error {
		_, _, ready = ramfb.ResizeLimits(d.pc.displayMemory())
		return nil
	})
	return ready, err
}

// Resize asks the guest driver/helper to switch Windows' live desktop. Only
// mailbox accesses stop the vCPUs; Windows must continue running to apply and
// acknowledge the request. The fixed firmware GOP mode is never modified here.
func (d *driver) Resize(ctx context.Context, width, height int) error {
	if width <= 0 || height <= 0 || width > ramfb.MaxWidth || height > ramfb.MaxHeight {
		return &vmm.Error{Code: vmm.ErrorInvalid, Message: "invalid display dimensions"}
	}
	// A cold Windows compositor can page in during its first mode change.
	// Honor the caller's deadline instead of silently shortening it to 10s.
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}
	var sequence uint32
	var platform *pc
	if err := d.call(ctx, func() error {
		platform = d.pc
		var err error
		sequence, err = ramfb.RequestResize(platform.displayMemory(), width, height)
		return err
	}); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var complete bool
		if err := d.call(ctx, func() error {
			if platform != d.pc {
				return fmt.Errorf("machine reset during display resize")
			}
			var err error
			complete, err = ramfb.ResizeComplete(platform.displayMemory(), sequence, width, height)
			return err
		}); err != nil {
			return err
		}
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.ctx.Done():
			return d.ctx.Err()
		case <-d.finished:
			return &vmm.Error{Code: vmm.ErrorState, Message: "VM stopped during display resize"}
		case <-ticker.C:
		}
	}
}
