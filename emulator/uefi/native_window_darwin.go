//go:build darwin && arm64

package uefi

import (
	"context"
	"fmt"
	"j5.nz/cc/display"
	presenter "j5.nz/cc/display/gowin"
)

func (n *NativeExecution) OpenWindow(title string) error {
	if n.Display == nil || n.Keyboard == nil || n.Pointer == nil {
		return fmt.Errorf("native window requires RAMFB, keyboard and pointer")
	}
	runner := display.StartRunner(context.Background(), &NativeDisplaySession{Execution: n}, func(ctx context.Context) error {
		ex, err := n.Run(ctx)
		if err != nil {
			return err
		}
		if ex.Reason != 0 {
			return fmt.Errorf("native execution stopped: %+v", ex)
		}
		return nil
	})
	defer runner.Close()
	return presenter.Run(context.Background(), runner, presenter.Options{Title: title, Advance: func(context.Context) error { return runner.Err() }})
}
