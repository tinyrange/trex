//go:build darwin && arm64

package uefi

import (
	"context"
	"errors"
	"fmt"
	"j5.nz/cc/display"
	presenter "j5.nz/cc/display/gowin"
)

func (n *NativeExecution) OpenWindow(title string) error {
	if n.Display == nil || n.Keyboard == nil || n.Pointer == nil {
		return fmt.Errorf("native window requires RAMFB, keyboard and pointer")
	}
	runner := display.StartRunner(context.Background(), &NativeDisplaySession{Execution: n}, n.advanceDisplay)
	defer runner.Close()
	err := presenter.Run(context.Background(), runner, presenter.Options{Title: title, Advance: func(context.Context) error { return runner.Err() }})
	if errors.Is(err, errNativeShutdown) {
		return nil
	}
	return err
}
