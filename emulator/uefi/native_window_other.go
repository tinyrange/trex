//go:build !darwin || !arm64

package uefi

import "fmt"

func (n *NativeExecution) OpenWindow(string) error {
	return fmt.Errorf("native window requires macOS ARM64")
}
