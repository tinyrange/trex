package rfe

import (
	"context"
	"j5.nz/cc/hypervisor"
)

// NewCPU creates the software CPU used by Backend. This is also useful for
// embedding the engine in a shared PC/device model or native differential tests.
func NewCPU(ctx context.Context) (hypervisor.X86, error) { return newCPU(ctx) }
