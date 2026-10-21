// Package rfe implements a software x86 PC backend using Renvo's x86.rfe.
// Firmware, disk, VGA, keyboard and other PC devices are shared with cc, so
// CPU comparisons do not accidentally compare different machine models.
package rfe

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/cc"
	"go.starlark.net/starlark"
)

type Backend struct{ OverlayLimit int64 }

func (b *Backend) pc() *cc.Backend {
	return &cc.Backend{CPUFactory: newCPU, Name: "rfe.v1", OverlayLimit: b.OverlayLimit}
}
func (*Backend) ID() string                                     { return "rfe.v1" }
func (b *Backend) Capabilities() []string                       { return b.pc().Capabilities() }
func (b *Backend) Validate(m vmm.Machine) []vmm.ValidationIssue { return b.pc().Validate(m) }
func (b *Backend) Start(ctx context.Context, m vmm.Machine) (vmm.Driver, error) {
	return b.pc().Start(ctx, m)
}
func (*Backend) String() string            { return "<rfe.backend x86 native-jit pc>" }
func (*Backend) Type() string              { return "vmm_backend" }
func (*Backend) Freeze()                   {}
func (*Backend) Truth() starlark.Bool      { return starlark.True }
func (*Backend) Hash() (uint32, error)     { return 0, fmt.Errorf("unhashable: rfe backend") }
func (b *Backend) VMMBackend() vmm.Backend { return b }
func Builtins() starlark.StringDict {
	return starlark.StringDict{"backend": starlark.NewBuiltin("rfe.backend", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		limit := int64(256 << 20)
		if err := starlark.UnpackArgs("rfe.backend", args, kwargs, "overlay_limit?", &limit); err != nil {
			return nil, err
		}
		if limit <= 0 {
			return nil, fmt.Errorf("rfe.backend: overlay_limit must be positive")
		}
		return &Backend{OverlayLimit: limit}, nil
	})}
}
