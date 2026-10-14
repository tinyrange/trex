package cc

import (
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"math"
	"runtime"
	"time"
)

func (b *Backend) String() string {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return "<cc.backend arm64 hvf>"
	}
	if b.UEFI {
		return "<cc.backend uefi pc>"
	}
	return "<cc.backend bios pc>"
}
func (b *Backend) Type() string            { return "vmm_backend" }
func (b *Backend) Freeze()                 {}
func (b *Backend) Truth() starlark.Bool    { return starlark.True }
func (b *Backend) Hash() (uint32, error)   { return 0, fmt.Errorf("unhashable: cc backend") }
func (b *Backend) VMMBackend() vmm.Backend { return b }
func Builtins() starlark.StringDict {
	return starlark.StringDict{"kernel_symbol": starlark.NewBuiltin("cc.kernel_symbol", kernelSymbolBuiltin), "boot_bsd": starlark.NewBuiltin("cc.boot_bsd", bsdBootBuiltin), "backend": starlark.NewBuiltin("cc.backend", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		acpi, pciIDE, hpet, uefi := false, false, false, false
		ideDMA := true
		privateAppleISA := false
		ideModel := "synthetic"
		overlayLimit := int64(256 << 20)
		runTimeoutValue := starlark.Value(starlark.Float(30))
		if err := starlark.UnpackArgs("cc.backend", args, kwargs, "acpi?", &acpi, "uefi?", &uefi, "hpet?", &hpet, "pci_ide?", &pciIDE, "ide_model?", &ideModel, "ide_dma?", &ideDMA, "overlay_limit?", &overlayLimit, "run_timeout?", &runTimeoutValue, "private_apple_isa?", &privateAppleISA); err != nil {
			return nil, err
		}
		if overlayLimit <= 0 {
			return nil, fmt.Errorf("cc.backend: overlay_limit must be positive")
		}
		runTimeout, number := starlark.AsFloat(runTimeoutValue)
		if !number || math.IsNaN(runTimeout) || math.IsInf(runTimeout, 0) || runTimeout <= 0 || runTimeout > 86400 {
			return nil, fmt.Errorf("cc.backend: run_timeout must be positive and at most 24 hours")
		}
		return &Backend{PrivateAppleISA: privateAppleISA, RunTimeout: time.Duration(runTimeout * float64(time.Second)), UEFI: uefi, ACPI: acpi, HPET: hpet, PCIIDE: pciIDE, IDEModel: ideModel, PIOOnly: !ideDMA, OverlayLimit: overlayLimit}, nil
	})}
}
