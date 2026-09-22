package cc

import (
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (b *Backend) String() string {
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
	return starlark.StringDict{"backend": starlark.NewBuiltin("cc.backend", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		acpi, pciIDE, hpet, uefi := false, false, false, false
		ideDMA := true
		overlayLimit := int64(256 << 20)
		if err := starlark.UnpackArgs("cc.backend", args, kwargs, "acpi?", &acpi, "uefi?", &uefi, "hpet?", &hpet, "pci_ide?", &pciIDE, "ide_dma?", &ideDMA, "overlay_limit?", &overlayLimit); err != nil {
			return nil, err
		}
		if overlayLimit <= 0 {
			return nil, fmt.Errorf("cc.backend: overlay_limit must be positive")
		}
		return &Backend{UEFI: uefi, ACPI: acpi, HPET: hpet, PCIIDE: pciIDE, PIOOnly: !ideDMA, OverlayLimit: overlayLimit}, nil
	})}
}
