package cc

import (
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/device"
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
	return starlark.StringDict{"p390": starlark.NewBuiltin("cc.p390", p390Builtin), "kernel_symbol": starlark.NewBuiltin("cc.kernel_symbol", kernelSymbolBuiltin), "boot_bsd": starlark.NewBuiltin("cc.boot_bsd", bsdBootBuiltin), "backend": starlark.NewBuiltin("cc.backend", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		acpi, pciIDE, pciDisplay, hpet, uefi, usb := false, false, false, false, false, false
		ideDMA := true
		sb16 := false
		devices := starlark.Value(starlark.Tuple{})
		p390 := false
		p390S370 := false
		p390Start := ""
		privateAppleISA := false
		ideModel := "synthetic"
		overlayLimit := int64(256 << 20)
		runTimeoutValue := starlark.Value(starlark.Float(30))
		if err := starlark.UnpackArgs("cc.backend", args, kwargs, "acpi?", &acpi, "uefi?", &uefi, "usb?", &usb, "sb16?", &sb16, "p390?", &p390, "p390_s370?", &p390S370, "p390_start?", &p390Start, "hpet?", &hpet, "pci_ide?", &pciIDE, "pci_display?", &pciDisplay, "ide_model?", &ideModel, "ide_dma?", &ideDMA, "overlay_limit?", &overlayLimit, "run_timeout?", &runTimeoutValue, "private_apple_isa?", &privateAppleISA, "devices?", &devices); err != nil {
			return nil, err
		}
		if overlayLimit <= 0 {
			return nil, fmt.Errorf("cc.backend: overlay_limit must be positive")
		}
		runTimeout, number := starlark.AsFloat(runTimeoutValue)
		if !number || math.IsNaN(runTimeout) || math.IsInf(runTimeout, 0) || runTimeout <= 0 || runTimeout > 86400 {
			return nil, fmt.Errorf("cc.backend: run_timeout must be positive and at most 24 hours")
		}
		var epoch time.Time
		if p390Start != "" {
			var err error
			epoch, err = time.Parse(time.RFC3339, p390Start)
			if err != nil {
				return nil, fmt.Errorf("cc.backend: invalid p390_start: %w", err)
			}
		}
		if !p390 && (p390S370 || p390Start != "") {
			return nil, fmt.Errorf("cc.backend: mainframe CPU options require p390=True")
		}
		var specs []device.Spec
		iterable, ok := devices.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("cc.backend: devices must be iterable")
		}
		iter := iterable.Iterate()
		defer iter.Done()
		var value starlark.Value
		for iter.Next(&value) {
			d, ok := value.(PCIDeviceValue)
			if !ok {
				return nil, fmt.Errorf("cc.backend: expected pci_device, got %s", value.Type())
			}
			specs = append(specs, d.PCIDeviceSpec())
			if len(specs) > 256 {
				return nil, fmt.Errorf("cc.backend: too many devices")
			}
		}
		backend := &Backend{Devices: specs, P390S370: p390S370, P390Start: epoch, PrivateAppleISA: privateAppleISA, RunTimeout: time.Duration(runTimeout * float64(time.Second)), UEFI: uefi, USB: usb, SB16: sb16, P390: p390, ACPI: acpi, HPET: hpet, PCIIDE: pciIDE, PCIDisplay: pciDisplay, IDEModel: ideModel, PIOOnly: !ideDMA, OverlayLimit: overlayLimit}
		if err := device.Validate(backend.deviceSpecs(), device.Profile{}, reservedPCISlots()); err != nil {
			return nil, err
		}
		return backend, nil
	})}
}
