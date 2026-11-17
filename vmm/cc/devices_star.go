package cc

import (
	"fmt"
	"github.com/tinyrange/trex/vmm/device"
	"go.starlark.net/starlark"
)

// PCIDeviceValue is the extension boundary for other native model namespaces.
// A new model can expose this interface without changing cc.backend or dispatch.
type PCIDeviceValue interface {
	starlark.Value
	PCIDeviceSpec() device.Spec
}
type pciDeviceValue struct{ spec device.Spec }

func (d *pciDeviceValue) String() string {
	return fmt.Sprintf("<pci_device %s 00:%02x.%d>", d.spec.Name, d.spec.BDF>>3, d.spec.BDF&7)
}
func (d *pciDeviceValue) Type() string               { return "pci_device" }
func (d *pciDeviceValue) Freeze()                    {}
func (d *pciDeviceValue) Truth() starlark.Bool       { return starlark.True }
func (d *pciDeviceValue) Hash() (uint32, error)      { return 0, fmt.Errorf("unhashable: pci device") }
func (d *pciDeviceValue) PCIDeviceSpec() device.Spec { return d.spec }

// NewPCIDeviceValue wraps immutable native construction policy, not a live
// device or Starlark callbacks. The caller must not mutate captured options.
func NewPCIDeviceValue(spec device.Spec) PCIDeviceValue { return &pciDeviceValue{spec} }
