package star

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/firmware/acpi"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"acpi_mcfg": starlark.NewBuiltin("acpi_mcfg", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var base uint64
			var segment uint16
			var first, last uint8
			if err := starlark.UnpackArgs("acpi_mcfg", args, kwargs, "base", &base, "first_bus", &first, "last_bus", &last, "segment?", &segment); err != nil {
				return nil, err
			}
			data, err := acpi.PCIConfiguration(base, segment, first, last)
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "mcfg", Data: data}, nil
		}),
		"acpi_pci_root": starlark.NewBuiltin("acpi_pci_root", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var p acpi.PCIRoot
			var routes *starlark.List
			if err := starlark.UnpackArgs("acpi_pci_root", args, kwargs, "memory_base", &p.MemoryBase, "memory_size", &p.MemorySize, "routes", &routes, "first_bus?", &p.FirstBus, "last_bus?", &p.LastBus, "segment?", &p.Segment); err != nil {
				return nil, err
			}
			if routes.Len() > 255 {
				return nil, fmt.Errorf("too many PCI interrupt routes")
			}
			for i := 0; i < routes.Len(); i++ {
				row, ok := routes.Index(i).(starlark.Tuple)
				if !ok || len(row) != 3 {
					return nil, fmt.Errorf("route must be (device,pin,interrupt)")
				}
				var r acpi.PCIInterrupt
				if err := starlark.UnpackArgs("route", row, nil, "device", &r.Device, "pin", &r.Pin, "interrupt", &r.Interrupt); err != nil {
					return nil, err
				}
				p.Interrupts = append(p.Interrupts, r)
			}
			data, err := p.AML()
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "pci-root.aml", Data: data}, nil
		}),
		"acpi_gtdt_arm64": starlark.NewBuiltin("acpi_gtdt_arm64", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var physical, virtual uint32
			if err := starlark.UnpackArgs("acpi_gtdt_arm64", args, kwargs, "physical_interrupt", &physical, "virtual_interrupt", &virtual); err != nil {
				return nil, err
			}
			data, err := acpi.ARM64GenericTimer(physical, virtual)
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "gtdt", Data: data}, nil
		}),
		"acpi_madt_arm64": starlark.NewBuiltin("acpi_madt_arm64", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var distributor, redistributor uint64
			var performance, maintenance uint32
			var processors starlark.Iterable
			if err := starlark.UnpackArgs("acpi_madt_arm64", args, kwargs, "distributor", &distributor, "redistributor", &redistributor, "mpidrs", &processors, "performance_interrupt?", &performance, "maintenance_interrupt?", &maintenance); err != nil {
				return nil, err
			}
			var mpidrs []uint64
			it := processors.Iterate()
			defer it.Done()
			var value starlark.Value
			for it.Next(&value) {
				var mpidr uint64
				if err := starlark.AsInt(value, &mpidr); err != nil {
					return nil, err
				}
				mpidrs = append(mpidrs, mpidr)
				if len(mpidrs) > 256 {
					return nil, fmt.Errorf("too many GIC processors")
				}
			}
			data, err := acpi.ARM64Interrupts(distributor, redistributor, mpidrs, performance, maintenance)
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "madt", Data: data}, nil
		}),
		"acpi_fadt_arm64": starlark.NewBuiltin("acpi_fadt_arm64", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var dsdt uint64
			psci, hvc := false, false
			if err := starlark.UnpackArgs("acpi_fadt_arm64", args, kwargs, "dsdt", &dsdt, "psci?", &psci, "hvc?", &hvc); err != nil {
				return nil, err
			}
			data, err := acpi.ARM64FixedDescription(dsdt, psci, hvc)
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "fadt", Data: data}, nil
		}),
		"acpi_rsdp": starlark.NewBuiltin("acpi_rsdp", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var xsdt uint64
			oem := "TREXOS"
			if err := starlark.UnpackArgs("acpi_rsdp", args, kwargs, "xsdt", &xsdt, "oem_id?", &oem); err != nil {
				return nil, err
			}
			data, err := acpi.RootPointer(xsdt, oem)
			if err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "rsdp", Data: data}, nil
		}),
		"acpi_table":         starlark.NewBuiltin("acpi_table", firmwareACPITableBuiltin),
		"acpi_compatible_id": starlark.NewBuiltin("acpi_compatible_id", firmwareACPICompatibleIDBuiltin),
	}
}

func firmwareACPITableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var signature string
	var bodyValue starlark.Value
	revision := 2
	oemID, oemTableID := "TREXOS", "TREXACPI"
	oemRevision := uint64(1)
	creatorID := "TREX"
	creatorRevision := uint64(1)
	if err := starlark.UnpackArgs("acpi_table", args, kwargs,
		"signature", &signature, "body", &bodyValue, "revision?", &revision,
		"oem_id?", &oemID, "oem_table_id?", &oemTableID, "oem_revision?", &oemRevision,
		"creator_id?", &creatorID, "creator_revision?", &creatorRevision,
	); err != nil {
		return nil, err
	}
	body, err := starfile.BytesForValue(bodyValue, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("acpi_table: body: %w", err)
	}
	table, err := acpi.Table(signature, body, revision, oemID, oemTableID, oemRevision, creatorID, creatorRevision)
	if err != nil {
		return nil, fmt.Errorf("acpi_table: %w", err)
	}
	return &starfile.Bytes{Name: strings.ToLower(signature) + ".aml", Data: table}, nil
}

func firmwareACPICompatibleIDBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var device, compatibleID string
	if err := starlark.UnpackArgs("acpi_compatible_id", args, kwargs, "device", &device, "compatible_id", &compatibleID); err != nil {
		return nil, err
	}
	body, err := acpi.CompatibleIDAML(device, compatibleID)
	if err != nil {
		return nil, fmt.Errorf("acpi_compatible_id: %w", err)
	}
	table, err := acpi.Table("SSDT", body, 2, "TREXOS", "COMPATID", 1, "TREX", 1)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "compatible-id.aml", Data: table}, nil
}
