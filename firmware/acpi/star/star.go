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
