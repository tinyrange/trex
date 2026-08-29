"""Portable ACPI table construction helpers returning trex files."""

def table(signature, body, revision = 2, oem_id = "TREXOS", oem_table_id = "TREXACPI"):
    """Builds a checksummed ACPI table around a caller-supplied binary body."""
    return firmware.acpi_table(
        signature,
        body,
        revision = revision,
        oem_id = oem_id,
        oem_table_id = oem_table_id,
    )

def compatible_id(device, compatible_id):
    """Builds an SSDT that assigns _CID on an absolute ACPI device path."""
    return firmware.acpi_compatible_id(device, compatible_id)
