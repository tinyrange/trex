"""Compatibility entry point for the embedded msdos_622 image policy."""

load("@stdlib//images:msdos_622.star",
    _PARTITION_LBA = "PARTITION_LBA",
    _IMAGE_SIZE = "IMAGE_SIZE",
    _DISK_SIGNATURE = "DISK_SIGNATURE",
    _VOLUME_LABEL = "VOLUME_LABEL",
    _BIOS_CHS = "BIOS_CHS",
    _HELLO_MESSAGE = "HELLO_MESSAGE",
    _msdos_622_directory = "msdos_622_directory",
    _msdos_622_disk = "msdos_622_disk",
    _main = "main",
)

PARTITION_LBA = _PARTITION_LBA
IMAGE_SIZE = _IMAGE_SIZE
DISK_SIGNATURE = _DISK_SIGNATURE
VOLUME_LABEL = _VOLUME_LABEL
BIOS_CHS = _BIOS_CHS
HELLO_MESSAGE = _HELLO_MESSAGE
msdos_622_directory = _msdos_622_directory
msdos_622_disk = _msdos_622_disk
main = _main
