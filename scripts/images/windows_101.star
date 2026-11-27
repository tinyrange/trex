"""Compatibility entry point for the embedded windows_101 image policy."""

load("@stdlib//images:windows_101.star",
    _PARTITION_LBA = "PARTITION_LBA",
    _IMAGE_SIZE = "IMAGE_SIZE",
    _DISK_SIGNATURE = "DISK_SIGNATURE",
    _VOLUME_LABEL = "VOLUME_LABEL",
    _BIOS_CHS = "BIOS_CHS",
    _HELLO_TITLE = "HELLO_TITLE",
    _windows_101_disk = "windows_101_disk",
    _main = "main",
)

PARTITION_LBA = _PARTITION_LBA
IMAGE_SIZE = _IMAGE_SIZE
DISK_SIGNATURE = _DISK_SIGNATURE
VOLUME_LABEL = _VOLUME_LABEL
BIOS_CHS = _BIOS_CHS
HELLO_TITLE = _HELLO_TITLE
windows_101_disk = _windows_101_disk
main = _main
