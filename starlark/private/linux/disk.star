"""Installed Linux disks backed by Trex file views."""

_ESP_TYPE = "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}"
_LINUX_FS_TYPE = "{0FC63DAF-8483-4772-8E79-3D69D8477DE4}"
_SECTOR = 512
_ESP_START = 2048

def _guid(image_id, role):
    value = binary.hex(digest("trex-linux:" + image_id + ":" + role))
    return "%s-%s-5%s-8%s-%s" % (value[:8], value[8:12], value[13:16], value[17:20], value[20:32])

def root_partition_id(image_id):
    """Returns the PARTUUID used in the boot configuration and installed fstab."""
    return _guid(image_id, "root")

def disk_image(image_id, loader, kernel, cmdline, initramfs = None, root = None):
    """Build a GPT with a GRUB EFI System Partition and the supplied root volume."""
    if any([c in cmdline for c in ["\n", "\r", "\x00", ";", "$", "\"", "'", "\\"]]):
        fail("invalid character in GRUB kernel command line")
    esp = directory()
    esp.write("/EFI/BOOT/BOOTX64.EFI", loader)
    esp.write("/boot/vmlinuz", kernel)
    initrd_line = ""
    esp_bytes = kernel.size + loader.size
    if initramfs != None:
        esp.write("/boot/initramfs", initramfs)
        initrd_line = "    initrd /boot/initramfs\n"
        esp_bytes += initramfs.size
    esp.write("/boot/grub/grub.cfg", 'set timeout=0\nmenuentry "Linux" {\n    linux /boot/vmlinuz ' + cmdline + "\n" + initrd_line + "}\n")
    esp_size = max(64 << 20, ((esp_bytes + (17 << 20)) >> 20) << 20)
    esp_image = filesystem.fat32(esp, size = esp_size, hidden_sectors = _ESP_START, label = "LINUX EFI")
    root_lba = _ESP_START + esp_size // _SECTOR
    disk_size = root_lba * _SECTOR + (root.size if root != None else 0) + (1 << 20)
    image = filesystem.gpt(disk_size, disk_guid = _guid(image_id, "disk")).partition(
        esp_image,
        partition_guid = _guid(image_id, "esp"),
        type_guid = _ESP_TYPE,
        start_lba = _ESP_START,
        name = "EFI System",
        attributes = 1,
    )
    if root != None:
        image = image.partition(root, partition_guid = root_partition_id(image_id), type_guid = _LINUX_FS_TYPE, start_lba = root_lba, name = "Linux root")
    return image

def launch_cc(disk, memory = 512 << 20, overlay_limit = 256 << 20, run_timeout = 60, capturable = False, cpus = 1, virtio_gpu = False, serial = False):
    """Start CC firmware with the installed disk and a memory-only write overlay."""
    working = block.overlay(block.device(disk), max_dirty_bytes = overlay_limit, chunk_size = 4096)
    vm = vmm.start(vmm.machine(
        architecture = "x86_64",
        memory = memory,
        cpus = cpus,
        disks = [vmm.disk(working, bus = "nvme", unit = 0)],
        display = vmm.display("capturable" if capturable else "none"),
        channels = [vmm.channel("serial", name = "console")] if serial else [],
    ), cc.backend(uefi = True, hpet = True, run_timeout = run_timeout, virtio_gpu = virtio_gpu))
    return vm
