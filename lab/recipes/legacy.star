"""Native boot for the legacy images supplied by Trex."""

load("@stdlib//images:msdos_622.star", "msdos_622_disk", dos_geometry = "BIOS_CHS")
load("@stdlib//images:windows_101.star", "windows_101_disk", win_geometry = "BIOS_CHS")

def _boot(disk, geometry, cfg):
    capacity = geometry[0] * geometry[1] * geometry[2] * 512
    if disk.size < capacity:
        disk = binary.concat([disk, binary.extents(size = capacity - disk.size, extents = [])])
    storage = block.overlay(block.cache(block.device(disk)), max_dirty_bytes = 256 << 20, chunk_size = 4096)
    vm = vmm.start(vmm.machine(architecture = "i386", memory = cfg["memoryMiB"] << 20,
        disks = [vmm.disk(storage, bus = "ide", unit = 0, chs = geometry)], display = vmm.display("capturable")), cc.backend())
    return {"vm": vm}

def dos622(kind, cfg, media, lan, mac, trust):
    return _boot(msdos_622_disk(media["dos1"], media["dos2"], media["dos3"]), dos_geometry, cfg)

def win101(kind, cfg, media, lan, mac, trust):
    return _boot(windows_101_disk(media["dos1"], media["dos2"], media["dos3"],
        media["setup"], media["build"], media["utilities"], media["applications"], media["write"], startup = ""), win_geometry, cfg)
