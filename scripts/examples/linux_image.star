"""Composable Linux image construction; no host paths or guest package tools.

Load construct with previously authenticated/pinned Alpine package records.
Returned effects must be deliberately implemented or replaced by the caller.
This constructs artifacts, not a bootloader, Linux VM or installed apk database.
"""

load("@stdlib//unix:alpine.star", "install_plan")
load("@stdlib//unix:kernel.star", "select", "build_initramfs")

def construct(packages, init, modifications = [], requested_modules = [], module_aliases = {}, external = [], root_size = 256 << 20, flavor = "virt"):
    plan = install_plan(packages, modifications = modifications, external = external)
    kernel = select(plan["entries"], flavor = flavor)
    userspace = [e for e in plan["entries"] if not e["path"].startswith("lib/modules/") and not e["path"].startswith("boot/")]
    initrd = build_initramfs(kernel, userspace, init = init, requested = requested_modules, module_aliases = module_aliases)
    rootfs = filesystem.ext4_build(plan["entries"], size = root_size, label = "alpine")
    return {"kernel": kernel, "initramfs": initrd, "rootfs": rootfs, "plan": plan}
