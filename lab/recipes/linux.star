"""Boot original distro kernels on the isolated lab Ethernet domain."""

load("@stdlib//unix:alpine.star", "install_plan", "merge", "read_package")
load("@stdlib//unix:kernel.star", "select", "modules")
load("@stdlib//unix:initramfs.star", initramfs = "build")

# Alpine 3.22 byte identities. If the package mirror retires a version,
# update this set together and rerun the networked shell smoke.
_APK_BASE = "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/"
_APK_SOURCES = [
    ("busybox-1.37.0-r20", 506116, "7cc34c2dda2520b456ab4a55abc37fe245ac90f98ab9f1c7a9be3aec035df48e"),
    ("musl-1.2.5-r13", 412387, "359890bc7c4dc5fee7a85192de60a471c987e4664767288578beca60a44db2c8"),
    ("linux-virt-6.12.119-r0", 40781462, "e38b6ba4c80d4c99f1130418154d8d4dd02d9adc1fbb9eaeae330e8430de8875"),
]
_NON_INSTALL_EFFECTS = [".pre-upgrade", ".post-upgrade", ".pre-deinstall", ".post-deinstall"]

_DHCP_CLIENT = """#!/bin/sh
B=/bin/busybox
case "$1" in
  deconfig)
    $B ip -4 addr flush dev "$interface"
    ;;
  bound|renew)
    $B ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
    if [ -n "$router" ]; then
      set -- $router
      $B ip route replace default via "$1" dev "$interface"
    fi
    {
      for server in $dns; do echo "nameserver $server"; done
      if [ -n "$domain" ]; then printf 'search %s\\n' "$domain"; fi
    } > /etc/resolv.conf
    ;;
esac
"""

def _packages(sources):
    return [read_package(http_file([_APK_BASE + name + ".apk"], size = size, cache_bytes = 64 << 20), digest)
            for name, size, digest in sources]

def _install_links(packages, links):
    # Alpine supplies the applet paths in the package. Reproduce busybox's
    # fresh-install symlinks without replacing any package's real files.
    occupied = {e["path"]: True for package in packages for e in package["entries"]}
    occupied.update({e["path"]: True for e in links})
    for package in packages:
        name = package["name"]
        if name in ["busybox", "busybox-extras"] and package["version"] == "1.37.0-r20":
            paths = [e["data"].read() for e in package["entries"] if e["path"] == "etc/busybox-paths.d/" + name]
            if len(paths) != 1:
                fail("Alpine package " + name + " is missing its applet paths")
            for path in paths[0].splitlines():
                if path and path not in occupied:
                    links.append({"path": path, "mode": 0o120777, "target": "/bin/" + name})
                    occupied[path] = True
    return links

def _start(kernel, initrd, command, cfg, lan, mac, media = None):
    networks = [vmm.network("ethernet", switch = lan, mac = mac)] if lan != None else []
    disks = [] if media == None else [vmm.disk(block.cache(block.device(media)), bus = "ide", unit = 0, read_only = True)]
    display = "none" if media == None else "capturable"
    ide_model = "synthetic" if media == None else "ich7-pata"
    vm = vmm.start(vmm.machine(architecture = "x86_64", memory = cfg["memoryMiB"] << 20,
        boot = vmm.linux_boot(kernel = kernel, initramfs = initrd, command_line = command),
        networks = networks, disks = disks, display = vmm.display(display),
        channels = [vmm.channel("serial", name = "console")]), cc.backend(acpi = True, pci_ide = True, ide_model = ide_model, hpet = media != None))
    return {"vm": vm, "console": vm.channel("console")}

def alpine(kind, cfg, media, lan, mac, trust):
    lab_phase("preparing", "Reading pinned Alpine packages")
    applets = "sh ash ls cat cp mv rm mkdir rmdir pwd grep find sed awk less head tail sort wc chmod ps dmesg top mount umount hostname uname ip ifconfig ping nslookup sleep date tar gzip vi stty env which df du clear id whoami tty".split()
    links = [{"path": "bin/" + name, "mode": 0o120777, "target": "busybox"} for name in applets]
    base = _packages(_APK_SOURCES)
    plan = install_plan(base, external = ["initramfs-generator"])
    kernel = select(plan["entries"])
    packages = base
    if cfg.get("packages"):
        lab_phase("preparing", "Resolving and verifying Alpine packages")
        additional = []
        for source in lab_alpine_packages(tuple(base)):
            package = read_package(source["file"], source["sha256"], expected = source["expected"])
            effects = [name for name in sorted(package["effects"]) if name not in _NON_INSTALL_EFFECTS]
            if package["name"] == "busybox-extras" and package["version"] == "1.37.0-r20":
                effects = [name for name in effects if name != ".post-install"]
            if effects:
                fail("Alpine package " + package["name"] + " needs unsupported installation effects: " + ", ".join(effects))
            additional.append(package)
        packages = base + additional
    payload = merge(packages, modifications = _install_links(packages, links), allow_effects = True)
    entries = [e for e in payload if not e["path"].startswith("lib/modules/") and not e["path"].startswith("boot/")]
    instruct = """#!/bin/sh
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
B=/bin/busybox
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
"""
    if lan != None:
        network_drivers = ["e1000"] if cfg.get("address") else ["e1000", "af_packet"]
        for module in modules(kernel, network_drivers):
            entry = dict(module)
            if entry["path"].endswith(".gz"):
                entry["path"] = entry["path"][:-3]
                entry["data"] = archive.gzip(entry["data"], maximum_bytes = 8 << 20)
            entries.append(entry)
            instruct += "$B insmod /" + entry["path"] + "\n"
        instruct += "$B ip link set eth0 up\n"
        if cfg.get("address"):
            instruct += "$B ip addr add " + cfg["address"] + " dev eth0\n"
        else:
            entries.append({"path": "bin/lab-dhcp", "mode": 0o100755, "data": binary.encode(_DHCP_CLIENT, encoding = "ascii")})
            instruct += "$B udhcpc -f -t 3 -T 2 -i eth0 -s /bin/lab-dhcp >/dev/null 2>&1 &\n"
    instruct += """export TERM=xterm
$B stty rows 28 cols 96 < /dev/ttyS0
echo 'Alpine Linux lab shell. Guest files are temporary.'
$B setsid -c /bin/sh -i </dev/ttyS0 >/dev/ttyS0 2>&1
$B poweroff -f
"""
    result = _start(kernel["file"], initramfs(entries, init = instruct), "console=ttyS0,115200 rdinit=/init nokaslr nopti panic=0", cfg, lan, mac)
    result["address"] = cfg.get("address", "").split("/")[0] if lan != None else ""
    result["display"] = False
    return result

def _iso_member(iso, directory, basename):
    exact = iso.find(directory + "/" + basename)
    if exact != None:
        return exact
    entries = [e for e in iso.entries if e.path.startswith(directory + "/" + basename + "-") and e.entry_type == "file"]
    if len(entries) == 1:
        return entries[0].data
    fail("expected the original " + directory + "/" + basename + " in the selected ISO")

def live_linux(kind, cfg, media, lan, mac, trust):
    source = media["system"]
    iso = filesystem.iso9660(source)
    if kind == "debian-live":
        directory, initrd = "/live", "initrd.img"
        command = "console=ttyS0 console=tty0 boot=live components live-media=/dev/sda"
    elif kind == "ubuntu-live":
        directory, initrd = "/casper", "initrd"
        command = "console=ttyS0 console=tty0 boot=casper live-media=/dev/sda"
    else:
        directory, initrd = "/images/pxeboot", "initrd.img"
        command = "console=tty0 console=ttyS0,115200 inst.rescue inst.stage2=hd:/dev/sda inst.text"
    # Each initramfs locates the live filesystem on the same unmodified ISO
    # bytes that supplied the kernel. CC presents those bytes on its IDE disk.
    return _start(_iso_member(iso, directory, "vmlinuz"), _iso_member(iso, directory, initrd), command, cfg, lan, mac, media = source)
