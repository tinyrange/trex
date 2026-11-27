"""Boot original distro kernels on the isolated lab Ethernet domain."""

load("@stdlib//unix:alpine.star", "install_plan", "read_package")
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
    if [ -n "$dns" ]; then
      : > /etc/resolv.conf
      for server in $dns; do echo "nameserver $server" >> /etc/resolv.conf; done
    fi
    ;;
esac
"""

def _packages():
    return [read_package(http_file([_APK_BASE + name + ".apk"], size = size, cache_bytes = 64 << 20), digest)
            for name, size, digest in _APK_SOURCES]

def _start(kernel, initrd, command, cfg, lan, mac, media = None):
    networks = [vmm.network("ethernet", switch = lan, mac = mac)] if lan != None else []
    disks = [] if media == None else [vmm.disk(block.cache(block.device(media)), bus = "ide", unit = 0, read_only = True)]
    vm = vmm.start(vmm.machine(architecture = "x86_64", memory = cfg["memoryMiB"] << 20,
        boot = vmm.linux_boot(kernel = kernel, initramfs = initrd, command_line = command),
        networks = networks, disks = disks, display = vmm.display("capturable"),
        channels = [vmm.channel("serial", name = "console")]), cc.backend(acpi = True, pci_ide = True))
    return {"vm": vm, "console": vm.channel("console")}

def alpine(kind, cfg, media, lan, mac, trust):
    lab_phase("preparing", "Reading pinned Alpine packages")
    applets = "sh ash ls cat cp mv rm mkdir rmdir pwd grep find sed awk less head tail sort wc chmod ps dmesg top mount umount hostname uname ip ifconfig ping nslookup sleep date tar gzip vi stty env which df du clear id whoami tty".split()
    links = [{"path": "bin/" + name, "mode": 0o120777, "target": "busybox"} for name in applets]
    plan = install_plan(_packages(), external = ["initramfs-generator"], modifications = links)
    kernel = select(plan["entries"])
    entries = [e for e in plan["entries"] if not e["path"].startswith("lib/modules/") and not e["path"].startswith("boot/")]
    instruct = """#!/bin/sh
export PATH=/bin:/sbin
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
    entries += [{"path": name, "mode": 0o040755} for name in ["dev", "proc", "sys"]]
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
    boot = None
    disks = [vmm.disk(block.device(source, logical_block_size = 2048), bus = "ide", media = "cdrom", read_only = True, unit = 2)]
    devices = [qemu.device("VGA"), qemu.device("qemu-xhci"), qemu.device("usb-tablet")]
    netdevs = []
    if cfg.get("qemuPeer"):
        netdevs.append(qemu.netdev("socket", id = "lab", connect = cfg["qemuPeer"]))
        devices.append(qemu.device("e1000", netdev = "lab", mac = mac))
    options = [qemu.option("-nodefaults"), qemu.option("-cpu", "host"), qemu.option("-boot", "order=d")]
    channels = []
    if kind == "debian-live":
        _iso_member(iso, "/live", "vmlinuz")
        _iso_member(iso, "/live", "initrd.img")
    elif kind == "ubuntu-live":
        _iso_member(iso, "/casper", "vmlinuz")
        _iso_member(iso, "/casper", "initrd")
    else:
        boot = vmm.linux_boot(kernel = _iso_member(iso, "/images/pxeboot", "vmlinuz"),
            initramfs = _iso_member(iso, "/images/pxeboot", "initrd.img"),
            command_line = "console=tty0 console=ttyS0,115200 inst.rescue inst.stage2=hd:/dev/sr0 inst.text")
        channels = [vmm.channel("serial", name = "console")]
    machine = vmm.machine(architecture = "x86_64", memory = cfg["memoryMiB"] << 20, boot = boot,
        disks = disks, channels = channels, display = vmm.display("capturable"))
    vm = vmm.start(machine, qemu.backend(machine = "pc", accelerator = "kvm", display_frontend = "none",
        block_transport = "nbd", devices = devices, netdevs = netdevs, options = options))
    result = {"vm": vm}
    if channels:
        result["console"] = vm.channel("console")
    return result
