"""Run the installed Linux CrumbleCracker smokes from a caller-supplied media manifest."""

load("//scripts/smoke:alpine_linux.star", alpine = "main")
load("//scripts/smoke:arch_linux.star", arch = "main")
load("//scripts/smoke:fedora_linux.star", fedora = "main")
load("//scripts/smoke:gentoo_linux.star", gentoo = "main")
load("//scripts/smoke:nixos_linux.star", nixos = "main")
load("//scripts/smoke:opensuse_linux.star", opensuse = "main")
load("//scripts/smoke:slackware_linux.star", slackware = "main")
load("//scripts/smoke:solus_linux.star", solus = "main")
load("//scripts/smoke:ubuntu_linux.star", ubuntu = "main")
load("//scripts/smoke:void_linux.star", void = "main")

load("//starlark/private/linux:media.star", "media_paths", "read_media")

_LOADER = ("shared", "loader_iso")
_MINIROOT = ("shared", "minirootfs")

_SMOKES = {
    "alpine": (alpine, [_LOADER, _MINIROOT, ("alpine", "main_index"), ("alpine", "packages")]),
    "arch": (arch, [("arch", "iso"), _LOADER, _MINIROOT]),
    "fedora": (fedora, [("fedora", "iso"), _LOADER]),
    "gentoo": (gentoo, [("gentoo", "stage3"), ("gentoo", "iso"), _LOADER, _MINIROOT]),
    "nixos": (nixos, [("nixos", "iso"), _LOADER, _MINIROOT]),
    "opensuse": (opensuse, [("opensuse", "iso"), _LOADER, _MINIROOT]),
    "slackware": (slackware, [("slackware", "iso"), _LOADER]),
    "solus": (solus, [("solus", "iso"), _LOADER]),
    "ubuntu": (ubuntu, [("ubuntu", "iso"), _LOADER]),
    "void": (void, [("void", "iso"), _LOADER]),
}

def main(args):
    media, base, names = read_media(args, _SMOKES.keys(), "scripts/smoke/linux_installed_cc.star")
    failed = []
    for name in names:
        smoke, fields = _SMOKES[name]
        result = testing.attempt(_smoke, args = [smoke, fields, media, base])
        if not result.ok:
            print(name, result.error)
            failed.append(name)
    if failed:
        fail("installed smokes failed for " + ", ".join(failed))

def _smoke(smoke, fields, media, base):
    smoke(media_paths(media, base, *fields))
