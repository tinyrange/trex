"""Slipstream Alpine Xfce packages and verify an Xfce session in CC."""

load("//scripts/images:alpine_linux.star", "alpine_disk", "alpine_sources")
load("//starlark/private/linux:desktop.star", "add_desktop_account", "configure_xfce_x11", "install_shared_mime", "verify_desktop_cc")
load("//starlark/private/linux:installed.star", "inspect_root")
load("//starlark/private/linux:tree.star", "file_entry", "symlink_entry")

_PACKAGES = ["xfce4", "xorg-server", "xf86-video-fbdev", "xinit", "xf86-input-libinput", "dbus-openrc", "eudev", "xfce4-terminal", "xprop"]
_PROOF = "ALPINE_DESKTOP_OK xfce4-panel xfdesktop xfwm4"
_CACHES = ["ca-certificates", "desktop-file-utils", "fontconfig", "gdk-pixbuf", "glib", "gtk+3.0", "gtk-update-icon-cache", "mkfontscale", "pango", "shared-mime-info"]
_SVG_LOADER = """# GdkPixbuf Image Loader Modules file
"/SVG_LOADER_PATH"
"svg" 6 "gdk-pixbuf" "Scalable Vector Graphics" "LGPL"
"image/svg+xml" "image/svg" "image/svg-xml" "image/vnd.adobe.svg+xml" "text/xml-svg" "image/svg+xml-compressed" ""
"svg" "svgz" "svg.gz" ""
" <svg" "*    " 100
" <!DOCTYPE svg" "*             " 100

"""

def _effects(package, phase):
    name = package["name"]
    # Service accounts, D-Bus identity and the desktop's image lookup files
    # are composed below. The installed APK database retains the original hooks.
    if phase == ".trigger":
        return name in _CACHES or name in ["dbus", "eudev"]
    if phase == ".pre-install":
        return name in ["dbus", "polkit-common"]
    return phase == ".post-install" and name in ["dbus", "icu-data-en", "thunar"]

def _configure(entries):
    add_desktop_account(entries, "messagebus", 470, shell = "/sbin/nologin")
    add_desktop_account(entries, "polkitd", 471, shell = "/sbin/nologin")
    entries["etc/machine-id"] = file_entry("etc/machine-id", binary.hex(digest("alpine-xfce-cc"))[:32] + "\n")
    entries["etc/runlevels/default/dbus"] = symlink_entry("etc/runlevels/default/dbus", "/etc/init.d/dbus")
    install_shared_mime(entries)
    suffix = "/loaders/libpixbufloader_svg.so"
    svg = [path for path in entries if path.startswith(("usr/lib/", "usr/lib64/")) and path.endswith(suffix)]
    if len(svg) != 1:
        fail("librsvg must provide one GdkPixbuf SVG loader")
    cache = svg[0][:-len(suffix)] + "/loaders.cache"
    entries[cache] = file_entry(cache, _SVG_LOADER.replace("SVG_LOADER_PATH", svg[0]))
    configure_xfce_x11(entries, "busybox", _PROOF, "apk info --who-owns /usr/bin/xfce4-panel | grep -q 'owned by xfce4-panel-'", display_modules = ["simpledrm"])

def main(args):
    if len(args) not in [5, 6] or len(args) == 6 and args[5] != "--media-plan":
        fail("usage: scripts/smoke/alpine_desktop.star <Alpine virt ISO> <Alpine minirootfs> <main APKINDEX> <package directory> <community APKINDEX> [--media-plan]")
    if len(args) == 6:
        for repo, name in alpine_sources(extra_packages = _PACKAGES, list_only = True, *args[:5]):
            print(repo + " " + name)
        return
    boot, mini, repo, sources, community = alpine_sources(extra_packages = _PACKAGES, *args)
    disk = alpine_disk(boot, mini, repo, sources, community = community, extra_packages = _PACKAGES, configure = _configure, package_effects = _effects)
    root = inspect_root(disk, ["usr/bin/xfce4-panel", "usr/bin/xfce4-session", "usr/bin/Xorg", "lib/apk/db/installed", "lib/apk/db/scripts.tar", "lib/apk/db/triggers", "usr/share/mime/magic"])
    records = root.find("lib/apk/db/installed").file.read()
    if not any([block.startswith("P:xfce4-panel\n") or "\nP:xfce4-panel\n" in block for block in records.split("\n\n")]):
        fail("the Xfce panel was not registered in the installed APK database")
    verify_desktop_cc(disk, _PROOF)
