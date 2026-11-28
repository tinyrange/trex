# Public examples and investigation tools

Run these commands from the repository root with `trex`, or replace `trex`
with `go run ./cmd/trex`. Script arguments follow the script filename. Input
paths below are caller-supplied; no private NAS layout is assumed.

## Start here: no media, network, or QEMU required

```console
trex scripts/examples/archive_roundtrip.star
trex scripts/examples/emulator_call.star
trex scripts/examples/emulator_override.star
```

These examples assert an in-memory TAR round trip, an x86 return value and
output buffer, and a wrapped semantic callback with restored plugin state.
The CLI test suite executes all three, so they are working examples rather
than pseudocode. They create no host outputs. See the
[emulation guide](../docs/starlark/emulation.md) for the API contracts.

The existing `examples/renvo_cc.star` and `examples/renvo_make.star` demonstrate
native compilation and checked execution without a host compiler; both are
also tested. `examples/renvo.star` is the larger compilation demonstration,
and `renvo_support.star` is a helper library, not a command. See
[renvo](../docs/renvo.md) for constraints and supported targets.

## Build GNU Hello in memory (network required)

```console
go run -tags renvo_bundle ./cmd/trex scripts/smoke/hello.star
```

The Starlark recipe pins and hashes the source, installs a virtual tool set,
then runs configure, make and all seven upstream tests. Nine CLI cases exercise
the generated ELF. Sources and intermediate products remain in memory; no host
shell or compiler is used. See [the shell/build guide](../docs/shell-emulator.md)
for the optional native same-image comparison and explicit compatibility limits.

## Inspect caller-owned input

```console
trex scripts/inspect/sevenzip.star archive.7z verify
trex scripts/inspect/debian_package.star package.deb control /control
trex scripts/inspect/debian_package.star package.deb --repl
trex scripts/inspect/installer_repl.star setup.exe
trex scripts/inspect/installer_repl.star media.iso /SETUP.EXE
```

The Debian inspector currently supports XZ-compressed control/data TARs.
The installer REPL exposes the format probe, decoded installer, payload, and
planning/registration helpers; unsupported formats remain explicit probe
results. `trex -repl` is sufficient for an empty interactive session: do not
create another script just to call `repl()`.

Specialized inspectors remain because they expose different format state:

| Script under `inspect/` | Purpose |
| --- | --- |
| `reactos_media.star` | ReactOS media summary and optional final JSON report |
| `mssql_sfp_repl.star` | Nested Drawbridge SFP exploration in a Debian package |
| `mssql_sfp_overlay.star` | Explicit final extracted SFP overlay tree; not an image-building stage |
| `msdos_7z_media.star` | DOS archive/floppy media inventory |
| `msdos_floppy_boot.star` | Guest floppy-boot integration and final screenshot |
| `windows_9x_iso_repl.star` | ISO directory and multi-cabinet input inspection |
| `windows_9x_disk_repl.star` | FAT and CREG disk inspection, optionally against a reference |
| `windows_9x_boot_repl.star` | Retained guest integration and explicit final disk output |

## Build and smoke a public operating-system image

```console
trex scripts/images/reactos.star ReactOS.zip reactos.raw
```

This explicitly writes an independently useful FAT32-rooted disk. The
[ReactOS publication guide](../docs/reactos-publication.md) specifies supported
media and commands for `smoke/reactos.star` and
`smoke/reactos_custom_account.star`, including screenshot and report outputs.
These are QEMU integration tests, separate from in-process PE emulation.

## Boot installed Linux desktops on CrumbleCracker

Run the desktop matrix on a Linux x86-64 host with KVM. The same manifest can
also run the installed-system smokes, which exercise boot, package ownership
and a representative command through the serial console.

```console
trex scripts/smoke/linux_desktops_cc.star media.json
trex scripts/smoke/linux_desktops_cc.star media.json alpine nixos
trex scripts/smoke/linux_installed_cc.star media.json arch ubuntu
```

Use paths to your original media in the manifest. Relative paths are relative
to the manifest. A NAS can serve the original media while Trex assembles the
disks, VM overlays, and desktop captures in memory.

```json
{
  "shared": {
    "loader_iso": "media/alpine-virt.iso",
    "minirootfs": "media/alpine-minirootfs.tar.gz"
  },
  "alpine": {
    "main_index": "media/alpine/main/APKINDEX.tar.gz",
    "community_index": "media/alpine/community/APKINDEX.tar.gz",
    "packages": "media/alpine/packages"
  },
  "nixos": {
    "iso": "media/nixos-minimal.iso",
    "desktop_iso": "media/nixos-graphical.iso"
  }
}
```

This example supplies enough media for the Alpine and NixOS selections. Fill
in the remaining sections to run all ten.

| Section | Installed smoke inputs | Desktop smoke inputs |
| --- | --- | --- |
| `alpine` | `main_index`, `packages` | Also `community_index` for Xfce |
| `arch` | `iso` | `iso`, `packages` for Xfce |
| `fedora` | Workstation `iso` | Xfce spin `desktop_iso` |
| `gentoo` | OpenRC amd64 `stage3`, minimal installer `iso` | Plasma LiveGUI `desktop_iso` |
| `nixos` | Minimal `iso` with an LTS entry | Graphical `desktop_iso` with a Plasma LTS entry |
| `opensuse` | Tumbleweed live `iso` | Tumbleweed Xfce `desktop_iso` |
| `slackware` | Slackware64 install DVD `iso` | Same `iso` for Xfce |
| `solus` | Budgie `iso` | Xfce `desktop_iso` |
| `ubuntu` | Ubuntu 24.04 LTS Desktop `iso` | Same `iso` for GNOME, plus amd64 GNU Hello `hello_deb` |
| `void` | glibc base `iso` | glibc Xfce `desktop_iso` |

Use an x86-64 Alpine virt ISO as the shared GRUB source and an Alpine
minirootfs from the same stable series. Bring trusted APKINDEX and Pacman
repository databases from the release or snapshot matching their base media.
Place the selected APK files in Alpine's package directory. Place `core.db`,
`extra.db`, and the selected package archives in Arch's package directory.
The Alpine and Arch standalone desktop smokes accept `--media-plan` to list
their required package filenames before constructing a disk.

The recipes read boot and package metadata from the supplied media. A rolling
snapshot can still change its installer layout or package hooks. Trex checks
that the media satisfies each recipe's expected layout and rejects package
effects it has no policy for.

## Windows 1.01 native computer use

`examples/windows_101_computer.star` builds the installed DOS/Windows image and
a native Win16 computer-use agent from caller-supplied floppy images. The
[computer-use guide](../docs/windows-101-computer-use.md) covers connection,
keyboard/mouse gesture helpers, offline REPL wire documentation, and a native
Paint drawing. Optional `video=boot-and-paint.mp4` records continuously from
BIOS boot using FFmpeg; `repl=true` enters the public trex REPL. No StarAgent or
private SDK is needed. No original Microsoft media or installed image is bundled.

## Debugging and transport integration

| Script under `debug/` | Purpose / requirements |
| --- | --- |
| `windows_nt5_kd.star` | Shared Windows 2000/XP serial KD workflow; a debug-enabled caller disk |
| `windows_xp_boot.star` | XP boot/GDB breakpoint workflow, distinct from serial KD |
| `reactos_kernel.star` | ReactOS guest kernel observation |
| `nbd_boot_smoke.star` | Generated BIOS sector proving direct NBD boot; requires QEMU/KVM |
| `code_watch.star`, `pe_calls.star` | Reusable bounded observation helpers, not commands |

ARM64 board composition is exposed through the [generic platform API](../docs/arm64-platforms.md).
Product-specific boot and restore recipes belong to the containing recipe repository.

See [debugging](../docs/starlark/debugging.md) for channels, symbols, events,
timeouts, and cleanup. These tools do not extract media for use by host parsers
or debuggers. Consult each command's usage before running it; some explicitly
request final screenshots, reports, or disk outputs.

## Consolidated entry points

`inspect/debian_package_repl.star` was folded into
`inspect/debian_package.star PACKAGE.deb --repl`.
`debug/windows_xp_kd.star` was only an alias: use
`debug/windows_nt5_kd.star` with the same arguments. Both old files remain
recoverable from Git history. The other probes are retained as specialized
tools, not presented as the getting-started API.
