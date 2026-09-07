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

## Debugging and transport integration

| Script under `debug/` | Purpose / requirements |
| --- | --- |
| `windows_nt5_kd.star` | Shared Windows 2000/XP serial KD workflow; a debug-enabled caller disk |
| `windows_xp_boot.star` | XP boot/GDB breakpoint workflow, distinct from serial KD |
| `reactos_kernel.star` | ReactOS guest kernel observation |
| `nbd_boot_smoke.star` | Generated BIOS sector proving direct NBD boot; requires QEMU/KVM |
| `code_watch.star`, `pe_calls.star` | Reusable bounded observation helpers, not commands |

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
