# Native Intel XNU direct boot

## Verified scope

The private `scripts/run/macos_lion_cc.star` recipe boots the original Apple
Lion media's `kernelcache` and `BaseSystem.dmg` logical disk on native cc,
without executing boot.efi, adding a guest bootloader, or patching kernel/kext
instructions. Verified media is Lion 10.7.5 (11G63), Darwin 11.4.2,
XNU 1699.32.7. A fresh VM mounts its original HFS+ root, starts launchd PID1,
and displays the original single-user `-sh-3.2#` prompt. The root is read-only;
writes, if made by the guest, are confined to the existing snapshot overlay.

The installed-volume recipe and smoke additionally verify an unattended
Finder desktop and original Calculator computation (2+2=4). Recovery mode
remains the original single-user control. Other Intel macOS releases, slides,
APFS, RAM-disk boot, SMP and 3D acceleration are not claimed. The kernel logs
an ATA identify checksum warning.

All nested UDIF/XAR/HFS data remain portable borrowed views. No host mounting,
extraction or conversion tools are used; no intermediate disk image is written.
The format/handoff/device implementation is Go, with recipe and observations in
Starlark. There is no QEMU fallback or GPL-derived bootloader implementation.

## Installed volume and completed-setup disk state

The private recipe's `installed=True` reconstructs original BaseSystemResources
BOM entries and the original core and default English desktop package payloads
on a native 12GiB HFSX volume. It preserves forks, attributes, POSIX metadata and
hardlinks. Gzip/CPIO payloads use bounded, CRC-validated volatile RAM caches.
Default application payloads include Address Book, Automator, DVD Player, iCal,
iChat, iTunes, Mail, Safari, Podcast Capture, Java tools and X11. This is original
payload reconstruction, not a claim that every Apple installer postflight has
been replayed or every application has been tested.

`scripts/run/macos_lion_desktop.star` provisions completed-setup state directly
in the image. These records were established by completing genuine Setup
Assistant and then comparing the resulting disk, including enabling automatic
login through the original System Preferences UI:

* Complete original DefaultLocalDB, plus local account `trex`, UID501/GID20,
  home `/Users/trex`, a generated user identity and admin group membership.
* Original English and Non_localized home templates with correct ownership;
  cloned home files do not alias mutable template hardlinks.
* `.AppleSetupDone`, user SetupAssistant version/cloud-setup preferences,
  US language/input-source preferences and Pacific timezone.
* Original Lion four-byte salt plus SHA512(salt+password) ShadowHashData,
  `autoLoginUser=trex` and root-only `kcpassword`, observed from automatic login.
* ANSI identification for the synthetic USB keyboard (VID1234/PIDcc10),
  preventing Keyboard Setup Assistant from opening on first boot.

The deliberately known demo credential is **trex / liontest**. Automatic login
and this fixed credential are suitable only for isolated disposable demos, not
persistent or networked machines. Provisioning is image construction, not a
first-boot script, launchd job, terminal command or GUI wizard automation. The
original Setup Assistant executable remains unchanged. `provisioned=False`
retains an unconfigured installed-volume control.

A fresh normal startup exercises the original Apple ATA driver's MWDMA and
loads stock AppleSMC and DSMOS. The native EFI tree provides a fresh virtual
`system-id` UUID and truthful `TREX-CCPC` board identity, not an Apple hardware
identity. The PCI display is a synthetic 1234:cc02 device, using the original
IONDRV framebuffer path, not an impersonated Apple GPU. Its framebuffer is
1280x720 BGRX at physical 0xe0001000; no accelerated graphics are claimed.
ACPI describes its real memory aperture with a DWord resource when the full
root window is 32-bit, as required by the original Apple PCI resource consumer.

Native UHCI 1.1 at PCI00:03.0/BAR4/IRQ17 provides two low-speed synthetic HID
ports (keyboard and absolute pointer). The original Apple USB/HID drivers
consume bounded native descriptor DMA; no guest input driver is injected.
An inactive queue head's software tail remains owned by the guest driver.
The pointer API uses raw descriptor coordinates 0..32767. Stock Lion
IOHIDEventDriver-368.20 trims 7.5% from either end; the private smoke applies
that guest-generation-specific mapping in recipe coordinates, not hardware.

The native SMC is an ACPI APP0001 device at ports 0x300–0x31f with IRQ6. It
implements bounded key reads/writes, enumeration and metadata, including Lion's
fixed-width index/info commands. Unsupported keys return an error, not fabricated
data. `state().smc` records at most 64 command/key/length/result observations,
never key values. Wire facts were read from Linux `drivers/hwmon/applesmc.c` and
the original driver's actual transfers; Linux driver code was not copied.

`vmm.darwin_boot(..., smc_osk=bytes)` requires **explicit caller-supplied
64-byte** OSK material for protected original userspace. It is not bundled,
synthesized, scraped from a host, printed or included in reports. Without it,
OSK0/OSK1 are absent, protected loginwindow/fontd startup fails, and the
`diagnostic` mode remains blocked. “DSMOS has arrived” alone is not GUI proof.

From the private repository, using user-provided media and key paths:

```sh
go run ./trex/cmd/trex scripts/smoke/macos_lion_cc.star \
  /explicit/original/Lion-10.7.dmg /explicit/output/lion-desktop installed \
  /explicit/caller/osk-64-bytes
```

Alternatively call `desktop_smoke(source, output, smc_osk=bytes)` from an in-memory
script/REPL without creating an OSK file. The exact smoke constructs a fresh
image and VM, observes Finder/Dock/SystemUIServer without either setup assistant,
and checks that USB reports are still initial-only before sending any input.
It verifies the on-disk account/setup/autologin/keyboard records and writes
`<prefix>-desktop.png`. It then opens the original Calculator through Finder,
enters 2+2 and requires the exact result glyph4 (different from its initial0).
`<prefix>.png` and `<prefix>.json` record the application proof. The VM is
stopped, waited and closed. No terminal or injected application launcher is used.

## Portable intent and native board

```python
boot = vmm.darwin_boot(original_kernel_file,
                       command_line="-v keepsyms=1 rd=disk0s3 -s")
machine = vmm.machine(architecture="x86_64", memory=2048 << 20,
                      boot=boot, disks=[vmm.disk(original_disk_file,
                          bus="ide", unit=0, snapshot=True)],
                      display=vmm.display("capturable"))
vm = vmm.start(machine, cc.backend(acpi=True, hpet=True,
                                  pci_ide=True, ide_model="ich7-pata"))
```

The root partition in a real recipe must be derived from the complete map;
it is not always slice2. Lion BaseSystem's 2048-byte APM includes map and driver
entries before HFS+ slice3. The example above is specific to verified media.
Linux and Darwin boot intents are mutually exclusive. Darwin requires the
`boot.darwin` backend capability. Native cc requires Linux/amd64 KVM, one CPU,
x86_64, and no UEFI-image execution. QEMU rejects Darwin intent explicitly.
The default synthetic PCI IDE and legacy Windows CPU policy remain unchanged.

`ide_model="ich7-pata"` supplies Intel 8086:27df identification and relevant
register semantics over the existing native bounded ATA PIO/PRD-DMA engine.
Primary compatibility interrupts use IRQ14, while native INTA is routed through
ACPI _PRT to GSI16. These must not alias. Command/control and bus-master BARs
can be relocated. Decode, native interrupt-disable and timing-register masks
are honored; electrical cable timing is not simulated. The secondary channel
has no device (enabled reads return zero; disabled reads return 0xff).

## Handoff contracts

* `boot/darwin` selects the amd64 fat slice, verifies Apple's `comp/lzss`
  length and Adler32, and validates unslid Mach-O64 executable segments and
  LC_UNIXTHREAD. Kernel files and decoded caches are capped at 256MiB.
  Zero-VM-size file-only __CTF data is not loaded. Destination bounds are
  checked before copying segments or clearing their zero-fill tails.
* The native board supplies XNU boot_args v2/revision0, Apple's flattened
  device tree (not Linux FDT), EFI64 system/runtime/configuration tables with
  CRCs, and a sorted EFI memory map. Metadata fits the original low-1GiB
  bootstrap mapping and leaves at least 128MiB free RAM. The first usable
  range is conventional low memory, not the loaded kernel.
* Original pstart enters in flat 32-bit protected mode with IF and paging off,
  EAX pointing to physical boot_args. It performs its own long-mode transition.
  No external loader or injected transition code is run.
* EFI runtime pointers use XNU's high virtual mapping. Runtime functions
  return EFI_UNSUPPORTED rather than simulating persistent firmware variables.
  ACPI's device-tree configuration entry is named by its uppercase GUID,
  `8868E871-E4F1-11D3-BC22-0080C73C8881`, with a physical RSDP address.
* The single virtual Penryn CPU retains only accelerator-supported instruction
  features. The truthful CPUID hypervisor bit selects Apple's original virtual
  power-management implementation. FSB frequency is derived from the stopped
  VCPU's observed TSC frequency and PERF_STATUS multiplier, not a guessed
  host clock. Missing observations fail closed.
* The original console requires framebuffer base bit0 set to indicate a
  physical address after VM initialization. Exact `-v`/`-s` command-line tokens
  select FB_TEXT_MODE; the native capture uses the same 1280x720 BGRX buffer.

These wire formats and device semantics were implemented independently from
Apple's XNU 1699.32.7 ABI declarations/consumer behavior, AppleIntelPIIXATA
251.0.1 register use, and Intel ICH7 document 307013. Apple kernel/kext source
implementation bodies were not copied into the boot path. Tests use synthetic
Mach-O, EFI and disk fixtures, not distributed Apple payloads.

## Bounded native observations

`vm.extension("cc.v1")` is tied to the owning session and offers:

* `symbol(name)` and `symbols(prefix)`: original Mach-O kernel symbols; prefix
  selection is limited to 128 results. No prelinked-kext symbol table is implied.
* `symbolize(address)`: nearest preceding kernel symbol and unsigned offset,
  or None if no predecessor exists. It is not a function-extent or kext resolver.
* `read_virtual(address, size, page_table=0)`: read-only, nonwrapping
  0..65536-byte access, including cross-page reads. Zero uses current CR3;
  a nonzero value selects an explicitly caller-observed page-table root
  (raw CR3, including PCID bits). It changes only the inspector's register
  copy, never guest CR3 or memory. Unmapped roots fail; none is guessed.
  This permits kernel observations when a KPTI guest stops on an isolated
  userspace root. Obtain and validate the kernel root while it is mapped,
  using that kernel generation's original pmap layout.
* `disassemble(address, size=256, mode=64, page_table=0)`: read-only Intel-syntax instruction
  rows; size is 0..4096, mode is 16/32/64. Invalid or partial final instructions
  produce a terminal error row while preserving the decoded prefix.
* `breakpoint(address)`: native hardware execution breakpoint, with no guest
  instruction modifications. Address0 disables it.
* `state()`: existing bounded device/CPU state (including `ata_sleeping`) plus Darwin handoff metadata,
  full PCI IDE configuration and the last32 configuration transfers. Darwin
  transfers retain at most six readable frame-pointer links from transaction
  time; they are observations, not a guaranteed unwinder.

The private recovery smoke uses a panic breakpoint, the bounded original msgbuf
ring and allproc list, and verifies its generation-specific process-name offset
against the supplied kernel's own proc_name instructions. It polls for actual
HFS-root/launchd/sh readiness within120 seconds, not generic changed pixels.
The final recovery PNG permits separate visual verification of the original
shell surface; the recovery smoke does not send keyboard commands.

Run from the private repository (media paths must be supplied explicitly):

```sh
go run ./trex/cmd/trex scripts/smoke/macos_lion_cc.star \
  /explicit/original/Lion-10.7.dmg /explicit/output/lion-rootboot
```

Only final `<prefix>.png` and `<prefix>.json` evidence is written. The VM is
stopped, waited and closed after successful observation.
