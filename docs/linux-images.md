# Native Linux images and direct boot

Linux construction uses borrowed `storage.Reader` file views throughout. Go
implements formats; Starlark implements package selection, dependency policy,
module selection and initramfs composition. No host `cpio`, `apk`, `depmod`,
`mkfs`, mounts, extraction or intermediate payload files are used.

## Unix entries

`archive.cpio_build(entries)` and
`filesystem.ext4_build(entries, size, label="", uuid="")` accept the same
entry dictionaries:

```python
entries = [
    {"path": "bin/tool", "mode": 0o100755, "data": executable,
     "uid": 0, "gid": 0, "mtime": 0},
    {"path": "bin/alias", "mode": 0o100755,
     "hardlink": True, "target": "bin/tool"},
    {"path": "bin/sh", "mode": 0o120777, "target": "tool"},
    {"path": "dev/console", "mode": 0o020600, "major": 5, "minor": 1},
]
```

Modes are Unix on-disk bits, **not Go `fs.FileMode`**. Regular files default to
`0o100644`; data may be a file, bytes or string. Directories use `0o040000`,
symlinks `0o120000`, character/block devices `0o020000`/`0o060000`, FIFO
`0o010000`, socket `0o140000`, with permission bits added. Missing parents and
root `.` are synthesized as `0o040755`. IDs and timestamps are unsigned 32-bit.
Hardlinks must share mode/IDs/timestamp with their regular-file target. Chains
are resolved; cycles, missing targets, duplicates, traversal, NULs, absolute
paths and non-directory parents fail. Symlinks are never followed by readers.

Builders borrow payload files: retain their sources, and do not change their
contents during the lifetime of the resulting image. Deterministic metadata
and sparse zero padding are composed lazily; no full disk-sized allocation is
needed. Specify UUID as 32 hexadecimal digits; omission uses zero UUID, not a
random identity. Supply distinct UUIDs when mounting multiple constructed disks.

## CPIO and initramfs

`archive.cpio_build` emits deterministic Linux newc, including Unix metadata,
symlinks, devices and hardlink groups. File contents appear in the final record
of a hardlink group, as required by Linux's initramfs handling.
`archive.cpio(file)` exposes flat metadata dictionaries and borrowed payloads.
Its established reader also supports checksum newc, odc and concatenation;
device fields retain the existing names `rdev` and `rdev_minor`.

```python
load("@stdlib//unix:initramfs.star", initramfs = "build")

initrd = initramfs(entries, init = "#!/bin/sh\nexec /bin/tool\n")
```

The policy requires an executable regular `init`, supplies dev/proc/sys/run/tmp
and console/null nodes, and returns an **uncompressed** CPIO file. It does not
verify ELF/interpreter dependency closure, invent firmware, execute init,
compress the output, or configure a VM loader.

## Alpine policy in Starlark

`@stdlib//unix:alpine.star` supplies:

- `parse_index` / `read_index`: APKINDEX records, preserving repeated metadata
  fields; the archive reader requires a caller-trusted whole-file SHA-256.
- `select(index, pins, arch="x86_64")`: exact name/version pins. No mutable
  "latest" selection and no implicit repository/provider choice.
- `read_package(file, sha256, expected=None)`: APK v2's optional signature,
  control and data gzip members; `.PKGINFO`, compressed data SHA-256 and optional
  APKINDEX compressed-control SHA-1 checksum/identity/size checks; Unix payload
  metadata, links/devices, and original install scripts/triggers.
- `validate_dependencies`: bare/exact dependencies, conflicts, virtual provides
  and explicit external capabilities. Range/tilde constraints fail explicitly;
  this is **not a general apk version solver**.
- `install_plan`: dependency-before-dependent package order, merged entries,
  dependency graph and explicit effect records containing package/name/phase,
  original script file and trigger patterns. Cycles and ambiguous providers
  require explicit caller policy. Effects are **not executed**.
- `merge`: rejects scripts/triggers by default, rejects payload conflicts, shares
  directories only when mode/IDs agree, and allows explicit path modifications.

`archive.gzip_members(file, maximum_bytes, maximum_members)` is the small native
primitive needed for APK framing. It scans and validates each member's CRC and
length, retains only exact compressed-member file views, and rejects trailing
junk. Ordinary `archive.gzip` still handles concatenated streams independently.

**Trust boundary:** embedded signatures are retained, not verified. A freshly
computed hash from the same download does not authenticate its origin. Supply
an independently trusted full-file SHA-256; index checksums alone are not this
trust anchor. APK v3, installed-package database generation, package script
execution, trigger dispatch and APK signature verification are not implemented.

The pinned Apache-2.0 `tinyrange/pkg2` reference informed the declarative
package/effect boundary (see third-party-format-references.md). Its guest
package runner and relaxed version matching are not incorporated.

## Kernel and module policy

`@stdlib//unix:kernel.star` supplies `x86_header`, `select`, `modules` and
`build_initramfs`. Header inspection covers x86 boot protocol 2.04+ including
payload offset/length, load flags, initrd ceiling and command-line capacity.
`select` pairs `boot/vmlinuz-<flavor>` with one exact module release directory.
This is inspection/selection, not kernel relocation or VM memory loading.

`modules` reads `modules.dep`, `modules.builtin` and selected `modules.softdep`
records, accumulates repeated records, and resolves dependencies before their
consumers. Builtins need no file. Post softdeps are included and ordered;
unknown selected dependencies, malformed selected softdeps and cycles fail.
Crypto/device aliases use explicit caller pins, e.g.
`aliases={"crc32c": "crc32c_generic"}`: no hardware-dependent provider guessing.
Compressed `.ko.gz`/`.ko.xz`/`.ko.zst` files retain their original bytes.
Firmware, module decompression/loading and runtime init policy remain explicit.

`scripts/examples/linux_image.star:construct` composes authenticated package
records into a borrowed kernel, initramfs, ext4 root filesystem and effect plan.
It does not supply a bootloader, partition table, installed apk database or
claim that unapplied package effects have been installed.

## ext filesystem scope

The writer creates a fresh, journal-less ext4 volume with 4096-byte blocks,
256-byte inodes, extents, linear directories and backup superblocks/group
metadata. Regular files, directories, hardlinks, fast/long symlinks, devices,
FIFO/socket metadata, high UID/GID bits and multilevel extent trees are supported.
`size` is at least 8 MiB, 4096-byte aligned, with 32-bit block addressing and
at most 256 MiB retained allocation metadata. A short final group that cannot
hold metadata/data is rejected. A large image may hit the metadata bound before
the addressing limit. This builds fresh images; it is not an in-place editor.
No journal, metadata checksums, xattr values, ACLs, quotas, encryption or verity
are emitted by the writer.

`filesystem.ext4(file)` exposes flat entry records and lazy file views;
`auto(file).find(path)` uses the same reader. The reader covers ext2/3/4 layouts
with 1–64 KiB blocks, indirect pointers, sparse/unwritten extents, 64-bit group
descriptors, FLEX_BG, linear/indexed directory blocks and metadata checksum
seeds. CRC32C superblock/GDT/inode/extent/directory checksums and legacy GDT CRC16
are validated when relevant metadata is accessed. Checks do not authenticate
file payloads. Lazy file reads can fail after a directory was successfully listed.

Journal recovery is explicitly rejected; no replay occurs. Unsupported
layout-changing features, encrypted/inline/compressed inodes, malformed pointers,
cycles and configured traversal/index limits fail rather than being guessed.
Xattr/ACL semantics, non-Linux inode OS layouts, and dirty-image repair are not
implemented. Nanosecond/extended timestamp semantics are not exposed.

## Verification

The offline `linux` Starlark suite covers independent synthetic APK v2 framing,
whole-file/data/index checksum failures, metadata/effect retention, exact pins,
virtual providers/conflicts/cycles, CPIO/initramfs/ext4 composition and kernel
module closure. Native tests additionally check Linux final-hardlink emission,
lazy large extents, multiblock directories, independent bitmap accounting,
a hand-authored ext2 indirect/sparse layout, and independent CRC32C/CRC16
fixtures with superblock/GDT/inode/directory/extent corruption.

```sh
go run ./cmd/trex test.star linux
# Optional network-backed fixed-content construction smoke:
go run ./cmd/trex scripts/smoke/alpine_formats.star
```

The optional smoke uses fixed BusyBox 1.37.0-r20, musl 1.2.5-r12 and linux-virt
6.12.112-r0 bytes from Alpine v3.22. It checked **947 regular-file hashes** after
ext4 round-trip and each selected initramfs file, retaining all three BusyBox
effects. The initramfs was 2,164,456 bytes and the sparse ext4 image 256 MiB.
These hashes are regression identities, not independently established APK
signature trust. Packages can disappear from that mutable repository.

The format smoke is a construction/reader proof, not an e2fsck check. The
separate fresh-VM boot smoke below verifies Linux mount and runtime behavior.

## Direct Linux boot and fresh guest verification

```python
machine = vmm.machine(
    architecture = "x86_64", memory = 512 << 20,
    boot = vmm.linux_boot(kernel, initramfs = initrd,
                          command_line = "console=ttyS0,115200 rdinit=/init"),
    channels = [vmm.channel("serial", name = "console")],
)
```

`boot=None` retains firmware/disk startup. Direct boot borrows immutable files,
requires the `boot.linux` backend capability, and validates inputs before launch.
The kernel must be nonempty and at most 256 MiB; an optional initramfs must be
nonempty and at most 512 MiB. The command line is NUL-free and at most 64 KiB.
Kernel-specific boot protocol limits may be stricter. Files must remain alive
and unchanged until the VM closes. QEMU currently supports this intent only on
**Linux hosts with x86 guests**; it receives seekable anonymous inherited
kernel/initramfs descriptors, not extracted host payload files. Disks use the
existing block transport. No BIOS/UEFI bootloader is installed by this API.

`scripts/images/alpine.star:image` provides an executable policy using the fixed
packages above. It explicitly replaces the external initramfs-generator effect,
preserves other package effects unapplied, and supplies BusyBox/musl userspace.
For ext4 startup it natively decompresses the selected gzip modules before
boot, loads dependency-ordered virtio/ext4 modules, mounts `/dev/vda`, and
moves dev/proc/sys mounts before `switch_root` to the native ext4 root.

Run from the public checkout, with QEMU installed on Linux and network access:

```sh
go run ./cmd/trex scripts/smoke/alpine_boot.star both tcg
# Optional hardware acceleration:
go run ./cmd/trex scripts/smoke/alpine_boot.star both kvm
```

Fresh QEMU TCG runs verified both paths with `6.12.112-0-virt`:

- **Initramfs:** Linux unpacks native newc, executes `/init` as PID1, and
  responds to an interactive serial-shell challenge.
- **ext4 root:** Linux mounts the native journal-less 256 MiB ext4 image
  read/write and executes `/sbin/trex-init` as PID1 after `switch_root`.
  The guest checks root identity, high UID/GID values, hardlinks and symlinks,
  writes `/var/boot-proof`, then responds to the serial-shell challenge.
- Both guests sync and power off; QEMU exits cleanly. After closing the VM,
  the native ext4 reader verifies the guest-written bytes from the committed
  overlay, while the immutable base image remains unchanged.

The serial challenge response is not present verbatim in the echoed command.
Observation is bounded by deadlines, panic/failure detection and output limits.
This proves direct-kernel boot and Linux filesystem compatibility, **not a
firmware-bootable disk or a full Alpine installation**. OpenRC services,
installed apk database, arbitrary package effects and signature verification
remain outside this recipe. KVM is optional and not part of the TCG proof.
