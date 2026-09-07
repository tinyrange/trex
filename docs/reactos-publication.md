# ReactOS image construction

trex builds complete installed ReactOS disks directly from caller-supplied ISO,
single-ISO ZIP or single-ISO 7z media. Construction is native and in memory:
archive/ISO/CAB reads, registry hives, SAM/SECURITY records, DLL registration,
profiles, shortcuts and FAT32/MBR layout. QEMU is used only for the finished
image smoke. No Windows registry templates or private modules are required.

## Build and smoke

From a trex checkout with its Go dependencies and QEMU available:

```sh
go run ./cmd/trex scripts/images/reactos.star /path/to/media.zip reactos.raw

go run ./cmd/trex scripts/smoke/reactos.star \
  reactos=/path/to/ReactOS-0.4.16-i386.zip output=local/reactos-0416

go run ./cmd/trex scripts/smoke/reactos.star \
  reactos=/path/to/reactos-bootcd-0.4.17-dev-755-gdbdf684-x86-gcc-lin-dbg.7z \
  output=local/reactos-0417

go run ./cmd/trex scripts/smoke/reactos_custom_account.star \
  reactos=/path/to/ReactOS-0.4.16-i386.zip output=local/reactos-custom
```

The smoke uses the QEMU i386 ReactOS profile, KVM, 512 MiB RAM, an IDE disk
with an in-memory snapshot, and disabled networking. Each fresh run checks
generated identity/account/profile coherence, the desktop, guest version,
Notepad, Calculator and Minesweeper. JSON and HTML reports include five
screenshots. Inspect the application-specific surfaces: framebuffer changes
alone do not prove that an application succeeded.

The custom-account smoke uses a different machine identity, adds a passworded
`Builder` account and administrators membership, and selects it for autologon.
It reuses the same smoke function and hardware profile. Passwords are checked
offline but are not included in reports.

## Declarative accounts and policy

```python
load("@stdlib//windows:identity.star", "machine_identity")
load("@stdlib//windows/reactos:security.star", "workstation_security")
load("@stdlib//windows/reactos:image.star", "reactos_disk")

def build(source):
    identity = machine_identity("MY-REACTOS")
    security = workstation_security(
        identity["sid"], identity["computer_name"],
        administrator_password = "test-only",
    )
    security["users"][0]["full_name"] = "Image Administrator"
    security["domain_policy"]["minimum_password_length"] = 6
    return reactos_disk(
        source, security = security,
        computer_name = identity["computer_name"],
        autologon = "Administrator",
    )
```

`workstation_security(domain_sid, domain_name, workgroup="WORKGROUP",
administrator_password="", creation_time=None)` returns a fresh mutable dictionary. It is explicit
recipe policy, not a saved hive. `security_database(specification,
hive_format=None)` also works independently of the image builder.

| Field | Meaning |
| --- | --- |
| `domain_sid`, `domain_name`, `workgroup` | Account-domain identity and workstation workgroup. In the image recipe these must agree with the selected machine identity. |
| `users` | Names, RIDs, passwords, named account flags, primary group, optional profile strings, expiry, password-set time and hourly logon schedule. |
| `groups` | Named account-domain groups, RIDs and explicit user RID membership. Both directions of membership are generated from this list. |
| `aliases` | Named built-in local groups, RIDs and explicit member SIDs. |
| `rights` | Per-SID named logon rights and privileges with named enablement attributes. |
| `domain_policy` | Named fixed-record fields for password ages/history, lockout intervals/threshold, allocation of the next RID and domain state. |
| `descriptors` | Per-object owner/group SIDs and an explicit allow list using named `read`, `all` and, for users, `change_password` access. Individual users/groups/aliases/policy accounts can override their descriptor. |
| `audit`, `quota` | Named LSA audit/quota record fields; defaults are visible in the recipe. |

A new user must have a distinct name/RID, belong to its declared primary
group, and fall below `domain_policy.next_rid`. Local membership references,
duplicate policy accounts/privileges and unknown fields/flags are rejected.
The checked-in custom-account smoke is a complete example of adding a user.

Timestamps are NT FILETIME ticks. Creation/password-set times default to the
portable clock; pass `creation_time` explicitly for reproducible construction.
password-age and lockout intervals are negative relative NT time values.
`must_change_password=True` explicitly emits a zero password-set time. That
user needs an interactive password change and is not suitable for an unattended
autologon smoke. The observed 0.4.16 SAMR user-information path calculates the
password-expiry time from the domain age policy even when the no-expiry account
flag is encoded. Use a construction timestamp compatible with the intended
guest clock and password-age policy; an old fixed timestamp can expire ordinary
users while the built-in Administrator still logs on. The builder does not
patch the guest authentication implementation to change that behavior.

Current passwords use the legacy LM/NT fields and are limited to 14 ASCII
bytes by the LM-compatible constructor. This is preservation/test-image
policy, not a modern authentication recommendation. The default Administrator
has an empty password, networking is disabled in the smoke, and autologon
stores the selected password in the image. Do not use real credentials or
expose these test images to an untrusted network.

## Format and module boundaries

- `windows/reactos_records.go` owns the split SAM fixed records and the LSA
  counted-string, audit, quota, modification, privilege and logon-hours
  encodings. Go structs name each field, including required alignment.
  `windows.reactos_record(kind, fields)` is the Starlark adapter. Unknown
  fields, invalid revisions, integer overflow and invalid record sizes fail.
- `windows/reactos/security.star` owns account defaults and policy; it uses
  existing SID/ACL/security-descriptor and cryptographic primitives.
- `media.star` discovers the setup tree and supplies one INF destination map
  for installed-file population and registration.
- `registry.star` describes hardware and shell policy and executes the
  selected media exports in the self-registration emulator.
- `profiles.star` uses one relative directory specification for each declared
  profile; `shortcuts.star` interprets media shortcut declarations.
- `image.star` composes those pieces into `reactos_disk(file)`; the native
  entry point does not depend on host paths, processes or sockets.

New combined CDs use `/i386` setup inputs and require `rosload.exe`; older CDs
use `/reactos`. The builder seeds the logon desktop keyboard preload and sets
the shell to `explorer.exe`. There is no first-boot registration batch.
INF registration bits independently select `DllRegisterServer` and
`DllInstall`; incomplete execution or a failed HRESULT stops construction.

The public emulator supports the registration paths exercised here, not every
ReactOS registrar. Static registration resources remain the baseline for
other media controls. Activation contexts currently cover file-backed
zero-flag manifests; unsupported resolution modes stop explicitly.

## Verification and provenance

```sh
go test ./...
go run ./cmd/trex test.star
```

Focused tests cover record layout, validation, default and customized hive
contents, password hashes, group/alias membership, profile paths and INF
registration flags. Fresh public smokes pass for 0.4.16 `release-0-g822e864`,
0.4.17 `dev-755-gdbdf684`, and the additional passworded-account variant on
0.4.16: 18 checks, zero disk-command errors, and 15 reviewed screenshots.
The 0.4.17 build is a development snapshot, not a release. Desktop/application
smoke does not claim coverage of every operating-system subsystem.

No GPL implementation code, OS media or opaque private SAM/SECURITY templates
are included. Split-record layout observations are serialized directly, and
access/privilege semantics use the Microsoft
[MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380)
and [MS-LSAD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/93798a19-a71a-4d32-a5bc-f44e2c49b2ea)
contracts. The LZMA2 framing follows its
[published description](https://sourceforge.net/p/sevenzip/discussion/45797/thread/09814bb2/);
the small compressed fixtures come from the public-domain XZ Utils test corpus.
