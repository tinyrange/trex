# Offline memory inspection

Memory inspection separates portable Go access from Starlark interpretation.
`windows.memory_image(file, ranges=None)` borrows a physical capture; its
`address_space(directory_table_base, pae=False)` creates an i386 virtual view.
Neither needs a running VM, host debugger, mount, or extracted intermediate.
Keep the backing file unchanged for the lifetime of its views.

```python
load("@stdlib//inspect:memory.star", "read_structure", "read_list")

def inspect_processes(file, cr3, list_head, offsets):
    image = windows.memory_image(file)
    kernel = image.address_space(cr3, pae = False)
    layout = {
        "pid": (offsets["pid"], "uint", 4),
        "name": (offsets["image_name"], "cstring", 16),
        "cr3": (offsets["directory_table_base"], "uint", 4),
        "peb": (offsets["peb"], "uint", 4),
    }
    return read_list(kernel, list_head, layout, link_offset = offsets["links"])
```

Supply offsets and roots established for the captured kernel. This is not an
automatic Windows version detector: even related OS builds can have different
layouts. Process-specific pointers such as PEBs must be read through that
process's CR3, not whichever address space happened to be active at capture.

## Declarative structures

`read_structure(space, address, layout, address_bits=32)` maps names to
`(offset, kind, size)` tuples. Integer fields are little-endian with widths
1, 2, 4 or 8. `bytes` preserves the bytes; `cstring` stops at the first NUL
within the fixed field and preserves its byte string without code-page guessing.
`unicode` reads an eight-byte **32-bit Windows UNICODE_STRING descriptor**,
checks Length/MaximumLength, and follows its buffer for precisely Length bytes.
It is not an x64 descriptor. All other pointers remain integers until the
caller explicitly reads their targets. Field sizes are bounded to 64 KiB.

Every helper returns a dictionary with `value`, `complete`, and `fault`.
A failed structure includes only earlier fully read fields. Fault dictionaries
contain `kind`, `address`, and `message`; memory faults also include
`physical_address` and the paging `level`. Invalid layout arguments raise an
error instead of masquerading as evidence of a corrupt capture.

`walk_list(space, head, link_offset=0, pointer_size=4, maximum=4096)` walks a
circular doubly linked list and returns containing-object addresses. It checks
alignment, reciprocal links, cycles, and a hard entry limit. `read_list` combines
this with a declarative layout. An incomplete checked prefix is not a complete
process inventory, and a valid active list cannot prove that no unlinked objects
exist elsewhere in memory.

For example, loader-entry fields can be described as:

```python
module_layout = {
    "base": (0x18, "uint", 4),
    "size": (0x20, "uint", 4),
    "path": (0x24, "unicode", 8),
    "name": (0x2c, "unicode", 8),
}
```

These offsets were verified against our XP SP3 x86 capture, not all Windows
versions. Locate the loader-list sentinel from the process's PEB using a
capture-qualified layout. Preserve duplicate module basenames: side-by-side
assemblies can legitimately load different files with the same name.

## Missing memory and translation

- `read(address, size)` requires a complete read.
- `probe(address, size)` returns a native record with `data` (valid prefix),
  `complete`, and `fault`; unavailable bytes are never filled with zeros.
- `view(address, size)` is a lazy read-only file usable by existing `binary`
  readers. Creating it does not establish that its bytes are present.
- `translate(address)` returns `mapped`, `physical_address`, `page_size`, raw
  page-table `entries`, and `fault`. A present mapping can point outside the
  captured ranges. Faults distinguish `not-present`, `not-captured`,
  `source-error`, `invalid-address`, and `unsupported`.

Reads and file views are bounded to 64 MiB per call. Optional physical `ranges`
are `(physical_start, file_offset, size)` tuples, allowing packed sparse
captures. Omitted ranges cover the entire file; `[]` means nothing captured.
The reader does not infer RAM ranges, skip container headers, or parse crash
dumps. A QEMU raw physical-range capture can include device/ROM areas.

Go provides `memory.NewPhysical`, `memory.NewX86`, and bounded `memory.Read`;
both views implement `storage.Reader`. Present non-PAE 4 KiB/4 MiB and PAE
4 KiB/2 MiB translations are supported. PSE-36, x64 paging, software PTEs,
pagefile recovery and CPU permission validation are not implemented.

## Windows inventories

Load `read_vads`, `read_threads`, `read_drivers`, `read_handle_table`, and
`read_file_handles` from `@stdlib//windows:memory.star`. All return the same
`value/complete/fault` dictionaries as the generic readers. No new Go Windows
structure parser is involved.

| Reader | Input and required layout fields | Validation |
| --- | --- | --- |
| `read_vads` | Root pointer; `left`, `right`, `parent`, `start_vpn`, `end_vpn` integers | Untagged parent links, cycles, ordered nonoverlapping VPN intervals, entry bound |
| `read_threads` | List sentinel, embedded link offset, owner PID; `pid`, `tid` integers | Reciprocal links, owner PID, unique nonzero TIDs, optional expected count |
| `read_drivers` | Kernel loader sentinel; `base`, `size` integers; optional name/path fields | Reciprocal links, nonoverlapping ranges; separate per-entry mapped PE32 checks |
| `read_handle_table` | Table address; `table_code`, `next_handle`, `count` integers | Table hierarchy/alignment, slot bound, live-entry count |
| `read_file_handles` | Handle-table result, object-header/type/file layouts, body offset | Object type name `File` and FILE_OBJECT type 5, bounded Unicode names |

The VAD reader is for the XP-style binary tree with a null root parent, not a
later sentinel-root or tagged-parent representation. It returns **half-open byte
ranges** (`start <= address < end`) and retains raw caller fields such as flags.
It does not equate allocated virtual regions with captured/resident physical
pages or decode protection/private/mapped-file flags yet.

The handle reader supports XP's zero-, one-, and two-level TableCode encoding:
4 KiB table pages, eight-byte leaf entries, four-byte directory pointers, handle
stride four and low-three-bit object-header flags. It does not decode newer
encoded object pointers. The maximum bounds *examined slots*, including free
ones. File-handle filtering preserves aliases and raw access masks; a filename
may be empty, relative, or a device name. No canonical DOS-path reconstruction,
file-content extraction or related-file traversal is implied. `complete` for
file handles also requires the upstream handle inventory to be complete.

Driver-list `complete` describes the **inventory**, not the availability of each
driver's image bytes. When `verify_pe=True` (the default), each entry additionally
has `pe = {value, complete, fault}`. PE checks accept an exact SizeOfImage or a
page-rounded loader size and preserve the raw header value. Unavailable or
mismatched headers do not erase readable loader records. Kernel/HAL entries are
included, not only `.sys` files. Use an address space containing the relevant
session mappings when checking session drivers; System's CR3 may not contain
those mappings. A passing header check is not a trust/authenticity claim.

For illustration, these layouts and roots were checked against our captured
XP SP3 x86 kernel (5.1.2600.5512). They are evidence-qualified examples, not a
universal profile. Obtain matching type/layout information for another build;
Microsoft describes the relationship between type information and matching
symbol files in its [symbol documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-and-symbol-files).

```python
vad_layout = {
    "start_vpn": (0, "uint", 4), "end_vpn": (4, "uint", 4),
    "parent": (8, "uint", 4), "left": (12, "uint", 4),
    "right": (16, "uint", 4), "flags": (20, "uint", 4),
}
thread_layout = {
    "pid": (0x1ec, "uint", 4), "tid": (0x1f0, "uint", 4),
    "start_address": (0x224, "uint", 4),
}
handle_layout = {
    "table_code": (0, "uint", 4),
    "next_handle": (0x38, "uint", 4), "count": (0x3c, "uint", 4),
}
object_header_layout = {"type": (8, "uint", 4)}
object_type_layout = {"name": (0x40, "unicode", 8)}
file_layout = {
    "type": (0, "uint", 2), "size": (2, "uint", 2),
    "device": (4, "uint", 4), "related_file": (0x20, "uint", 4),
    "flags": (0x2c, "uint", 4), "name": (0x30, "unicode", 8),
}
```

In that capture, EPROCESS fields at `0x11c` and `0xc4` point to the VAD root and
handle table respectively. The thread-list sentinel is embedded at `0x190`,
its count at `0x1a0`, and ETHREAD links at `0x22c`. File bodies are `0x18` bytes
past their object header. The kernel loader list uses the module layout above;
its root was independently obtained from KDBG. None of these roots is a fixed
virtual address in the API.

```python
regions = read_vads(kernel, vad_root, vad_layout)
threads = read_threads(kernel, thread_head, thread_layout,
                       link_offset=0x22c, owner_pid=pid,
                       expected_count=thread_count)
drivers = read_drivers(session_space, driver_head, module_layout)
handles = read_handle_table(kernel, object_table, handle_layout)
files = read_file_handles(kernel, handles, object_header_layout,
                          object_type_layout, file_layout, body_offset=0x18)
```

## Validation and remaining artifacts

Synthetic tests cover paging, sparse inputs and malformed structures without
requiring Windows media. Against the private XP capture, these helpers matched
13 process records and 71 Explorer loader records exactly, with independent
mapped PE signature/size checks. Real-capture validation is non-PAE; PAE is
currently tested with synthetic fixtures. Captures and proprietary media are
not distributed with the library.

The four inventory readers recovered 1,281 VAD regions, 170 threads, 2,684 live
handles and 278 file-handle entries across all 13 processes. Thread and handle
counts matched their owning records, and all 71 Explorer modules fell within
recovered VAD intervals. The kernel loader list contained 76 entries: 75 mapped
PE checks passed in Explorer's address space; `fdc.sys` remained listed with an
explicit non-present-header fault. These are inventories of the linked/tree/table
objects, not proof that no unlinked objects exist. Zero- and one-level handle
tables were exercised by the capture; two-level tables are synthetic-tested.

Cross-checking linked inventories against independent object scans can follow.
Treat captures as sensitive: they can contain personal data and credentials even
when the analysis does not intentionally recover those fields.

## Process, region, thread and object context

`@stdlib//windows:memory_context.star` adds composable interpretation over these
inventories. All layout arguments are declarative field dictionaries; none
silently selects an OS build. Optional sub-artifacts have their own result
dictionaries so a paged-out stack does not discard a readable thread record.

| API | Result and boundaries |
| --- | --- |
| `read_process_context` | Kernel process fields plus PEB command line, image path and working directory. Handles normalized and relative parameter-buffer pointers. Parent PID and creation FILETIME remain raw facts; a reused or absent parent PID is not an identity proof. A null PEB has no user parameters. |
| `describe_vad` | Private/mapped classification, a caller-defined protection-code lookup, and control-area backing-file fields. Private short VADs never dereference long-VAD tails. Unknown protections remain `None` with the original numeric code. Region protection is not proof of per-page hardware permissions. |
| `read_thread_context` | State and start-address attribution plus a saved-trap-seeded EBP chain. Selects user TEB or kernel stack bounds based on trap CS. Saved trap state is not necessarily current CPU state. |
| `walk_frames` | Bounded, monotonic conventional x86 EBP links and saved return addresses, with optional module/RVA attribution. It does not scan arbitrary words for plausible code pointers or unwind FPO/optimized frames. Even a null-terminated chain is not proof of a complete call stack. |
| `module_at` | Every covering module/RVA, preserving overlap ambiguity. An unattributed address alone is not evidence of suspicious memory. |
| `read_object_handles` | All object types, raw access, optional object-manager names and caller-selected body fields. Unknown/unselected types remain in the inventory without a fabricated body. Name/body failures are per-handle results. |
| `read_object_path` | Leaf-to-root object-manager directory components; bounds/cycles/unnamed ancestors produce partial results, not fabricated absolute paths. File device paths can identify named-pipe handles. |
| `read_key_path` | Leaf-to-root KCB names with parent-cycle detection and compressed/UTF-16 name-block decoding. This reads registry key names, not values. |

For the same capture-qualified XP example, process context used EPROCESS parent
PID `0x14c`, creation FILETIME `0x70`, and PEB `0x1b0`. PEB parameters are at
`0x10`; parameter fields are flags `0x08`, directory `0x24`, image path `0x38`
and command line `0x40`. Pass Unicode fields as eight-byte descriptors and flags
as a four-byte integer. These can contain sensitive data; reports should remain
private by default.

```python
load("@stdlib//windows:memory_context.star", "read_process_context", "describe_vad")

context = read_process_context(kernel, process_space, eprocess,
    {"parent_pid": (0x14c,"uint",4), "created": (0x70,"uint",8),
     "peb": (0x1b0,"uint",4)},
    {"parameters": (0x10,"uint",4)},
    {"flags": (8,"uint",4), "directory": (0x24,"unicode",8),
     "image_path": (0x38,"unicode",8), "command_line": (0x40,"unicode",8)})

region = describe_vad(kernel, vad,
    {"private_bit": 31, "protection_shift": 24, "protection_mask": 31,
     "protections": protection_table, "control_area_offset": 0x18},
    {"file": (0x24,"uint",4)},
    {"type": (0,"uint",2), "name": (0x30,"unicode",8)})
```

The caller supplies `protection_table` rather than inheriting guessed meanings.
The local capture example recognizes the basic read/write/execute/copy-on-write
codes and retains one extended code (12) numerically without guessing its
modifier. Other VAD flags remain raw.

Thread layouts need `state`, `start`, `trap`, `teb`, `stack_limit`, `stack_base`
and optionally `win32_start`. Trap layouts need `eip`, `ebp`, `cs`, `esp`; TEB
layouts need stack bounds. `states` is an explicit numeric-to-label dictionary.
Module inputs are lists of `base`, `size`, and optional `name`/`path` records.
If attributing via a file-backed VAD rather than a validated loader entry, retain
that weaker provenance in the supplied module record.

Generic handle layouts require header `type` and backward `name_offset`, an
object-type Unicode `name`, and a name-info `directory` pointer/Unicode `name`.
`body_layouts` maps type names to chosen fields: e.g. Event signal state, Section
segment pointer, Key KCB pointer, or File name/device. `read_key_path` takes
KCB `parent`/`name` pointers and a name-block `compressed`/`length` layout plus
the inline-name offset. Compressed names zero-extend bytes to UTF-16 units,
rather than assuming UTF-8 or a host code page.

## Network endpoints

`read_endpoints(space, table, buckets, layout, maximum=16384)` reads an explicit
hash-bucket array of singly linked IPv4 endpoint records. Required layout fields
are `next`, `pid`, `local_address` (four bytes) and `local_port` (two network-order
bytes). Optional `remote_address`/`remote_port` use the same encodings. Protocol
and state fields are retained as caller-selected raw metadata. It checks cycles,
duplicate objects across buckets and total entry bounds.

This is not automatic tcpip.sys discovery or a pool scan. Root addresses and
layouts must be established for the matching driver. In our no-NIC XP capture,
the driver RSDS identity matched Microsoft `tcpip.pdb` GUID
`1B7E3279-92FD-49DC-AEBA-AD2FC8F7BBF4`, age 2. Native symbol parsing located
`AddrObjTable`, `AddrObjTableSize`, and `TCBTable`; captured roots were null and
the address-object bucket count zero. The API reports this as **unavailable /
uninitialized**, not a successful empty inventory or proof of no historical
network activity. Positive IPv4/port parsing is currently synthetic-tested;
nonempty real XP endpoint layouts and active connection-state interpretation
still need a network-enabled capture.

## Cached-file bytes

`read_cache_views` reads a **caller-verified flat VACB pointer array**. Supply
shared-cache `file_size`/`vacbs` fields and VACB `base`/`owner`/`offset` fields.
It checks owner and file-offset agreement and masks the low view-offset bits
that carry active-count metadata. Null VACBs produce explicit uncached ranges.
This does not interpret multilevel VACB trees or data/image-section prototype
PTEs; do not apply a flat layout to a different cache generation/representation.

`recover_cached_file(space, views, maximum=16<<20)` reads each view page by page.
Its result contains `extents` with file offsets and bytes, `gaps` with faults,
and `data`. Only a complete contiguous recovery returns `data`; partial recovery
sets it to `None` while retaining later resident pages after a gap. No zero-fill,
disk fallback or implicit extraction occurs. Bounds limit total recovered range
size, not just the number of resident bytes. Cached bytes may be newer than
durable disk contents.

The XP validation selected only benign `stdole2.tlb`: its complete 16,896-byte
cached file was recovered and parsed natively as a PE containing one type library.
Registry/credential-file contents were not recovered. The recovered file and
detailed context report remain private final outputs, not distributed fixtures.

## Extended capture results

The context readers recovered process metadata for all 13 processes, backing-file
references for 541 of the 1,281 VADs, thread metadata for all 170 threads and
293 saved return-address frames from 66 threads. Stack results independently
reported 25 absent trap contexts, 78 non-present-page stops and 67 null-terminated
chains (one empty). They also classified all 2,684 handles into 19 object types,
decoded 349 registry-key paths and 381 object name-info records, and identified
46 file handles through named-pipe device paths. These counts preserve aliases;
they are not unique-object or unique-file counts.
