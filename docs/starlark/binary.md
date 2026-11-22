# Binary data in trex Starlark

The `binary` namespace handles bounded byte parsing and construction while
preserving lazy `file` inputs. Choose an API based on access pattern rather than
converting every input to `bytes`.

`binary.slip_encode(value, maximum=65536)` returns RFC1055 wire bytes with
leading/trailing END and escaped END/ESC bytes. `binary.slip_decode(value,
maximum=65536)` returns `(packets, remainder)`, ignoring empty frames. Prepend
the unchanged partial wire packet in `remainder` to the next channel read;
even an escape split across reads is retained. Malformed escapes and oversized
packets fail explicitly. Decoding accepts at most16MiB per chunk and each
packet limit is1..1MiB.

## Scalar matrix

| Family | Names | Widths | Endianness |
| --- | --- | --- | --- |
| Unsigned integers | `u8`, `u16le`, `u16be`, `u32le`, `u32be`, `u64le`, `u64be` | 8, 16, 32, 64 | Explicit except for one-byte values |
| Signed integers | `i8`, `i16le`, `i16be`, `i32le`, `i32be`, `i64le`, `i64be` | 8, 16, 32, 64 | Explicit except for one-byte values |
| Floating point | `f32le`, `f32be`, `f64le`, `f64be` | IEEE-754 binary32 and binary64 | Explicit |

The same scalar names appear in five contexts:

```starlark
# Encode one value as immutable bytes.
raw = binary.u32le(0x12345678)

# Read one field from bytes, a byte view, or a lazy file.
value = binary.read_u32le(source, offset = 0x24)

# Sequential decoding and encoding.
cursor = binary.cursor(source)
kind = cursor.u16le()
builder = binary.builder()
builder.u16le(kind).i32le(-7)

# Patch an already reserved record.
record = binary.builder()
record.reserve(16)
record.patch_u32le(8, payload_offset)

# Access emulated guest memory without temporary byte values.
capacity = machine.read_u32le(pointer)
machine.write_u32le(pointer, required)
```

Encoding is exact. Unsigned inputs must be non-negative and fit their width;
signed inputs must fit the corresponding two's-complement range. No operation
implicitly truncates or masks. Deliberate wrapping remains visible:

```starlark
machine.write_u32le(address, result & 0xffffffff)
```

Bounds errors identify the operation, offset, width, and available data. A
direct scalar read from a file reads only the scalar width.

## Sequential parsing

`binary.cursor(source, offset=0)` maintains an offset and provides scalar
methods plus:

- `bytes(size)` reads materialized bytes and advances.
- `skip(size)` advances after checking bounds.
- `seek(offset)` moves to an absolute offset.
- `align(alignment)` advances to the next aligned offset.
- `offset` and `remaining` report state.

Use one cursor for a multi-field sequential record. Do not create a cursor and
slice merely to read one random field; use a direct `binary.read_*` operation.

## Construction and patching

`binary.builder(capacity=0, limit=512MiB)` accumulates bounded in-memory output.
Scalar append methods return the builder, allowing chaining. `append(value)`
accepts binary values, `reserve(size, fill=0)` returns the reserved offset,
and `align(alignment, fill=0)` pads output.

`patch(offset, value)` copies arbitrary bytes into an existing range. Typed
`patch_u32le` and related methods encode and patch one scalar with the same
range rules as append. Patches never grow the builder.

`bytes()` returns an immutable snapshot. `file()` returns a random-access file
snapshot. Both currently copy builder storage, so builders should represent
bounded records rather than complete disk images.

## Fixed layouts

Compile reusable fixed records with `binary.layout(format, names=None)`. A
format starts with `<` for little endian or `>` for big endian and supports
`b/B`, `h/H`, `i/I`, `q/Q`, and fixed byte strings such as `16s`.

```starlark
descriptor = binary.layout(
    "<BBHIIII",
    names = ["revision", "reserved", "control",
             "owner", "group", "sacl", "dacl"],
)

header = descriptor.decode(source, offset = 0)
if header.revision != 1:
    fail("unexpected descriptor revision")

encoded = descriptor.encode({
    "revision": 1,
    "reserved": 0,
    "control": 0x8004,
    "owner": 20,
    "group": 0,
    "sacl": 0,
    "dacl": 32,
})
```

Encoding accepts a decoded record, a dictionary keyed by field name, or a list
or tuple in field order. Fixed byte strings must have exactly the declared size.
Use layouts where named fields improve a stable record; isolated scalars remain
clearer with direct methods.

## Views, text, and encodings

`binary.view(value, offset=0, size=remaining)` creates an immutable lazy window.
Slicing a byte view with step one remains a view. Explicit `bytes()` calls
materialize the selected range. Views support bounded search and comparison.

`binary.encode(text, encoding="utf8", nul=False)` supports ASCII, UTF-8,
UTF-16LE, UTF-16BE, and explicit IBM037 (`ibm037` or `cp037`). IBM037 is a chosen rendering, not detected saved CCSID. `binary.text(value, encoding="utf8", nul=False)`
performs the reverse conversion with validation. Hex and Base64 conversion use
`binary.hex`, `binary.base64`, and `binary.decode` with explicit output limits.

Use `binary.concat` and `binary.extents` for lazy composition. Do not join large
files by converting them to bytes or by extracting intermediate host files.


## IBM i DASD inspection

`binary.ibmi_dasd_index(source,ranges,maximum_pages=1048576)` indexes9-sector
page envelopes intersecting explicit `(offset,size)` ranges. The returned
record exposes `matches(address)` (physical offset and data/header/sidecar
files), `page_address(offset)` for a physical frame and `file(address,size)`
for uniquely backed SLS storage. Missing and
duplicate pages fail; omitted ranges are not assumed empty. Nonzero sector
controls must agree before displaced words are restored. Unstamped bytes
remain unchanged. This observation does not select filesystem generations.

`binary.ibmi_lid_directory(source,offset=0,maximum_entries=4096)` validates
the counted LIDDIR framing and returns metadata dictionaries. Its sector
fields are not interpreted as physical extents. See
[the DASD format note](../formats/ibmi-dasd.md) for the observed generation.

`binary.ibmi_procedures(source,name,maximum_matches=64,
maximum_bytes=67108864)` finds exact IBM037 names in qualified native kind2
procedure descriptors. It returns record offsets and entry addresses; partial
names and unqualified strings are excluded. It does not infer a load map.

## POWER instruction inspection

`binary.ppc_instructions(source, offset=0, size=256, address=0,
byte_order="big", maximum=4096)` returns bounded decoded records using the pinned
portable Go POWER decoder, without executing code or invoking a host disassembler.
`address` is the address of the first selected byte, not a base to which `offset`
is added. File/bytes/string/byte-view sources and both byte orders are supported.

Ranges are four-byte aligned and limited to 64KiB. Records contain source offset,
64-bit address, raw first word, length, opcode, GNU text, typed operands and a
resolved branch target where present. Absolute branch targets are sign-extended
for 64-bit execution; GNU display text retains upstream 32-bit absolute label
spelling. Prefixed instructions consume eight bytes. Unknown words and truncated
prefixes carry an explicit error and advance by four bytes. Successful decoding
alone does not establish that bytes are executable code. This API does not infer
load addresses, recover control flow, apply relocation or emulate POWER state.

`binary.ppc_census(source, ranges=None, byte_order="big", samples=4,
maximum=1<<30, flow=False)` merges a whole-range opcode histogram in Go: decoded
mnemonic counts, `mfspr`/`mtspr` SPR numbers, absolute branch targets per 64KiB page
and undecodable words keyed by
primary/extended opcode with a few sample words and source offsets. Pass
`flow=True` with one range per procedure to count only words reachable from the
range's first nonzero word through fallthrough and in-range direct branches and
calls; this keeps literal pools and strings after unconditional transfers out of the census.
The census does not establish that a range is code or what an unknown encoding does.

`binary.locate_table(source, addresses, high=0xffffffff, top=10)` finds where a
table image belongs: given addresses that must hold pointers (such as TOC slots
read by code), it returns bases at which the source has an aligned doubleword
with the given high word at many of them, ranked by hits. `word_mask=` and
`word_value=` match four-byte words instead, such as branch-table entries.
