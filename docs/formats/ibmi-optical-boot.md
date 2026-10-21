# IBM i optical boot inspection

UDF directory traversal alone does not identify every IPL payload. Native UDF
support now reads ECMA-167 BOOT2 descriptors from the bounded recognition
sequence and exposes raw descriptors, metadata and declared byte extents:

- `$metadata/boot0.json`
- `$metadata/boot0.descriptor.bin`
- `$metadata/boot0.extent.bin`

This uses the descriptor's 2048-byte sector address and byte length, not file
names or payload signature carving. Reserved framing, source bounds and
recognition termination are checked. A malformed recognized descriptor fails.

A qualified IMD1 extent opens as `ibmi_imd`; its counted LIDDIR table exposes
stored component ranges. A qualified 0x01df component can then open as
`xcoff32`, with metadata and raw stored section views. Plain bytes, wrapped
components, unknown flags and loader semantics are not silently promoted to
fully decoded executable content. Qualified packed components now expose a lazy
`expanded.bin` view via `ibmi_packed`; its instruction-derived grammar and limits
are documented in `archive/ibmiimd/PACKED.md`. Expansion is not relocation,
authentication, object restoration or a demonstrated IPL chain.

Portable Go APIs are in `filesystem/udf`, `archive/ibmiimd` and `binary/xcoff`.
The public engine includes synthetic regression fixtures only. Private media
selection and whole-image verification remain in the recipe repository.

References: ECMA-167, third edition, part 2, section 9.4 (Boot Descriptor);
IBM AIX XCOFF file-header, auxiliary-header and section-header documentation.
Observed IBM i IMD1/LIDDIR layouts were independently inferred from input bytes;
no proprietary payloads or third-party parser code are included.
