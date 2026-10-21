# IBM i IMD1 boot containers

Read-only native support for the observed IBM i optical `IMD1` profile, using
portable `storage.Reader` inputs. No host parser, extracted intermediate, guest
execution or proprietary fixture is required.

`Open(source, maximumEntries, maximumBytes)` reads the active `LIDDIR` directory
at byte 4096: a 32-byte header, counted 32-byte entries, and an invariant EBCDIC
`END ` marker. Component locations and lengths are qualified in 512-byte units.
Duplicate identities, directory/payload overlap, component overlap, out-of-range
extents, truncation and exhausted budgets fail explicitly. This profile was
independently inferred from original media; it is not a universal LIC format.

The entry's 64-bit `DeclaredAddress` preserves the address-shaped word at +16;
its role as an actual load destination has not been established. Flags and the
eight-byte tail remain uninterpreted. Stored sections are borrowed readers.

Automatic `ibmi_imd` browsing exposes `header.bin`, `directory.bin`,
`metadata.json`, and `components/<eight-hex-digit-id>.bin`. Components preserve
allocated stored bytes including padding. `decoding_complete=false` is explicit:
this is not decompression, relocation, object restoration, signature validation
or IPL support. The original full container remains readable.

A UDF BOOT2 descriptor can reference this image without a named QCDIML file.
The UDF reader exposes the referenced extent under `$metadata/bootN.extent.bin`.
XCOFF32 components have independent qualified header/section views. Qualified
packed components now open independently as `ibmi_packed` (see below).

Packed profile details and limits are in `PACKED.md`. Native saved-segment
COPYDIR browsing and omitted-page semantics are described in `COPYDIR.md`.

Tests use synthetic directories and payloads, including malformed framing,
conflicting extents and budget exhaustion. No implementation source or media
payload is embedded in fixtures.
