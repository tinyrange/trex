# Windows NE resource inspection

`windows.ne_resources(file)` reads a Windows New Executable's resource table
using the same native Go reader used by `windows.icon`. It returns records
with `type`, `name` (numeric identifiers use `#N`), `size`, `data` (bytes), and
`version`. This is read-only inspection, not loading or execution. It accepts
TinyRangeX file values; it does not need host paths or external tools.

`version` is `None` except for a recognized type-16 Win16 VERSIONINFO root
with a valid ANSI `VS_VERSION_INFO` key, DWORD-aligned fixed value, signature,
and lengths. The decoded record has four-component `file`/`product` lists,
`flags_mask`, `flags`, `os`, `type`, and `subtype`. StringFileInfo translation
or code-page interpretation is not implemented. An absent/unknown fixed
version is not an OS release assertion. Win16 resources are not Win32's
UTF-16 VERSIONINFO layout (which includes wType).

The executable envelope and table are strict: malformed MZ/NE signatures,
header/table bounds, alignment shifts, name lengths, resource counts,
unterminated tables and out-of-file payloads raise errors. A valid empty
resource table returns an empty list. Non-NE binaries raise errors rather
than being silently classified as NE. Existing PE inspection is unchanged.

Tests exercise shifted payloads, named/numeric IDs, independent file/product
versions, the Starlark binding, every truncated prefix of a valid example,
corrupt fields and fuzz inputs. The resource bytes remain unmodified.
