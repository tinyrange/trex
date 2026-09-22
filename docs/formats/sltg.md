# SLTG type-library registration metadata

`windows.pe(file).typelibs` reads both MSFT and SLTG `TYPELIB` resources. SLTG uses a linked block directory, one block per type, a final library block, and a shared name table. The parser follows physical block order through the directory links, validates the complete chain and lengths, and checks each type's index identity against the library directory.

The result has the same registration metadata as MSFT: library GUID, name, description, version, language, registration LCID, flags and system kind; each type supplies its GUID, name, kind and flags. Dual interfaces have dispatch kind. Localized SLTG libraries use neutral registration LCID while retaining their source language. Member signatures and compressed per-member documentation are outside this metadata API.

Malformed chains, truncated strings/blocks, mismatched type counts, and names outside the library block fail explicitly. All parsing uses the owned PE snapshot and requires no temporary files or external type-library loader.

Format facts were checked against the `SLTG_*` structures and reader in [Wine's typelib.h](https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h) and [typelib.c](https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c). The Go metadata parser is independently implemented. Synthetic tests exercise a directory chain whose logical indices differ from physical order, dual flags, localized LCID, truncation at every byte, cycles, and invalid offsets.
