# SRD1 XML-property wire entries

The string primitive is based on the Windows 11 StateRepositoryClient image
with PDB identity `E59E7033-C493-E066-C1B2-DD68AA452AD3`, image age 1.
Inspection used the native PE reader, matching PDB and amd64 disassembler.

All integers are little-endian. The header is `SRD1`, a uint32 total size,
and a uint32 entry count. An entry has uint32 extent, uint32 type, uint16
key byte length, terminated UTF-16LE key, and the type-specific payload.
For string type 14, the payload is uint32 byte length followed by terminated
UTF-16LE. Entries have no alignment padding. Limits observed in the reader
and writer are 1024 entries, 65534 key bytes, and 1048576 value bytes.

Relevant native functions and RVAs:

- `WinRTReader::Deserialize`, 0x205b0: header validation and pair iteration.
- `WinRTReader::ProcessPair`, 0x20a40: key and variable data extents; duplicate
  map insertions fail rather than silently replacing an earlier entry.
- `Writer::AddString`, 0x22c5c: type 14.
- `Writer::SizeOfPair`, 0x22e88: string entry size is 14 + key bytes + value bytes.
- `Writer::StringSize`, 0x22f88: string length includes the UTF-16 terminator.

`EncodeStrings` and `DecodeStrings` cover string-valued wire primitives.
`Encode` and `Decode` additionally support nested dictionaries (type 21) and
arrays of dictionaries (type 42). A map payload is a uint32 byte length followed
by a complete SRD1 dictionary. A map-array entry inserts a uint32 count between
its type and key length, then stores a uint32 size and complete SRD1 value for
each child. Unsupported types are rejected.
The wire-layout test is independently specified from this layout; it is not
a captured native-producer fixture or proof of guest interoperability.

Manifest mapping must be verified separately. Public AppExtension properties
represent element text through a nested PropertySet with a `#text` key:
[Microsoft's property documentation](https://learn.microsoft.com/en-us/windows/msix/desktop/custom-props-app-extensions).
The matching DesktopShellExt consumer at 0x861a0 likewise looks up the named
property as a PropertySet, then looks up `#text`. A flat string dictionary is
therefore not sufficient for these shell-host properties.

The nested-property consumer is not an inference from a misleading folded
symbol name: DesktopShellExt wrapper 0x5f2a4 calls interface slot 0x58. The
matching WindowsUdk.ShellCommon IAppExtension vtable at 0x4ee298 has
`get_ExtensionProperties` (0x30710) in that slot. Its implementation calls
0x30780 -> 0x30810 -> 0x25c3a4. StateRepositoryClient's exported conversion
wrapper calls 0x20850 -> 0x205b0. No hierarchy conversion was identified in
those wrappers. The conversion is in the previously unexamined type-21 branch
of `WinRTReader::CreatePropertyValue`, 0x1f67d: it calls `Deserialize` at
0x1f6a0 and checks that the entire child extent was consumed at 0x1f6cb.

The producer independently confirms this encoding. Matched
AppXDeploymentExtensions.OneCore PDB `BDE5418F-DBFE-B38C-24F5-0231D4E23C62`,
image age 1, contains `XmlWriter::AddElements` at 0x22b9e0. A single child is
recursively serialized at 0x22bc37, then stored with type 21 at 0x22bca2.
Repeated children use `Writer::AddArrayOfMap` at 0x22bf1b; that function writes
type 42 at 0x188889. `XmlWriter::AddText` writes a type-14 `#text` entry at
0x22c6e4. The earlier assumption that the native decoder was flat was incorrect.
