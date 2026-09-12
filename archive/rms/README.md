# RMS record framing

`VariableRecords` / `archive.rms_variable(file, attributes)` separates sequential
VAR and VFC records using the32-byte RMS attributes carried by ODS-2 and BACKUP.
The format byte must be2 or3 (sequential organization). Variable records have
a little-endian length word, that many bytes, and one alignment byte if odd.
FFFF marks unused bytes through the next512-byte boundary. The padding bytes
are not required to be zero. The no-span attribute forbids crossing a block.

VFC length includes the fixed control area; the declared maximum record size
applies to the data after that area. Control size is attribute byte15.
The API exposes control and data separately, as borrowed file views. It does
not apply printer controls, add line endings, or flatten record boundaries.
The publisher documents the distinction in the
[File Applications guide](https://docs.vmssoftware.com/guide-to-openvms-file-applications/)
and [RMS reference](https://docs.vmssoftware.com/vsi-openvms-record-management-services-reference-manual/).

Other sequential formats, relative/indexed organization and extended record
flags remain unsupported. An RMS format attribute does not guarantee that an
application actually wrote records: XDPS$GLYPHATTR.DAT and TERMTABLE.EXE on
both observed discs fail strict framing. Their raw BACKUP payloads are intact;
their binary formats still need investigation. No filename bypass is used.

Native REPL validation matches independent Starlark framing totals across
2,685 files and1,362,111 records from both discs. The four known mismatches
(two files on each disc) remain reported separately, not counted as successes.
A VFC command-file control verifies the first control area `018d` separately
from its command text. Synthetic tests cover padding, odd alignment, record
limits, control size, maximum length, truncation, no-span rules and borrowed
payload views. Other record formats and nested payload layers remain unfinished.
