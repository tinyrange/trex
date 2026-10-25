# Office Click-to-Run streams

`Open(database, stream)` reads the full-stream UnityDB/`.dat` pair natively.
It is a container reader, **not an Office installer**. Source handles are borrowed.
It does not execute SQL, extract files, run ODT, apply deltas or activate Office.

## Observed format

Verified against Microsoft 365 Apps x64 Current Channel `16.0.20527.20088`,
neutral (`s640.cab`) and en-US (`s641033.cab`) metadata from Microsoft's CDN.
The private source recipe pins the CABs and original streams by SHA-256.

UnityDB starts with `C2RxUnityDB` followed by FF. The supported header has:

| Offset | Representation | Meaning |
| --- | --- | --- |
| 12 | LE16 | format 0x30 |
| 14 | LE32 | fixed header length (80) |
| 18 | LE16 | extra header string bytes |
| 20 | LE32 | compressed SQL offset |
| 24 | LE32 | compressed SQL length |
| 28 | LE32 | digest offset (48) |
| 32 | LE16 | digest length (32) |
| 34 | LE16 | supported encoding marker (1) |
| 36 | LE32 | decoded SQL length, including optional final NUL |
| 40–47 | bytes | zero in supported format |
| 48–79 | bytes | decoded SQL SHA-256 |

A single zlib stream contains generated schema-5 SQL. The decoder tokenizes only
literal INSERT data, with SQL doubled-quote escaping; CREATE/PRAGMA/transaction
statements are skipped, never executed. All tables remain inspectable through
`archive.c2r_database`. The stream reader validates the tables it uses.

Files reference Paths/Directories, package ownership, and whole-file hashes.
Blocks reference a logical file offset and decoded size. BlockSource references
the compressed stream offset and stored size. Both block records identify the
**stored** SHA-256 digest; it is not the decoded block hash. The Files digest is
independent and covers the complete decoded file. Stored blocks are independent
RFC 1950 zlib streams. Neutral file tags are 1024; en-US file tags are 0; both use
the same block encoding. Other tags and schema/encoding versions fail closed.

Reads validate stored hashes before decoding, enforce complete contiguous logical
coverage, and retain at most one decoded block across the archive. Full-file
`verify()` additionally checks the decoded file hash. Database integrity alone
is not publisher trust: authenticate/pin metadata before consuming payloads.

The stream includes delta files as ordinary members; this reader does **not**
apply them. A fresh-install policy must select full packages, not `_delta` ones.
`root/vreg/*.dat` members are ordinary REGF hives containing App-V relocation
tokens. Their presence and readable manifests are not proof of installed service,
virtualization, COM, servicing, licensing, or usable application state.
