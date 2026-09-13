# NT5 SAM alias records

`windows.sam_alias_members(source)` accepts bytes or a portable file containing
one compact SAM alias `C` value and returns a list of binary SIDs.
`windows.sam_alias_with_members(source, members)` returns replacement record
bytes. Both validate the header, payload extents, member count and SID extents;
replacement rejects duplicate SIDs. Starlark inputs are bounded to 16 MiB.

The 0x34-byte header stores the membership vector's payload-relative offset at
0x28, byte length at 0x2c, and SID count at 0x30. Members are concatenated
revision-1 SIDs. The other bounded payload fields describe the security
descriptor, name and description. Replacement preserves those fields and opaque
record data. A trailing membership vector is replaced in place; otherwise the
new vector is appended without relocating unrelated fields. Repeating a
replacement does not grow the record.

These APIs only implement the binary record. They do not choose group policy,
modify host accounts, generate registry patches or update a hive automatically.
The caller must update the SAM reverse-membership indexes and their counts in
the same hive construction operation. Account names, selected groups and
operating-system setup policy belong to the image recipe.
