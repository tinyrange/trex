// Package udf parses Universal Disk Format filesystems.
//
// ICB file type 12 is exposed as entry_type="symlink" with a link target decoded
// from ECMA-167 path components and UDF compressed Unicode. Link targets preserve
// relative parent/current components and root components. A named external
// volume root has no portable interpretation and returns an explicit error.
// Links are never followed or exposed as ordinary encoded payload files: their
// size is the decoded target length, stored_size is the encoded length, and
// Entries returns a nil File. Both embedded and extent-backed links are read
// through the same storage abstraction as ordinary files.
package udf
