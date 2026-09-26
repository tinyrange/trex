// Package iso9660 parses ISO 9660 optical-disc filesystems.
//
// A primary tree declaring Rock Ridge through SUSP SP/ER takes precedence over
// Joliet. Rock Ridge names retain their case and lookup is case-sensitive;
// ordinary ISO/Joliet volumes retain case-insensitive lookup. The reader follows
// bounded, cycle-checked CE continuation areas, joins NM/SL continuations,
// restores relocated directories (CL/RE), and exposes PX, PN and TF metadata.
// Entry attributes include entry_type, link, mode (raw POSIX st_mode), uid, gid,
// nlink, optional inode, and timestamps as Unix seconds. Unknown SUSP extensions
// are ignored. Symbolic links expose their target without following it and have
// no regular file data; Entries returns a nil File for links and special entries.
package iso9660
