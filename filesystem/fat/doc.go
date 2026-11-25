// Package fat parses FAT volumes and builds FAT12, FAT16, and FAT32 images.
//
// Builders honor directory.set_times metadata in UTC-calendar form; FAT has no
// timezone field. Explicit times must fit 1980..2107; zero remains unspecified.
// Last-write times have DOS two-second precision, creation times retain DOS
// centiseconds, and last-access times retain dates only. No host timezone or
// host wall clock is consulted.
//
// A parsed volume's metadata(path) returns original DOS date/time words and a
// last_write_local_filetime: a FILETIME-shaped LOCAL calendar value, not UTC.
// Invalid or unspecified local calendars yield None without altering raw words.
// The root has no owning directory entry and yields None.
package fat
