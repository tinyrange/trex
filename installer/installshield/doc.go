// Package installshield reads InstallShield packages and supported executable
// installer envelopes without running the installer.
//
// Nested package discovery prefers a separate data1.hdr over a version 5 volume
// carrying the same version marker. Combined version 5 cabinets remain valid
// when no separate header belongs to that package. Automatic views preserve
// existing member paths for a single package; installers with several packages
// expose each package's members beneath its package root. An empty primary
// package therefore does not hide populated child packages. Explicit installer
// payload and packages attributes retain their existing meanings.
package installshield
