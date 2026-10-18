# Private SMB implementation

First-party SMB 2.1 protocol code over caller-supplied `io.ReadWriteCloser`
streams. No Samba, server subprocess, or host listener is created. `NewServer`
exports one `FileSystem`; the caller supplies private connections to `Serve`,
then calls `Server.Close` before closing its filesystem backend.

Implemented:

- Direct-TCP framing and compound bounds (2 MiB / 16 commands), 32 connections,
  bounded replay-resistant credits, and at most 256 open handles per session.
- SMB 2.1 negotiation, including SMB1-format dialect discovery **only**.
  SMB1 authentication and file operations are not supported.
- NTLMv2/SPNEGO authentication with MIC validation, mandatory HMAC-SHA256
  signing, whole-compound signature validation before effects, signed session
  completion, echo/logoff, and session-key cleanup.
- Tree connect/disconnect; create/open, close, flush, read/write (64 KiB chunks),
  directory enumeration, common file/filesystem queries, rename, truncate,
  deletion and access/modification time updates.
- Portable filesystem interfaces and a native `os.Root` implementation with
  read-only enforcement, sharing checks before truncation, case-insensitive
  lookup, rename and delete-pending semantics. Traversal/device/stream names
  and symlink escapes are rejected; special files are not exported.
- Authentication has a 30-second timeout. Authenticated streams can remain idle;
  server shutdown interrupts them and waits for file handles to be released.
  Reconnects require fresh authentication, not merely a previous session ID.

The standalone Windows desktop connects this server to
`j5.nz/cc/network.Isolated`, the packet-only private DHCP/TCP endpoint. There is
no host forwarding, DNS proxy or DHCP gateway. Credentials are random per launch.
The launch directory maps as Z:; its writes persist independently of the guest
system disk. Use `-share`, `-share-read-only`, or `-no-share` to control exposure.

## Scope and validation

A fresh Windows 11 26300.9457 guest mapped Z: automatically, browsed the share,
read host data, wrote/renamed/deleted host files, created a directory, and copied
1 MiB with exact byte comparison. Windows reported SMB 2.1 with signing enabled.
Tests cover signed wire-level mutations and read-only denial, malformed framing,
authentication, signature tampering, replay, compound validation, reconnect,
shutdown, native sharing conflicts (including hardlinks), and symlink races.
Native storage runtime tests cover Linux.

Metadata-only opens do not participate in data-sharing checks in either open
order. Windows 11 Explorer's This PC volume probe uses READ_ATTRIBUTES plus
SYNCHRONIZE with ShareAccess=0; rejecting it against an existing directory
reader incorrectly returns SHARING_VIOLATION. Wire-level regressions exercise
that exact probe at root and child directories, 137 Unicode filenames across
small response buffers, independent enumeration cursors, restart, single-entry
requests, and pending-entry preservation after BUFFER_TOO_SMALL. Exclusive
data opens still reject conflicting reads, writes, and deletes.

The standalone `WINDOWS11_TEST_SHARE=1` smoke covers Explorer root → This PC →
root → child → refreshed root, asserts the volume probe succeeded without any
sharing violation, and checks complete repeated PowerShell enumeration of both
directories. A fresh 26300.9457 four-core/8-GiB run passed in 467 seconds with
visually reviewed directory listings. Optional TraceCreate diagnostics report
access/share/options/status and handle count, never filenames or payloads.

This is not a complete Windows file server. Notifications and advanced IOCTLs
return NOT_SUPPORTED; refresh Explorer to observe host-side changes. Byte-range
locks, leases, durable handles, encryption, anonymous/guest access, alternate
streams, ACL editing, and full DOS attribute/creation-time preservation are not
implemented. Do not expose this transport to untrusted external networks.
