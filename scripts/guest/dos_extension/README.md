# DOS extension guest

Renvo Go source for a synchronous plaintext extension v1 endpoint on COM1.
The private repository's `starlark/private/msdos/extension.star` builds this
package in a virtual `renvo.dev` module with the DOS device sources and external
`msdos.rtg` backend, entirely in memory. No host Go executable is substituted
for the guest. `hardware_host.go` exists only for Go protocol safety tests.

The endpoint uses DOS 5+ services and COM's single-segment model. Requests are
bounded to 1024 bytes and transfers to 256 bytes (hex encoding); printable ASCII
paths and command tails are validated before effects. Directory names are
returned as raw OEM hex. The manifest documents all operations.

Keep buffers and interrupt register blocks persistent: repeated heap allocation
will exhaust a DOS program's small arena. Do not relax the compiler's image or
stack limits to make an oversized endpoint compile. `run` is synchronous, with
inherited environment/console, no capture or cancellation, and requires all
extension handles closed. The parent retains 64 KiB and releases excess DOS
memory for the child. A child must return and leave COM1 available.

Host tests:

```
go test ./scripts/guest/dos_extension
```

The end-to-end proof boots a freshly built DOS image, discovers this exact
manifest through StarAgent `open_ext`, checks binary file round trips, directory
operations, child exit/command tail, and filesystem operations after execution.
The service and client scripts live in the private repository under
`scripts/smoke/dos_extension*.star`; see its `docs/dos-extension.md`.
