# ReactOS publication prerequisites

trex provides native archive decoding and in-process Windows DLL registration
primitives used by the downstream ReactOS image builder. The complete builder
is not yet included in this repository.

## Archive and registration support

- The 7z reader accepts LZMA2 framing over the existing Go LZMA decoder, with
  bounded dictionaries, chunk-size checks, reset handling and end validation.
  ZIP entries expose `name` without reading their payload, allowing recipes to
  select an ISO before decoding it.
- The Windows emulation runner distinguishes resource-only module mapping from
  process attach and tracks the primary module during import-cycle handling.
- Registration plugins model the registry query/deletion, activation-context
  lifetime, bitmap/brush ownership, Automation exports, resource identifiers,
  debug formatting and CRT operations needed by the tested ReactOS exports.
  Activation-context support here covers file-backed manifests with zero
  flags; additional resolution modes stop explicitly, rather than reporting
  successful registration.

These primitives let a recipe execute media-provided `DllRegisterServer` and
`DllInstall` exports before boot, check completion and HRESULTs, and apply the
resulting registry and file effects to its in-memory image. They do not replace
recipe policy: the caller supplies the complete installed file namespace,
baseline hives, target exports and arguments.

No guest registration batch or external archive/conversion tool is required.
The LZMA2 implementation follows the
[published framing description](https://sourceforge.net/p/sevenzip/discussion/45797/thread/09814bb2/).
The small compressed fixtures are from the public-domain XZ Utils test corpus;
no ReactOS implementation source, installation media or private registry
templates are included.

## Validation

The public tests require no OS media:

```sh
go test ./...
go run ./cmd/trex test.star
```

Downstream fresh-image QEMU smokes passed for ReactOS 0.4.16
`release-0-g822e864`, 0.4.17 `dev-755-gdbdf684`, and compatibility 0.4.15
`release-1-gdbb43bba`. Each checked generated identity, the desktop, guest
version, Notepad, Calculator and Minesweeper, with zero disk-command errors.
This integration evidence uses a downstream recipe and caller-supplied media;
it is not a public, reproducible image-building entry point yet, nor a claim
that every ReactOS subsystem or registrar is supported.

## Remaining builder migration

1. Replace the downstream dependency on private NT5 SAM/SECURITY templates
   with direct ReactOS record construction from explicit accounts, groups,
   SIDs, passwords and security descriptors. Binary serialization belongs in
   Go; account policy belongs in the recipe. Review provenance before moving
   any existing template data.
2. Separate media discovery, registry/account policy, installed-file selection
   and disk layout into small helpers. Share the INF destination map between
   file population and registration instead of maintaining parallel mappings.
3. Publish a file-based `reactos_disk(file)` entry point and the exact
   desktop/version/application smoke. Keep QEMU policy outside construction
   and require caller-supplied media.

The current changes are independently usable prerequisites, not completion of
those migration steps.
