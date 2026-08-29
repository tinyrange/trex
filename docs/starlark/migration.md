# Refactoring migration guide

The refactored APIs preserve existing cursor, builder, file, debugger, and VMM
operations. New code should use the forms below; old public operations are not
deprecated unless stated explicitly.

## Scalars

```starlark
# Before
value = binary.cursor(source[offset:offset + 4]).u32le()

# After: reads exactly four bytes from a lazy source
value = binary.read_u32le(source, offset)

# Before
encoded = binary.builder(capacity = 4)
encoded.u32le(value)
output.patch(offset, encoded.bytes())

# After
output.patch_u32le(offset, value)
```

Guest scalar reads and writes use `machine.read_u32le(address)` and
`machine.write_u32le(address, value)`. They avoid temporary Starlark byte
objects. Encoding is exact and never masks an out-of-range value.

## Records and text

Use `binary.layout(...).decode()` and `.encode()` for stable named fixed
records. Keep isolated values on direct scalar methods. Encoding names are
case-insensitive and accept `ascii`, `utf8`/`utf-8`, `utf16le`/`utf-16le`, and
`utf16be`/`utf-16be` where supported.

## Images and overlays

Image functions now return lazy disks. Move final `write()` calls to a CLI
`main(args)` wrapper. Pass a returned file directly to `vmm.disk()` or wrap it
with `block.cache()` and `block.overlay()`.

For repeated builds in one runtime, construct one `runtime.stage_cache()` and
pass it as `stages=`. Cached results are frozen; make option-dependent changes
inside a separate later stage instead of mutating an earlier result.

Replace `overlay.commit()` during an active VM with `overlay.snapshot()`.
Commit still seals an inactive overlay and remains useful for an explicit final
image.

## Time and VM input

Replace elapsed-time uses of `clock.unix()` with `clock.monotonic()`. Keep
`clock.unix()` for actual UTC/calendar data. Prefer `vm.tap()`, `vm.chord()`,
and `vm.type_and_enter()` to unbalanced `vm.key()` calls.
Use `pump_events()` for shared VM/KD dispatch loops that previously duplicated
`debug.select`, deadline, and event-budget policy.

## Partitions

Parse complete disks with `filesystem.mbr(file)` or `filesystem.gpt(file)`
rather than reading MBR offset 446 manually.

## Interactive experiments

Use whole-script stdin for reproducible one-offs and `repl()` to inspect live
lexical values, overlays, VMs, and debugger sessions. REPL rebinding is local
to the console, while mutations to shared capability objects persist.
