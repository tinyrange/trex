# Absolute RPA block lists

An RPA block list describes a scatter list of real-memory buffers. It begins
with a big-endian 16-byte header: u16 `0101`, u16 context (observed zero), u32
used byte length, u64 next-list address. The context's meaning is unverified.
Observed pointers use absolute addresses with high nibble 8. The used length
includes the header and up to 255 16-byte entries, each a u64 absolute address
and u64 length. A zero next address ends the chain.

The entry count is `(used_length-16)/16`, after which the next pointer is
followed. A one-page buffer list has used length 32 and a 4096-byte target;
the header is not an output buffer.

`binary/rpa.ReadBlockList` accepts a portable real-memory reader and validates
the complete chain before returning targets. It bounds lists, entries and
total capacity; rejects cycles, unsupported header/context values, truncated or
invalid ranges and targets overlapping list metadata; and never modifies
memory. This is observation of the demonstrated format; other context values
remain explicit gaps. `power_machine.rpa_block_list(address,
maximum_capacity=16MiB)` exposes the validated capacity and target records
without changing memory, pointer tags or translation state.
