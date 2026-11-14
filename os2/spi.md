# Native stream-handler profiles

`os2.stream_profile(source, maximum=64MiB)` reads the original SSMRES LX
module's RT_RCDATA resources and builds the binary `SPI.INI` profile. It does
not execute `SpiInstall`, load a handler DLL, or run a guest installer.

Resource 1 is a two-byte handler count. Subsequent records contain terminated
class/name strings, a two-byte handler type, a terminated module name, a
two-byte protocol count, and 72-byte SPCB records. Strings, counts, protocol
sizes, resource identities and all LX references are bounded and validated.
The original declaration order is retained; classes containing several
handlers are grouped without dropping protocols or introducing pointers.

`SHCLASS/<class>` values begin with a two-byte count, followed by each
handler's packed 273-byte header and protocol array. The header order is
name[9], type[2], DLL[260], protocol-count[2]. In particular, type precedes
DLL: swapping those two fields makes the original SSM report handler-not-found.
`SHNAME/GLOBAL` contains a two-byte class count and padded nine-byte names.
The profile writer enforces its own 16-bit value limits as well.

Layout facts were checked against original IBM SSMRES resources, the original
SSMINI profile-write path and the SSM runtime lookup, and the IBM toolkit's
`ssm.h` definitions. Synthetic tests cover multi-handler classes, differing
handler types/protocol counts, exact header offsets and malformed input.
Original software-video and SB16 PCM playback supply integration evidence.
