# Observed LIC packed component profile

Portable native support is implemented by `OpenPacked(source, maximumFrames,
maximumBytes)` and `DecodeFrame(frame)`. Automatic `ibmi_packed` browsing exposes
`expanded.bin` and `metadata.json`; the node's original file retains stored bytes.
The expanded reader decompresses only requested frames, caching one frame.

This grammar was recovered by reading actual Motorola 68k instructions in the
unwrapped LIC component `a0b00700`: file offset `0x28cc` is the framed-stream
driver, `0x29a4` the frame-expansion routine and `0x2bcc` its bit-advance helper.
The driver contains a direct `JSR 0x000229a4` at file offset `0x2940`. This is
independently derived format behavior, not execution of the proprietary code.

## Framing

The 16-byte big-endian component header contains stored length (including this
header), expanded length, frame count and a zero reserved word. Allocation padding
may follow the declared stored length. Each frame contains three big-endian words:
`03000080`, frame length (including its header) and expanded length. Bitstream data
starts at **frame byte 12**, not 16. The IBM routine initially preloads four bytes
there; this does not make those bytes an additional header. Frame output is at
most 32768 bytes. Stored and expanded frame totals must exactly match the outer
header before output is exposed. Source ranges and caller budgets are checked.

## Bitstream

Bits are consumed most significant first. History resets for every frame.

- Tag `0`: read eight bits and emit a literal byte.
- Tag `1`: begin with length width 2. While width is below 8 and the next bit is
  zero, consume that zero and increment width. Read `width` bits as the length;
  the first one bit that stopped the loop belongs to that length, not to a
  separate terminator. At width 8, read all eight bits without a leading-one
  requirement. Length 255 is a control/error return in the observed routine.
- For a reference, the next bit chooses distance width: `1` means 7 bits;
  `0` means 11 bits. Read the unsigned distance and copy `length` bytes from
  that many bytes behind the current output, forwards and allowing overlap.

This bounded profile requires positive lengths/distances, frame-local history,
no output overrun, and the entire declared frame output. A 255 control token
before that output is complete fails explicitly. Tail bytes are not interpreted as extra output. Their now-qualified end-control
and stop-bit fill checks are described below; checksum semantics remain unknown.
This is not an encoder, authenticity check, relocation engine or IPL emulator.

Synthetic tests cover literals, both distance widths, overlapping copying,
wide lengths, invalid history, overrun, premature control, truncation, budgets,
frame isolation, random-access reads and EOF behavior. No proprietary payload
or implementation source is included in the fixtures.


## Complete-frame termination and inspection

A full survey of all 14819 RS750-J frames independently established the suffix:
length-255 control (15 bits), a one stop bit, then zero bits completing a 32-bit
boundary. The post-control span is 1..32 bits; frames have word-aligned stored
lengths. `DecodeFrame` now requires this exact suffix after the declared output.
It rejects output prefixes followed by missing/incorrect control or garbage
padding. This validates framing, not a checksum or IBM authenticity signature.

`DecodeFrameWithInfo` additionally returns consumed-output bits, raw-tail byte
and initial-bit offsets, control/padding counts, stop/fill observations and
termination_verified. It can return exact output with a nonverified tail for
inspection; callers must check that field. The strict expanded reader uses
`DecodeFrame`, not the diagnostic success condition. `Packed.InspectFrame`
inspects one frame without expanding other frames. Automatic frames/00000000/
views expose metadata.json and tail.bin lazily. A tail's first byte can overlap
consumed bits; metadata identifies where unused bits begin.

Strict validation reproduced every one of the 542 previous expanded hashes.
Tests include intermediate length widths, distance boundaries 127/128/2047,
control/stop/fill corruption, mutable-metadata isolation and bounded fuzzing.
A synthetic BOOT2 -> IMD -> packed -> XCOFF test verifies actual nested reads
and propagation of a corrupted tail through lazy automatic format detection.
