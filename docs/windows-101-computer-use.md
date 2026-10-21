# Native computer use in Windows 1.01

This public trex demo builds a native Win16 NE agent and an installed DOS/Windows
image in memory, then draws in **Windows Paint (`PAINT.EXE`)** through guest-side
keyboard/mouse input. The host observes the framebuffer; it does **not** send
QEMU keyboard/mouse events, patch Paint's bitmap, or upload a picture.

## Run and record the whole boot

Requirements: Go and the trex source/submodules, QEMU, your own original media,
and (only for `video=`) **FFmpeg with the libx264 encoder on PATH**. No StarAgent,
private SDK, X server, Xvfb, VNC viewer, or physical display is required.

From the public trex checkout:

```sh
go run ./cmd/trex scripts/examples/windows_101_computer.star \
  /media/dos622-disk1.img /media/dos622-disk2.img /media/dos622-disk3.img \
  /media/win101-setup.img /media/win101-build.img /media/win101-utilities.img \
  /media/win101-applications.img /media/win101-write.img \
  video=boot-and-paint.mp4 screenshot=paint.png
```

The script starts QEMU paused, starts the recorder and waits for a captured frame
and encoder output, then resumes the guest. It records **BIOS, DOS, Windows
startup, and the Paint drawing**, continuously at 30 fps, 1440×900, without audio.
It pauses after Windows loads, spaces completed strokes/clicks and keystrokes,
then holds the final screen for five seconds, saves the PNG and MP4, and closes the
native client, recorder and VM. Omit `video=` to run without FFmpeg. Output paths
are explicit final artifacts, not intermediate frame files. Failure paths also
close the owned resources; they do not retry input or export a failed video as
success.

The default video is H.264 (libx264, CRF10, YUV420) in a fragmented MP4 container.
Use `lossless=true` for an RGB-lossless master (libx264rgb, CRF0, no chroma
subsampling). That mode preserves the encoded canvas exactly but may not play in
a browser; use the default compatible version for sharing.

Pacing changes real guest actions, not video timestamps. Each native gesture
remains one complete down/move/up batch. `pace=false` restores the fast smoke;
otherwise the demo includes a 3-second initial hold, 0.4-second click spacing,
0.65-second stroke spacing, 0.12-second character spacing, and a 5-second final hold. A fixed black canvas with
integer-factor upscaling/letterboxing handles BIOS/text/GUI resolution changes.
In this demo both DOS and Windows pixels are enlarged exactly 2× rather than
stretched by a fractional factor. Sources larger than the canvas downscale with
nearest-neighbor; choose a larger canvas to avoid losing source pixels. Capture
runs on a background worker, independent of native input calls. Missed sampling
slots duplicate the previous frame to preserve wall-clock time, rather than
speeding up playback; the final log reports frame and duplicate counts. This is
sampled real-time capture, not guaranteed capture of every guest display refresh.

FFmpeg is an explicit, narrowly scoped repository exception for QEMU video
encoding. Frames go through an anonymous QEMU capture handle and a pipe to
FFmpeg; encoded output stays bounded in memory until `write`. No arbitrary
FFmpeg command interface, host-file frame sequence, or converter fallback is
provided. The first backend is native QEMU on Linux/macOS; only Linux has been
integration-tested for this demo.

## Interactive public trex REPL

Append `repl=true` to enter the public trex REPL after native agent readiness
instead of automatically drawing. If `video=` is present, boot recording is
already active and continues through the REPL. EOF finalizes and exports it.

```starlark
help(device)
help(channel.extension)
print(channel.extension_protocol())  # complete offline wire specification
help(recorder)                      # when video= was supplied

draw_demo(device, pause=pause)      # ONCE, paced, on this fresh desktop
write("paint-now.png", vm.screenshot())
```

There is no TCP bridge in this path. The script consumes `WINEXT_READY\n` from
COM1, then `channel.extension(serial, timeout=5)` discovers and calls the native
endpoint directly over that byte channel. `computer_client.star` is ordinary
public trex Starlark, loaded by the example.

`draw_demo` assumes the fresh recipe's 640×350 guest display and no other desktop
interaction. It launches Paint, iconifies Executive, draws a dinosaur and sun,
and types all labels through native key events. Do not run it twice on the same
desktop. The same helpers are available for interactive experiments:

```starlark
click(device, 240, 53)
drag(device, [(180, 220), (220, 170), (270, 220)])
key_chord(device, [(0x10, 0x2a), (0x41, 0x1e)])  # Shift+A
type_text(device, "Hello from trex")           # supported US-layout subset
```

A launch result or completed input call is not visual proof. Inspect Paint's
surface, dinosaur, and typed labels in the screenshot/video.

## Recording API for other QEMU recipes

```starlark
# machine must request a capturable display and start_paused=True.
vm = vmm.start(machine, backend)
recorder = vm.record(width=1440, height=900, fps=30,
                     maximum=64 << 20, duration=600, lossless=False)
vm.resume()
# ... boot readiness, guest actions, or repl() ...
video = recorder.stop()     # finalize before stopping the VM
write("session.mp4", video)
vm.close()
```

`record()` has a 30-second startup deadline and fails explicitly when FFmpeg or
its encoder is unavailable. Only one recording can be active per VM. `stop()`
joins workers and finalizes, returning the portable video file; repeated `stop()`
returns the same content. `close()` aborts and discards it. VM teardown also
aborts/discards an owned recorder; stop/export first if you need the video.
`stats` exposes `frames`, `duplicated`, `elapsed` seconds, and `done`.

Limits: even width/height 2..4096, at most 4096×2160 pixels; 1..60 fps;
`maximum` 1 KiB..512 MiB; `duration` >0 and at most 3600 seconds. Duration
completion finalizes automatically; call `stop()` to retrieve the result.
Output-limit, capture, encoding, or excessive real-time lag failures are errors
from `stop()`, not successful partial files. `maximum` bounds encoded output,
not all process/decoded-frame memory. The current output is video-only.

## Native API and wire format

The complete v1 framing/manifest/value specification is embedded in
`channel.extension_protocol()` and lives in
[`channel/star/extension_protocol.md`](../channel/star/extension_protocol.md).
The native input payload below is carried inside a normal tagged string.

`compile_win16(computer_use=True)` advertises `ping`, `launch`, and
`input_events(events)`. The last argument is a hex string containing 1–40
six-byte records, each three little-endian words:

| Message | `paramL` | `paramH` |
| --- | --- | --- |
| `0x0200` mouse move | desktop x | desktop y |
| `0x0201` / `0x0202` left down / up | desktop x | desktop y |
| `0x0204` / `0x0205` right down / up | desktop x | desktop y |
| `0x0100` / `0x0101` key down / up | virtual key | scan code |

The native endpoint rejects an entire malformed batch **before any input
side effects**: invalid/truncated hex, excessive length, unsupported messages,
out-of-bounds coordinates, duplicate presses, unmatched releases, and batches
ending with held keys/buttons. Coordinates are pixels, not normalized values.
The client `input_events` helper supplies wire encoding; validation remains in
the guest. There is no direct injection of `WM_CHAR` or application messages.

**Send complete gestures.** Windows 1.01 can enter cooperative modal tracking
inside USER on a button press. Sending a synchronous down call and waiting to
send up deadlocks. Queue down, movement, and up together. A drag supports up to
38 points. Complete any opened modal interaction in the same batch as well;
leaving a menu/dialog tracking loop open can prevent the agent from returning.
Use exclusive input ownership: mixing physical/host input with playback is not
validated. Application mouse-move coalescing remains normal Windows behavior.

The hook acknowledges events consumed by USER, not completion of an application
repaint. Capture and inspect the display between gestures. Input timeout or
transport failure can have an **unknown partial outcome**: never automatically
retry. Restart a fresh demo VM rather than guessing which events ran.

## Implementation and scope

The native backend uses USER `SetWindowsHook(WH_JOURNALPLAYBACK)` and KERNEL
`MakeProcInstance` / `FreeProcInstance`. Windows 1.01's callback is
`playback(EVENTMSG far*, DWORD currentTime, WORD action)` with Pascal 10-byte
cleanup: action 0 requests the event and action 1 consumes it. This differs
from the later Win16 `HookProc` ABI. The callback uses the instance DS supplied
by the thunk and preserves the caller's registers/segments. Native imports and
state addresses use the normal relocation-aware backend, not RTGASM fragments.
Existing playback hooks are restored and rejected as busy, not overwritten for
a gesture. Completed batches remove their hook and release their thunk.

The computer-use build is currently **Windows 1.01 only**. Windows 3.x
computer-use builds are explicitly rejected; Windows 2.x has not been
validated. Unicode, arbitrary keyboard layouts, wheel events, and asynchronous
persistent held-button sessions are not implemented.

The existing file-service build is unchanged in capability and still supports
its prior Win16 targets. Computer use is a separate build because combining the
features currently exceeds the single 64 KiB near-code segment. The public demo
ships source/recipes only, not original Microsoft media or an installed image.

## Verified demo result

A fresh Windows 1.01 / MS-DOS 6.22 image completed `draw_demo(device)` with
Paint's dinosaur/sun drawing and all three native-keyboard labels visible in
the 640×350 host screenshot. A malformed batch suffix was rejected by the live
endpoint and a subsequent ping succeeded. No host keyboard/mouse input was
used. This is an application-specific Paint proof, not a claim that all modal
Windows workflows or other Win16 generations are supported.

## Checks

```sh
go test ./scripts/guest/windows_extension ./scripts/guest/dos_extension
go vet ./scripts/guest/windows_extension ./scripts/guest/dos_extension
go run ./cmd/trex scripts/guest/windows_extension/check.star
```

The image check covers both original file-service variants and the computer-use
image, including mandatory journal import fixups, code/data bounds, and loader
headers. The gesture tests cover accepted strokes/chords and invalid suffixes,
bounds, lengths, and unbalanced state. A final integration proof requires the
exact drawing script on a fresh image plus visual inspection of its screenshot.
