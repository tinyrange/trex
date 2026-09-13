# Browser VM display

The native `-serve` frontend accepts a script whose `main(args)` returns a VM
with the portable `vmm.DisplaySource` capability. cc supplies owned RGBA frames
and serialized keyboard/pointer input. A callable result still serves a regular
Starlark web application.

From the enclosing TinyRangeX checkout:

```sh
go run ./trex/cmd/trex -serve 127.0.0.1:8080 scripts/run/windows_cc.star \
  '/path/to/Microsoft Windows NT 3.1 Workstation (3.10.511.1) (ISO).7z'
```

Open the complete session URL printed in the terminal. At the NT welcome screen,
use the Ctrl+Alt+Delete toolbar button, then log on as **Administrator** with an
empty password. The image is constructed
in memory from original media. Disk changes live in the VM's memory overlay;
closing the browser leaves the VM running, while stopping trex discards them.
Only one browser can control the VM at a time. Disconnect to hand over control.

Click the canvas to capture keyboard and mouse; Esc releases mouse capture.
The toolbar sends Ctrl+Alt+Delete without invoking the browser/host shortcut.
Keyboard input uses US physical key positions. Clipboard, wheel, touch, audio,
and file transfer are not supported. PS/2 input is relative, so mouse capture
avoids confusing host/guest cursor alignment. Absolute
pointer devices require additional guest/backend support. The NT 3.1 browser
recipe now uses the Renvo RAM framebuffer driver at 1024×768 with 32-bit color;
see [the driver protocol and smoke](cc-pc.md#renvo-nt-31-display-driver).

The browser recipe deliberately uses interactive logon. Automatic logon in this
NT 3.1 image can race SPOOLSS initialization and fault in NTDLL's critical-section
wait path; the same error was captured before any browser connection. Interactive
logon reached Program Manager and accepted keyboard and mouse input. The general
image recipe retains its existing automatic-logon default and now accepts
`auto_logon = False`; this is a guest startup limitation, not a VNC protocol error.

The Go RFB 3.8 implementation is in `vmm/rfb`, over `channel.ByteChannel`.
It supports RGB888 raw rectangles, incremental requests and DesktopSize.
`vmm/vncweb` implements RFC 6455 binary framing and embeds the original
JavaScript client; there are no external client libraries or CDN resources.
The client requests updates at up to 20 Hz; incremental updates send the bounding
rectangle of changed pixels, and unchanged frames send no pixels.
Relative pointer positions wrap modulo 65536 in the included client/server.

The HTTP adapter requires a random session token and matching Origin for the
WebSocket connection, rejects unmasked/oversized input, and bounds stalled I/O.
The URL fragment is removed from browser history after loading; the token stays
in that tab's session storage for reloads. Plain HTTP is intended for loopback use;
remote deployment needs HTTPS to protect the bearer token and guest traffic.

Validation:

```sh
go test -race ./trex/vmm/rfb ./trex/vmm/vncweb ./trex/vmm/cc ./trex/vmm/star
node --test trex/vmm/vncweb/client_test.mjs
```

Protocol references: [RFB 3.8](https://www.rfc-editor.org/rfc/rfc6143) and
[WebSocket](https://www.rfc-editor.org/rfc/rfc6455).
