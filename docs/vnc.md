# Browser VM display

The native `-serve` frontend accepts a script whose `main(args)` returns a VM
with the portable `vmm.DisplaySource` capability. cc supplies owned RGBA frames
and serialized keyboard/pointer input. A callable result still serves a regular
Starlark web application.

From a trex checkout, pass a recipe whose `main(args)` returns a running VM:

```sh
go run ./cmd/trex -serve 127.0.0.1:8080 /path/to/vm.star
```

The recipe supplies the guest disk and backend configuration. Trex does not
construct or configure an operating system through this frontend. TinyRangeX
provides an NT 3.1 browser recipe and guest drivers in
[tinyrangex](https://github.com/tinyrange/tinyrangex).

Open the complete session URL printed in the terminal. Closing the browser
leaves the VM running. Disk persistence follows the recipe's attachment policy.
Only one browser can control the VM at a time. Disconnect to hand over control.

Click the canvas to capture keyboard and mouse; Esc releases mouse capture.
The toolbar sends Ctrl+Alt+Delete without invoking the browser/host shortcut.
Keyboard input uses US physical key positions. Clipboard, wheel, touch, audio,
and file transfer are not supported. PS/2 input is relative, so mouse capture
avoids confusing host/guest cursor alignment. Absolute
pointer devices require additional guest/backend support.

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
go test -race ./vmm/rfb ./vmm/vncweb ./vmm/cc ./vmm/star
node --test vmm/vncweb/client_test.mjs
```

Protocol references: [RFB 3.8](https://www.rfc-editor.org/rfc/rfc6143) and
[WebSocket](https://www.rfc-editor.org/rfc/rfc6455).
