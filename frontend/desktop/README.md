# Native desktop frontend

Linux X11/GLX presentation for `vmm.DisplaySource`. Call `Run` on the initial,
locked OS thread. Its `Options.Start` callback owns guest construction and VM
cleanup; publish the display exactly once, retain it until context cancellation,
and return only after cleanup. No private image recipes belong in this package.
Paused drivers continue rendering. A stopped driver is awaited: clean shutdown
closes the window, while failure reasons are propagated to the caller.

The frontend captures owned RGBA frames on a worker, renders with a persistent
OpenGL texture, preserves aspect ratio, and translates key/button transitions.
Relative pointing uses click capture and Ctrl+Alt release. An optional
`vmm.AbsolutePointerSource` enables integrated absolute coordinates without a pointer grab. The guest-drawn cursor remains visible; the host cursor is hidden only over the guest viewport, not the letterbox or other windows. This is not a host cursor-shape protocol. Ctrl+Alt+F
requests EWMH fullscreen; a cooperating window manager is required. The concrete
backend decides available keys, pointer modes and wheel support.

An optional `vmm.ResizeDisplaySource` lets the guest desktop follow window and
fullscreen dimensions after a 200 ms debounce. Capture and input continue during
the request. `DisplayResizeReadiness` delays requests until the guest driver is
ready; rejected dimensions are not retried without a viewport change. Automatic
requests preserve aspect ratio within 1920×1080, matching the current 8 MiB
Windows framebuffer. Presentation uses captured dimensions until the guest has
applied its new mode.

Platform code was copied/adapted with permission from the sister gowin project
(`window_linux.go`, `input.go`, MIT; license retained in `internal/xwindow/LICENSE`).
Changes add VM capture/warp handling, focus-loss events, cursor hiding, fullscreen
and title control, and remove host file-dialog subprocess integration. Renderer
shader code derives from CrumbleCracker's `internal/desktopapp/display.go`
(Apache-2.0, retained in `LICENSE-CRUMBLECRACKER`) and adds stride-aware upload,
persistent textures and aspect-preserving presentation.

`TREX_TEST_X11=1 go test -race ./frontend/desktop/...` in the trex checkout runs
real isolated Xvfb/GLX tests as well as portable input/worker tests. Xvfb is only
a test fixture. Production loads the host X11/GL libraries through purego and
never launches external graphical tools.
