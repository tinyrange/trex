# Desktop archive browser

`trex-browser` is a read-only, 7-Zip-style desktop file browser built with gowin.
It opens a native window with a compact menu bar and icon toolbar, address bar,
sortable details list, navigation history, and an in-process text/hex viewer.
The layout follows the 7-Zip file manager: a full-width file list by default,
20-pixel rows, small file icons, right-aligned grouped sizes, and a slim status
bar. The Folders toolbar button or View menu toggles the optional folder tree.
Ctrl+F reveals the filter field; Escape clears it and restores the full-width
address bar. The UI uses installed Tahoma on Windows (a local or embedded font
on other platforms). Text and hex previews always use the separately loaded
embedded Roboto Mono font, keeping offsets, byte groups, and ASCII aligned.
Gowin supplies
the platform window, graphics, input and clipboard; the controls are drawn by
the application, rather than OS-provided widgets or a webview.

From the trex module:

```sh
go run ./cmd/trex-browser /path/to/archive-library
go run ./cmd/trex-browser /path/to/image.iso
go install ./cmd/trex-browser
```

On Windows, use `trex-browser.exe L:\` to browse a mapped NAS drive. With no
argument it opens the current directory. The chosen directory is the browser's
root; when given an archive, its containing directory becomes the root.
The address bar uses paths relative to that root, starting with `/`, including
paths through nested archives such as `/collection.zip/images/disc.iso/docs`.

Double-click a row or press Enter to open a directory, archive or file preview.
Right-click a file or folder for its context menu; Shift+F10 opens the menu from
the keyboard. Arrow keys select menu commands, Enter activates them, and Escape
or a click outside dismisses the menu. Right-clicking selects the target without
opening it. The menu includes Open in trex, Open in system viewer, Save as,
Copy path, and Up one level, with unavailable actions disabled.

**Open in system viewer** (also Ctrl+Enter or the toolbar button) uses the
registered desktop file association. Existing host files open directly.
Archive members first show a Save and Open dialog: choose the full destination
filename for a retained copy, then the saved file opens in its system handler.
Save as creates a retained copy without launching it. Existing destinations are
never overwritten. Cancel leaves the filesystem untouched. No temporary
extraction or automatic cleanup of saved copies takes place.

These explicit desktop actions use Windows ShellExecute, macOS Launch Services
through `open`, or the Linux desktop's `xdg-open` handler. They are not used by
archive parsing, preview, navigation, or any processing stage. On Windows, the
file's normal shell `open` verb applies, including execution for executable
files; use Open in trex for the internal preview.

Click the column headings to sort by name, byte size, packed size, modification
time, or file type. Packed sizes and modification dates are shown only when
already supplied by the reader; blank cells mean unavailable metadata. Folder
sizes are not recursively calculated while listing. Folders stay
first in either sort direction. The filter matches names in the current folder.
The file-type column uses filename extensions; actual format detection occurs
when an item is opened, avoiding reads of every file on a network share.

| Action | Shortcut |
| --- | --- |
| Open selected item | Enter |
| Open selected file in system viewer | Ctrl+Enter / Command+Enter |
| Context menu for selection | Shift+F10 |
| Parent directory, including out of an archive | Backspace / Alt+Up |
| Back / Forward | Alt+Left / Alt+Right |
| Edit address | Ctrl+L (Command+L on macOS) |
| Filter current folder | Ctrl+F (Command+F on macOS) |
| Open menu bar menus | Alt+F / Alt+E / Alt+V / Alt+T / Alt+H |
| Move selection / scroll preview | Arrows, Page Up/Down, Home/End |
| Scroll preview horizontally | Left/Right, horizontal wheel, or Shift+wheel |
| Cycle list, address and filter focus | Tab / Shift+Tab |
| Return focus to list and clear filter | Escape |
| Select all / copy / paste in a field | Ctrl+A / Ctrl+C / Ctrl+V |

Archive browsing reuses trex `auto` detectors, including ZIP, 7z, tar,
compressed streams, CAB, WIM, ISO filesystems, disk partitions, and supported
legacy formats. Format-specific limitations and the auto API's expansion,
entry and depth limits still apply. Unsupported ordinary files open in the
preview; malformed recognized containers report their parser error and retain
the previous location. Previews read at most 64 KiB and choose text or hex from
the bytes. Browsing and preview do not extract, execute or modify files; saving
and desktop handoff require the explicit actions described above.

Directory enumeration and parsing run on a worker, keeping the window event
loop responsive. Navigation waits for an outstanding read to complete. Host
read handles are opened lazily and capped at 64; links and special files are
omitted. Directory and decoded archive views are cached for the session, so
restart the browser to refresh changed source media. Expanded archive bytes
remain in memory for the lifetime of their cached views.

Windows uses Win32/WGL, macOS uses Cocoa/OpenGL, and Linux uses X11/GLX through
gowin. Build with Go 1.25.5 or newer and initialized repository submodules.
Linux needs the X11 and OpenGL runtime libraries and a display. From WSL, a
Windows build can run directly against Windows drive letters:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/trex-browser.exe ./cmd/trex-browser
/tmp/trex-browser.exe 'L:\'
```

Focused tests run with `go test ./frontend/archivegui`. The optional real-window
test runs with `TREX_BROWSER_GUI_TEST=1 go test ./frontend/archivegui -run TestDesktop -v`.
It checks nested navigation, filtering, and history using in-memory fixtures.
Set `TREX_BROWSER_ROOT` and `TREX_BROWSER_OPEN` to test a real archive library;
`TREX_BROWSER_SCREENSHOT` optionally writes the final window screenshot to the
specified output path. The desktop test requires a display and currently runs
on Windows/Linux; the macOS main-thread requirement is handled by the command.
`TREX_BROWSER_VIEWER_FILE` enables `TestSystemViewer` with an existing document;
it actually launches the associated application and is skipped by default.
The desktop smoke also verifies independent monospace glyph advances and a
multi-line hex preview in the same window. `TREX_BROWSER_HEX_SCREENSHOT` writes
that preview as an optional final screenshot.
