# Native Win16 extension

This is a Renvo-built Windows NE task, not the DOS COM endpoint hosted inside
Windows. `build.star` assembles the source and backend in memory. It shares the
bounded parser and dispatch/file policy in `../dos_extension/{protocol,core}.go`,
but uses Windows KERNEL file APIs, USER communication APIs, and a cooperative
message loop. Directory services use the guest's virtualized DOS interrupt.

`compile_win16(root, windows3=False)` builds for Windows 1.x/2.x. Pass
`windows3=True` for Windows 3.x. That variant declares the Windows GUI NE flags,
expected Windows version 3.0, and linker generation 5. Setting only the expected
version is insufficient to avoid Windows 3.11's compatibility dialog.

The backend emits separate near code and automatic data segments, Pascal
ordinal imports, a reserved Windows instance header, and bounded heap/stack
space. Imported-name offset zero is reserved: Windows 1 treats it as SELF.
Windows calls restore ES=DS before returning to near-copy code. Do not replace
native launch with DOS EXEC or resize the DOS PSP.

The manifest advertises ASCII paths, hex-encoded binary data, eight open file
slots, one directory enumeration, and `launch(path, tail)`. Launch returns an
instance handle when LoadModule accepts a native application. It does not wait
or capture output. Process wait, cancellation, Unicode paths, and exit codes
are not advertised by this generation.

From the public checkout:

```
go run ./cmd/trex scripts/guest/windows_extension/check.star
go test ./scripts/guest/dos_extension
```

The image check compiles the file, display and computer-use variants and checks loader-sensitive headers,
segment/stack bounds, import-name resolution, and native-call relocations.
Fresh guest integration remains necessary. The private repository supplies
`scripts/smoke/windows_extension.star` and `windows_extension_client.star`.

`compile_win16(display_agent=True)` builds a compact native display observation
endpoint with `ping`, `launch`, and `display_geometry`. The latter reports
`width`/`height` from USER.GetSystemMetrics and `device_width`/`device_height`
from GDI.GetDeviceCaps on a temporarily acquired desktop DC. This separate
build keeps both it and the file-service build within the 64 KiB code-segment
limit. The computer-use build also advertises `display_geometry`.
Fresh CrumbleCracker COM1 smokes verify all four values against framebuffer
capture on Windows 1.01 (640×350), 2.03 (640×480), and 3.11 (640×480).
These checks observe native geometry; they do not demonstrate a live mode change.

`compile_win16(resize_helper=True)` builds a separate windowless task for the
recipe's native framebuffer driver and USER geometry extension. It polls the
TRF1/RSZ1 mailbox through GDI Escape, applies geometry through the USER entry,
and acknowledges success only when both USER and GDI report the requested size.
It needs no serial connection. Real-mode Windows may compact its data segment,
so it refreshes DS before forming far pointers. Each loop explicitly yields to
other cooperative tasks. The private fresh-image resize smokes cover Windows
1.01, 2.03, 3.11 and Workgroups 3.11 with the same live Notepad instance.

## Windows 1.01 computer use

`compile_win16(computer_use=True)` builds a separate native computer-use endpoint
with `ping`, `launch`, and bounded `input_events` batches. USER journal playback
handles keyboard/mouse routing; the host only captures the framebuffer. The
client helpers provide click, drag, key chords, and a US-layout text subset.
This build targets Windows 1.01, not the later Win16 hook ABI. It does not
advertise the file-service APIs; combining both currently exceeds the near-code
segment limit. See [the public demo guide](../../../docs/windows-101-computer-use.md)
for the standalone public trex script, explicit media arguments, REPL wire
documentation, native-input constraints, and continuous FFmpeg boot recording.

## Native PE endpoint (in progress)

`build_pe.star` builds `win32/` with the shared bounded wire parser. Discovery
uses `?`, as required by the extension protocol. Files use native Win32 APIs;
processes use CreateProcessA, nonblocking WaitForSingleObject, termination, and
explicit handle release. A completed process may legitimately have exit code
259: inspect the wait result before GetExitCodeProcess. Process slots are reused
and are not durable identifiers. Output capture and Unicode are not implemented.
Paths support ASCII long filenames within the 259-byte bound, not extended paths.
`display_geometry()` returns USER's screen dimensions and GDI's device extent,
using a freshly acquired and released desktop DC on every call.
`read_ini(path, section, key)` returns the native profile API's value as hex,
bounded to 255 bytes. An absent key returns an empty string; this observes
Windows' profile resolution, which can differ from the file's contents.
`read_registry(root, key, name)` reads one native value from `HKLM`, `HKCC`,
`HKCU`, or `HKU`; its result contains the numeric `type` and `data_hex`.
Keys are opened read-only and closed after both successful and failed queries.
Values over 256 bytes are rejected. The native x86/x64 ABI and bounds are checked
by `registry_check.star`.

`compile_pe(trust=True)` adds `verify_trust(path)` on Windows XP and later.
It asks the native Authenticode provider to verify the file, suppresses UI and
network retrieval, and always releases verification state. The result contains
`trusted` (true only for status zero) and the unsigned 32-bit native `status`.
This observes the guest's certificate stores and local revocation cache; it
does not perform an online revocation check. The default build retains its
older Windows imports and does not advertise this command.

The `early_nt=True` 386 backend targets NT 3.1's PE version and baseline imports.
It distinguishes PC-relative x86 data references from absolute IAT calls and
maps custom static imports after the runtime import slots. Other architectures
and Windows generations still require their own integration proof.

Unattended fresh-image smoke has passed on NT 3.1 Workstation/Advanced Server,
NT 3.5 Workstation/Server, NT 3.51 Workstation/Server, NT 4.0
Workstation/Enterprise Server SP3, Windows 95 RTM and OSR2.5, Windows 98
First and Second Edition, and Windows Me. Additional fresh native smokes passed
on Windows 2000 Professional SP1, Advanced Server SP4 and Datacenter SP1;
XP Professional SP3 x86 and x64 SP2; Server 2003 R2 Standard SP2; Vista Ultimate SP2 x86;
and Windows 7 Ultimate SP1 x86. XP x64 uses a native AMD64 endpoint; the other
listed targets use 386.
`window_visible(class_name, title)` queries `FindWindowA` and `IsWindowVisible` on
the endpoint's desktop. Supply an ASCII class, title, or both; one empty
argument is a wildcard. It returns false for absent or hidden windows and
does not activate or alter a window. GUI automation can use this to distinguish
endpoint readiness from shell or application visibility during first logon.
`window_active(class_name, title)` additionally requires that the matching
window is foreground, using `GetForegroundWindow`. This prevents input from
going to another visible window; the query itself does not change focus.

The private repository supplies `windows_pe_extension.star` and
`windows_pe_extension_client.star`: 4096-byte binary I/O, long-name enumeration,
rename/remove, native GUI launch, input-idle synchronization, process
polling/termination (exit codes 37 and 259), and 128 persistent calls.
The 9x selectors are `win95rtm`, `win95osr25`, `win98fe`, `win98se`, and
`winme`. They use the same 386 executable, an installed COM1 devnode, and
WIN.INI startup while retaining Explorer. Each passed from a fresh image
without interactive startup assistance. Separate OSR2/OSR2.1 media was not
available and those revisions are not independently validated.

`wait_input_idle(process, milliseconds)` uses native USER32 WaitForInputIdle,
accepts 0..1000 ms per call, and distinguishes timeout from failure. It proves
initial GUI input readiness, not application-specific success. The native smoke
waits for this before termination; immediate termination during NT 3.1 GUI
initialization was observed to produce exit code zero instead of the requested
code. Process status still uses WaitForSingleObject before inspecting exit code.

NT 3.x startup appends the agent to the existing Userinit list; NT 4 uses Run.
The transport drains bounded pre-agent firmware chatter before exposing the
protocol. NT 3.5 can launch Userinit before the automatic serial driver creates
COM1. The agent retries only the definite failed-open ERROR_FILE_NOT_FOUND for
at most 30 seconds. Other open failures and all uncertain writes are not retried.

The private NT4 recipe fixed the apparent Enterprise SP3 boot stall by decoding
its solid-7z ISO once into memory instead of replaying decompression on guest
random reads. Its fresh unattended native smoke now passes.

Serial reads have a one-second timeout. A successful zero-byte completion keeps
any partial request and continues reading; it is not EOF. The private Windows
95 RTM recipe fixes a native registry race: shell-logon validation could reopen
SYSTEM.DAT while the background writer held an exclusive handle (DOS sharing
violation 32). Its guarded RTM-only VMM transform serializes validation with the
existing registry mutex without suppressing checks or error reporting. A fresh
unattended full native smoke passed, and the matching no-endpoint base reached
a clean desktop with native mutex ownership verified during validation.
NT5/NT6 recipes assign `COM1` to the installed ACPI serial instance and start
the agent from the native Run key. XP x86 passed its full fresh unattended
smoke with a valid caller-supplied key, without additional runtime changes.
Keys are not stored in the repository. WinFLP is wired but skipped by request;
it still needs a caller key before its boot smoke. Server 2008/R2 media and
recipes are unavailable here.
Windows 2000, Vista, and Windows 7 hardware prompts also reproduced in matching
no-agent controls; they did not block the full endpoint smoke but remain base
image limitations. Windows 8 and later, and unlisted architectures, are pending.
Use backslash native
executable/working-directory paths for Win9x; its process-launch path does not
accept the slash-form paths that worked on NT.
