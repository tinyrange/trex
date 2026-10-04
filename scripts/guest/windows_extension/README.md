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

The image check compiles both variants and checks loader-sensitive headers,
segment/stack bounds, import-name resolution, and native-call relocations.
Fresh guest integration remains necessary. The private repository supplies
`scripts/smoke/windows_extension.star` and `windows_extension_client.star`.

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
