HELLO = """
package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
"""

STD_OUTPUT_HANDLE = 0xfffffff5
STD_ERROR_HANDLE  = 0xfffffff4

stdout_handle = 0x70000001
stderr_handle = 0x70000002

def main(args):
    source_fs = directory()
    source_fs.mkdir("src")
    source_fs.write("src/main.go", HELLO)
    source_fs.write("src/go.mod", "module hello")

    start = clock.monotonic()
    result = renvo.go(
        source = source_fs,
        input = "src",
        target = "windows/386",
        arena_size = 1 * 1024 * 1024,
    )
    if not result.ok:
        fail(result.diagnostic)
    elapsed = clock.monotonic() - start

    print("compilation time:", elapsed)

    write("main.exe", result.binary)

    machine = emulator.x86(
        image = result.binary,
        image_name = "main.exe",

        memory_limit = 4 << 20,

        instruction_limit = 100000,
        fs_base = 0x7ffde000,
    )

    tls_slots = machine.allocate(
        size = 64 * 4,
        name = "TLS slots",
    )

    machine.write_u32le(0x7ffde000 + 0x18, 0x7ffde000)
    machine.write_u32le(0x7ffde000 + 0x20, 4)
    machine.write_u32le(0x7ffde000 + 0x24, 8)
    machine.write_u32le(0x7ffde000 + 0x2c, tls_slots)

    def get_std_handle(event):
        which = event.args[0]

        if which == STD_OUTPUT_HANDLE:
            return stdout_handle

        if which == STD_ERROR_HANDLE:
            return stderr_handle

        return 0xffffffff

    def write_file(event):
        handle = event.args[0]
        address = event.args[1]
        length = event.args[2]
        written = event.args[3]

        if handle not in [stdout_handle, stderr_handle]:
            return 0

        data = event.machine.read(address, length)

        if handle == stdout_handle:
            stdout(data)
        else:
            # TREX only gives us host stdout here, so prefix stderr if desired.
            stdout(data)

        if written:
            event.machine.write_u32le(written, length)

        return 1
    
    def exit_process(event):
        code = event.args[0]
        event.machine.stop("success", "", 0)

    machine.hook(get_std_handle, module = "kernel32.dll", name = "GetStdHandle", argc = 1)
    machine.hook(write_file, module = "kernel32.dll", name = "WriteFile", argc = 5)
    machine.hook(exit_process, module = "kernel32.dll", name = "ExitProcess", argc = 1)

    print("")

    result = machine.run()

    if result.reason != "success":
        fail("Emulation failed: " + result.reason)
