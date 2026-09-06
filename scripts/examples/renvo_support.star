"""Execute Renvo Windows/386 programs entirely in the Trex x86 emulator."""

def execute(binary, expected_exit=0):
    """Run a binary and return its captured stdout after checking its exit code."""
    machine = emulator.x86(image=binary, image_name="renvo.exe", memory_limit=4 << 20, instruction_limit=1000000, fs_base=0x7ffde000)
    slots = machine.allocate(size=64 * 4, name="TLS slots")
    machine.write_u32le(0x7ffde000 + 0x18, 0x7ffde000)
    machine.write_u32le(0x7ffde000 + 0x20, 4)
    machine.write_u32le(0x7ffde000 + 0x24, 8)
    machine.write_u32le(0x7ffde000 + 0x2c, slots)
    state = {"stdout": b"", "exit": None}

    def get_std_handle(event):
        return 0x70000001 if event.args[0] == 0xfffffff5 else 0x70000002

    def write_file(event):
        data = event.machine.read(event.args[1], event.args[2])
        state["stdout"] += data
        if event.args[3]:
            event.machine.write_u32le(event.args[3], len(data))
        return 1

    def exit_process(event):
        state["exit"] = event.args[0]
        event.machine.stop("success", "", 0)
        return 0

    machine.hook(get_std_handle, module="kernel32.dll", name="GetStdHandle", argc=1)
    machine.hook(write_file, module="kernel32.dll", name="WriteFile", argc=5)
    machine.hook(exit_process, module="kernel32.dll", name="ExitProcess", argc=1)
    result = machine.run()
    if result.reason != "success":
        fail("emulation failed: " + str(result))
    if state["exit"] != expected_exit:
        fail("exit code: got %s, want %s" % (state["exit"], expected_exit))
    return state["stdout"]
