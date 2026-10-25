"""Native PE registry observation ABI, bounds and handle-lifetime check."""
load("//trex/scripts/guest/windows_extension:build_pe.star", "compile_pe")

def check(value, message):
    if not value:
        fail(message)

def validate(architecture):
    # No costly shared prefix/checkpoint: this executes the bounded endpoint.
    machine = emulator.machine(image = compile_pe("trex", architecture = architecture), instruction_limit = 3000000)
    plugin = emulator.plugin(lambda machine: None, state = {"input": 0, "output": [], "opened": [], "closed": []})
    machine.use(plugin)
    state = plugin.state
    request = b"?\nCALL\tread_registry\tsHKLM\tsSoftware\\\\Example\tsNumber\nCALL\tread_registry\tsHKCC\tsDisplay\\\\Settings\tsBitsPerPixel\nCALL\tread_registry\tsHKU\tsExample\tsLarge\n"
    command = machine.allocate(value = b"endpoint.exe\x00")
    environment = machine.allocate(value = b"\x00\x00")
    def read(event):
        if state["input"] == len(request):
            return 0
        machine.write(event.args[1], request[state["input"]:state["input"] + 1])
        machine.write_u32le(event.args[3], 1)
        state["input"] += 1
        return 1
    def write(event):
        state["output"].append(machine.read(event.args[1], event.args[2]))
        machine.write_u32le(event.args[3], event.args[2])
        return 1
    def open_key(event):
        index = len(state["opened"])
        expected = [0x80000002, 0x80000005, 0x80000003][index]
        if architecture == "amd64":
            expected |= 0xffffffff00000000
        check(event.args[0] == expected, "predefined HKEY sign extension: " + str((architecture, event.args[0], expected)))
        check(event.args[2:4] == [0, 0x20019], "registry open must be read-only")
        state["opened"].append(machine.read_cstring(event.args[1]))
        if architecture == "amd64":
            machine.write_u64le(event.args[4], 0x1200 + index)
        else:
            machine.write_u32le(event.args[4], 0x1200 + index)
        return 0
    def query(event):
        check(event.args[2] == 0 and machine.read_u32le(event.args[5]) == 256, "bounded registry query")
        name = machine.read_cstring(event.args[1])
        if name == "Large":
            machine.write_u32le(event.args[5], 400)
            return 234
        value, kind = (b"\x01\x00\x00\x00", 4) if name == "Number" else (b"32\x00", 1)
        machine.write_u32le(event.args[3], kind)
        machine.write(event.args[4], value)
        machine.write_u32le(event.args[5], len(value))
        return 0
    def close_key(event):
        state["closed"].append(event.args[0])
        return 0
    for name, count, hook in [
        ("GetCommandLineA", 0, lambda e: command), ("GetEnvironmentStringsA", 0, lambda e: environment),
        ("GetStdHandle", 1, lambda e: 1), ("CreateFileA", 7, lambda e: 1),
        ("GetCommState", 2, lambda e: 1), ("SetCommState", 2, lambda e: 1),
        ("SetCommTimeouts", 2, lambda e: 1), ("CloseHandle", 1, lambda e: 1),
        ("ReadFile", 5, read), ("WriteFile", 5, write), ("ExitProcess", 1, lambda e: machine.stop("endpoint-exit")),
    ]:
        machine.hook(hook, module = "kernel32.dll", name = name, argc = count)
    for name, count, hook in [("RegOpenKeyExA", 5, open_key), ("RegQueryValueExA", 6, query), ("RegCloseKey", 1, close_key)]:
        machine.hook(hook, module = "advapi32.dll", name = name, argc = count)
    result = machine.call(machine.entry, args = [])
    check(result.reason == "endpoint-exit", "native endpoint failed: " + result.reason + " " + result.detail)
    reply = binary.text(binary.concat(state["output"]))
    check("FN\tread_registry\tmap" in reply, "registry endpoint discovery")
    check("OK\tm2\tstype\ti4\tsdata_hex\ts01000000\n" in reply, "DWORD registry observation")
    check("OK\tm2\tstype\ti1\tsdata_hex\ts333200\n" in reply, "string registry observation")
    check(reply.endswith("ERR\tswin32\tsWindows error 234\n"), "oversized value must be rejected")
    check(state["closed"] == [0x1200, 0x1201, 0x1202], "query success and failure must close owned keys")

def main(args):
    for architecture in ["386", "amd64"]:
        validate(architecture)
    print("PASS native x86/x64 registry query bounds, predefined handles and cleanup")
