"""Explicit disconnected WinINet session model; no network access."""

def disconnected_wininet_plugin():
    """Creates local Internet sessions, but never fabricates network content.

    Only direct/preconfigured sessions and their owned lifetime are
    currently modeled. Other operations remain missing rather than succeeding.
    """
    state = {"handles": {}, "actions": []}
    def last_error(machine, code):
        result = machine.invoke(machine.resolve_export("kernel32.dll", name = "SetLastError"), args = [code])
        if result.reason != "return":
            fail("WinINet could not set the modeled thread error")
        return 0
    def open_session(event):
        m = event.machine
        agent, access, proxy, bypass, flags = event.args
        access &= 0xffffffff
        flags &= 0xffffffff
        if access not in [0, 1] or proxy or bypass or flags not in [0, 0x10000000]:
            fail("unsupported disconnected WinINet session options: access=%d flags=0x%x proxy=%s bypass=%s" % (access, flags, bool(proxy), bool(bypass)))
        handle = m.allocate(size = m.pointer_size, name = "wininet-session")
        state["handles"][handle] = {"kind": "session", "agent": m.read_cstring(agent, encoding = "utf16le") if agent else "", "access": access, "async": bool(flags & 0x10000000)}
        state["actions"].append({"api": "InternetOpenW", "handle": handle})
        return handle
    def close(event):
        handle = event.args[0]
        if handle not in state["handles"]:
            return last_error(event.machine, 6)
        state["handles"].pop(handle)
        event.machine.free(handle)
        return 1
    def install(machine):
        machine.provide_export(open_session, module = "wininet.dll", name = "InternetOpenW", argc = 5)
        machine.provide_export(close, module = "wininet.dll", name = "InternetCloseHandle", argc = 1)
    return emulator.plugin(install, name = "windows.wininet.disconnected", state = state)
