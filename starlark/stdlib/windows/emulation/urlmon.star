"""Explicit disconnected URLMon policy for offline installer execution."""

def offline_urlmon_plugin():
    """Rejects HTTP(S) stream binding when the modeled machine has no network.

    This must be selected explicitly by the image/probe, not installed as a
    default fallback for a missing network implementation. No request is sent,
    no completion callback is invented, and no content is returned.
    """
    state = {"requests": []}
    def open_stream(event):
        if not event.args[1] or event.args[2] & 0xffffffff:
            return 0x80070057  # E_INVALIDARG
        url = event.machine.read_cstring(event.args[1], encoding = "utf16le")
        if not url.lower().startswith("http://") and not url.lower().startswith("https://"):
            fail("offline URLMon stream policy only models HTTP(S) connection failure")
        state["requests"].append({"api": "URLOpenStreamW", "url": url, "result": 0x800c0004})
        return 0x800c0004  # INET_E_CANNOT_CONNECT; binding was not initiated.
    def install(machine):
        machine.provide_export(open_stream, module = "urlmon.dll", name = "URLOpenStreamW", argc = 4)
    return emulator.plugin(install, name = "windows.urlmon.offline", state = state)
