"""Explicit adapter inventory for a machine with no IPv4 network adapters."""

def no_ipv4_adapters_plugin():
    """Models GetAdaptersInfo for an explicitly empty IPv4 adapter inventory.

    This API excludes loopback. It returns ERROR_NO_DATA, never a fabricated
    adapter or successful empty linked list. It is not installed by default;
    disconnected but configured adapters require a different inventory model.
    """
    def adapters(event):
        if not event.args[1]:
            return 87  # ERROR_INVALID_PARAMETER
        # Validate the required ULONG storage without inventing an output size
        # for this error result. There is no adapter list to write.
        size = event.machine.read_u32le(event.args[1])
        event.machine.write_u32le(event.args[1], size)
        return 232  # ERROR_NO_DATA
    def install(machine):
        machine.provide_export(adapters, module = "iphlpapi.dll", name = "GetAdaptersInfo", argc = 2)
    return emulator.plugin(install, name = "windows.iphlpapi.no-ipv4-adapters", state = {})
