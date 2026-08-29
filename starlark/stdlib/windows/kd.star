"""Windows KD event and inspection policy over the native transport session."""

load("@stdlib//windows:symbols.star", "canonical_address")

def wait_for(kd, kinds, timeout = 30):
    """Returns the next KD event whose kind is selected."""
    deadline = clock.monotonic() + timeout
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for KD event")
        event = kd.next_event(timeout = remaining)
        if event.kind in kinds:
            return event

def wait_for_exception(kd, timeout = 30):
    """Waits for a kernel exception state change."""
    return wait_for(kd, ["exception"], timeout = timeout)

def delayed_breakin(kd, delay, timeout = 30):
    """Requests a KD break-in after a selectable delay unless an event arrives first."""
    if delay < 0:
        fail("delay must be non-negative")
    ready = debug.select([kd], timeout = delay)
    if ready == None:
        kd.breakin()
    return kd.next_event(timeout = timeout)

def continue_until(kd, predicate, timeout = 30, status = 0x00010002):
    """Continues state changes until predicate accepts an event."""
    deadline = clock.monotonic() + timeout
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for matching KD event")
        event = kd.next_event(timeout = remaining)
        if predicate(event):
            return event
        if event.kind in ["exception", "load_symbols", "command_string", "state"]:
            getattr(kd, "continue")(status = status)

def read_int(kd, address, size, signed = False):
    """Reads a little-endian integer from kernel virtual memory."""
    data = kd.read_virtual(address, size)
    encoded = hex(data)
    ordered = ""
    index = len(encoded) - 2
    while index >= 0:
        ordered += encoded[index:index + 2]
        index -= 2
    value = int(ordered, 16) if ordered else 0
    if signed and size and value & (1 << (size * 8 - 1)):
        value -= 1 << (size * 8)
    return value

def read_u32(kd, address):
    """Reads a little-endian kernel uint32."""
    return read_int(kd, address, 4)

def pointer_chain(kd, address, offsets, pointer_size = 4):
    """Follows kernel pointers through signed offsets."""
    current = address
    for offset in offsets:
        current = read_int(kd, current, pointer_size) + offset
    return current

def break_on_module(kd, event, pdb = None, symbol = None, rva = None):
    """Installs a breakpoint relative to one load-symbols event."""
    if event.kind != "load_symbols" or event.unload:
        fail("break_on_module requires a module-load event")
    if (symbol == None) == (rva == None):
        fail("specify exactly one of symbol or rva")
    if symbol != None:
        matches = pdb.find(symbol, exact = True)
        if not matches:
            fail("symbol not found: " + symbol)
        rva = matches[0].rva
    return kd.breakpoint(canonical_address(event.base) + rva)
