"""Event-driven portable VM automation without implicit sleeps."""

KEYS = {
    "ALT": "alt",
    "BACKSPACE": "backspace",
    "CONTROL": "control",
    "DELETE": "delete",
    "DOWN": "down",
    "END": "end",
    "ENTER": "enter",
    "ESCAPE": "escape",
    "HOME": "home",
    "LEFT": "left",
    "PAGE_DOWN": "page_down",
    "PAGE_UP": "page_up",
    "RIGHT": "right",
    "SHIFT": "shift",
    "SPACE": "spc",
    "TAB": "tab",
    "UP": "up",
}

def wait_for_event(vm, kinds, timeout = 30):
    """Returns the first event whose kind is in kinds before timeout."""
    deadline = clock.monotonic() + timeout
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for VM event")
        event = vm.next_event(timeout = remaining)
        if event.kind in kinds:
            return event

def wait_until(vm, predicate, timeout = 30):
    """Evaluates predicate after each VM event until it returns a value."""
    deadline = clock.monotonic() + timeout
    value = predicate(vm)
    while not value:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for VM condition")
        vm.next_event(timeout = remaining)
        value = predicate(vm)
    return value

def wait_duration(vm, seconds):
    """Waits using selectable VM events while draining them deterministically."""
    if seconds < 0:
        fail("duration must be non-negative")
    deadline = clock.monotonic() + seconds
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            return
        ready = debug.select([vm], timeout = remaining)
        if ready == None:
            return
        vm.next_event(timeout = 0)

def paced_tap(vm, key, hold = 0.1):
    """Presses and releases one key with a guest-visible hold interval."""
    if hold < 0:
        fail("key hold duration must be non-negative")
    vm.key(key, down = True)
    wait_duration(vm, hold)
    vm.key(key, down = False)

def paced_chord(vm, keys, interval = 0.1, hold = 0.1):
    """Sends a chord with explicit key transitions for legacy guest loops."""
    if not keys:
        fail("paced chord requires at least one key")
    if interval < 0 or hold < 0:
        fail("paced chord timings must be non-negative")
    pressed = []
    for key in keys:
        vm.key(key, down = True)
        pressed.append(key)
        if len(pressed) < len(keys):
            wait_duration(vm, interval)
    wait_duration(vm, hold)
    for key in reversed(pressed):
        vm.key(key, down = False)
        if len(pressed) > 1:
            wait_duration(vm, interval)

def pump_events(sources, handlers = {}, until = None, timeout = 30, max_events = 4096):
    """Dispatches VM/debugger events until a predicate accepts one.

    Each handler is selected by event kind and receives `(source, event)`.
    `until`, when supplied, receives the same pair after dispatch. The returned
    record preserves the selected source, event, and total dispatch count.
    """
    if not sources:
        fail("event pump requires at least one source")
    if timeout < 0:
        fail("event pump timeout must be non-negative")
    if max_events < 1 or max_events > 1000000:
        fail("invalid event pump budget")
    deadline = clock.monotonic() + timeout
    count = 0
    while count < max_events:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out pumping events")
        source = debug.select(sources, timeout = remaining)
        if source == None:
            fail("timed out pumping events")
        event = source.next_event(timeout = 0)
        count += 1
        handler = handlers.get(event.kind)
        if handler != None:
            handler(source, event)
        if until == None or until(source, event):
            return {"source": source, "event": event, "count": count}
    fail("event pump exceeded its event budget")

def click(vm, x, y, absolute = True, button = "left"):
    """Sends one portable pointer click at the selected position."""
    x = float(x)
    y = float(y)
    vm.pointer(x = x, y = y, absolute = absolute, buttons = [])
    press_x = x if absolute else 0.0
    press_y = y if absolute else 0.0
    vm.pointer(x = press_x, y = press_y, absolute = absolute, buttons = [button])
    vm.pointer(x = press_x, y = press_y, absolute = absolute, buttons = [])

def checkpoint(vm, format = "png"):
    """Returns an in-memory framebuffer checkpoint as a file value."""
    return vm.screenshot(format = format)

def repeat_ui(vm, procedure, count, settle = 0, screenshots = True):
    """Runs a guest UI procedure repeatedly and returns framebuffer checkpoints."""
    if count < 0 or count > 100000:
        fail("invalid repetition count")
    captures = []
    index = 0
    while index < count:
        procedure(vm, index)
        if settle:
            wait_duration(vm, settle)
        if screenshots:
            captures.append(checkpoint(vm))
        index += 1
    return captures
