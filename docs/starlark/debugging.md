# VMM and debugger workflows

Stable automation uses `vmm` sessions and capability checks. QEMU process,
socket, QMP, and transport details remain behind the backend. Backend-specific
experiments use `qemu.extension(vm)` explicitly.

```starlark
if not vm.has_capability("screenshot"):
    fail("backend cannot capture the display")

vm.tap("escape")
vm.chord(["control", "alt", "delete"])
vm.type_and_enter("dir C:\\")
screen = vm.screenshot()
```

Canonical navigation keys are listed as `KEYS` in
`@stdlib//vmm:automation.star`. A backend translates them to its native input
protocol. `key(name, down)` remains available for unusual press/release
sequences.

## Events and deadlines

Use `clock.monotonic()` for elapsed-time deadlines. Wall-clock changes must not
extend or shorten protocol waits. `debug.select()` and the helpers in
`vmm/automation.star`, `debug/gdb.star`, and `windows/kd.star` wait on events
without polling or implicit sleeps.

```starlark
load("@stdlib//vmm:automation.star", "pump_events", "wait_for_event")

event = wait_for_event(vm, ["started", "stopped"], timeout = 30)

def reached_desktop(source, event):
    return event.kind == "desktop"

result = pump_events(
    [vm, kd],
    handlers = {"exception": handle_exception},
    until = reached_desktop,
    timeout = 90,
)
```

`pump_events` selects across VMM and debugger sources, dispatches handlers by
event kind, and bounds both elapsed time and event count. Lower-level
`debug.select` and `next_event` remain available for unusual protocols.

`clock.profiler()` records nested spans and counters. Its snapshot contains
nanosecond timestamps, durations, and union coverage. `report()` requires at
least 95% coverage by default and attaches `runtime.stats()` byte and cache
metrics. Timeout APIs continue to accept finite seconds as integers or floats.

## Debug channels

Open debugger transports through the VM session:

```starlark
channel = vm.debugger("gdb", create = True, paused = True)
gdb = debug.gdb(channel)
stop = gdb.wait(timeout = 30)
print(stop.registers)
```

Windows KD uses `windows.kd(channel)` and the policy helpers in
`@stdlib//windows:kd.star`. Keep packet manipulation in Go and target-specific
symbol, process, and stop policy in Starlark. Both GDB and KD sessions are
runtime resources and close in reverse creation order.

## Shutdown and postmortem state

`vm.shutdown(timeout=30, force=True, force_timeout=10)` requests guest poweroff,
waits for the result, and uses the backend stop operation only after the grace
period. Repeated `wait()` calls return the cached result; `vm.result` exposes it
without consuming backend state. `vm.detach()` deliberately transfers
ownership out of automatic runtime cleanup.

Capture a framebuffer with `vm.screenshot()` and disk state with
`working.snapshot()`. Neither requires stopping the VM or writing a raw disk.
