"""Breakpoint and watchpoint orchestration expressed as session-local policy."""

load("@stdlib//debug:gdb.star", "follow_return_pattern", "step_over", "wait_for_pc")

def wait_hits(gdb, point, count, predicate = None, resume = True):
    """Collects count matching stops for an installed point."""
    hits = []
    while len(hits) < count:
        if resume:
            getattr(gdb, "continue")()
        stop = gdb.wait()
        if predicate == None or predicate(stop):
            hits.append(stop)
    return hits

def ordered_breakpoints(gdb, addresses, hits = 1, kind = "hardware"):
    """Visits addresses in order using only one active point at a time."""
    stops = []
    for address in addresses:
        stops += _execution_breakpoint_hits(gdb, address, hits, kind = kind)
    return stops

def repeated_breakpoint(gdb, address, hits, predicate = None, kind = "hardware"):
    """Collects repeated filtered hits at one execution address.

    A raw GDB execution breakpoint stops before its instruction. Re-arm it
    after each stop so continuing cannot immediately report the same hit.
    """
    return _execution_breakpoint_hits(gdb, address, hits, predicate, kind)

def _execution_breakpoint_hits(gdb, address, hits, predicate = None, kind = "hardware"):
    stops = []
    while len(stops) < hits:
        point = gdb.breakpoint(address, kind = kind)
        stop = wait_for_pc(gdb, address, resume = True)
        point.remove()
        accepted = predicate == None or predicate(stop)
        if accepted:
            stops.append(stop)
        if len(stops) < hits:
            # Execute the stopped instruction before re-arming its address.
            gdb.step()
            gdb.wait()
    return stops

def follow_write(gdb, address, size, hits = 1, access = "write"):
    """Collects stops from a temporary data watchpoint."""
    point = gdb.watchpoint(address, size, access = access)
    stops = wait_hits(gdb, point, hits)
    point.remove()
    return stops

def filtered_breakpoint_hits(gdb, address, count, predicate, kind = "hardware"):
    """Collects repeated breakpoint stops accepted by a Starlark predicate."""
    return repeated_breakpoint(gdb, address, count, predicate = predicate, kind = kind)

def chained_return_search_watch(
        gdb,
        entry_stop,
        pattern,
        occurrence,
        search_offset,
        watch_address,
        watch_size,
        watch_hits = 1):
    """Follows a return-side pattern and then collects writes at an address."""
    point = follow_return_pattern(gdb, entry_stop, pattern, occurrence, search_offset)
    getattr(gdb, "continue")()
    pattern_stop = gdb.wait()
    point.remove()
    watch = gdb.watchpoint(watch_address(pattern_stop), watch_size, access = "write")
    stops = wait_hits(gdb, watch, watch_hits)
    watch.remove()
    return {"pattern_stop": pattern_stop, "watch_stops": stops}

def delayed_snapshot(gdb, delay, continue_after = False, timeout = 30):
    """Interrupts after a selectable delay and captures a structured stop."""
    if delay < 0:
        fail("delay must be non-negative")
    ready = debug.select([gdb], timeout = delay)
    if ready == None:
        gdb.interrupt(timeout = timeout)
    stop = gdb.wait(timeout = timeout)
    if continue_after:
        getattr(gdb, "continue")(timeout = timeout)
    return stop

def run_window(gdb, duration, predicate = None, inspect_interval = None, max_stops = 4096, timeout = 30, resume = True):
    """Runs through incidental stops for a duration, then captures a stop.

    This is intended for noisy whole-system targets where an ordinary delayed
    snapshot would return early on the first unrelated exception.  A predicate
    can accept a stop early, and inspect_interval creates periodic stopped-state
    observations even when the target emits no events.  The stop budget bounds
    pathological targets and the result reports how many stops were resumed.
    """
    if duration <= 0:
        fail("run window duration must be positive")
    if max_stops < 1 or max_stops > 1000000:
        fail("invalid run window stop budget")
    if inspect_interval != None and (inspect_interval <= 0 or inspect_interval > duration):
        fail("invalid run window inspection interval")
    deadline = clock.monotonic() + duration
    stops = 0
    if resume:
        getattr(gdb, "continue")(timeout = timeout)
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            gdb.interrupt(timeout = timeout)
            return {"stop": gdb.wait(timeout = timeout), "matched": False, "resumed_stops": stops}
        wait = min(remaining, inspect_interval) if inspect_interval != None else remaining
        ready = debug.select([gdb], timeout = wait)
        if ready == None:
            gdb.interrupt(timeout = timeout)
        stop = gdb.wait(timeout = timeout)
        if predicate != None and predicate(stop):
            return {"stop": stop, "matched": True, "resumed_stops": stops}
        if clock.monotonic() >= deadline:
            return {"stop": stop, "matched": False, "resumed_stops": stops}
        stops += 1
        if stops >= max_stops:
            fail("run window exceeded its incidental-stop budget")
        getattr(gdb, "continue")(timeout = timeout)

def selective_step_trace(gdb, stop, count, into_call_targets = [], predicate = None, timeout = 30):
    """Steps over calls selectively while collecting filtered stop records."""
    output = []
    current = stop
    while len(output) < count:
        current = step_over(gdb, current, into_call_targets, timeout)
        if predicate == None or predicate(current):
            output.append(current)
    return output

def step_many(gdb, count):
    """Single-steps count instructions and returns every stop."""
    stops = []
    while len(stops) < count:
        gdb.step()
        stops.append(gdb.wait())
    return stops
