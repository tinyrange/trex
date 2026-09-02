"""Reusable GDB inspection helpers built on the native session primitives."""

def _uint(data, byteorder = "little", signed = False):
    encoded = hex(data)
    if byteorder == "little":
        ordered = ""
        index = len(encoded) - 2
        while index >= 0:
            ordered += encoded[index:index + 2]
            index -= 2
    elif byteorder == "big":
        ordered = encoded
    else:
        fail("byteorder must be little or big")
    value = int(ordered, 16) if ordered else 0
    if signed and len(data) and value & (1 << (len(data) * 8 - 1)):
        value -= 1 << (len(data) * 8)
    return value

def read_int(gdb, address, size, byteorder = "little", signed = False):
    """Reads one bounded integer from target memory."""
    return _uint(gdb.read_memory(address, size), byteorder, signed)

def read_u8(gdb, address):
    """Reads a little-endian unsigned 8-bit integer."""
    return read_int(gdb, address, 1)

def read_u16(gdb, address):
    """Reads a little-endian unsigned 16-bit integer."""
    return read_int(gdb, address, 2)

def read_u32(gdb, address):
    """Reads a little-endian unsigned 32-bit integer."""
    return read_int(gdb, address, 4)

def read_u64(gdb, address):
    """Reads a little-endian unsigned 64-bit integer."""
    return read_int(gdb, address, 8)

def read_c_string(gdb, address, maximum = 4096, encoding = "utf8"):
    """Reads a bounded NUL-terminated target string."""
    data = gdb.read_memory(address, maximum)
    end = 0
    while end < len(data) and data[end] != 0:
        end += 1
    if end == len(data):
        fail("target string exceeds configured maximum")
    return binary.text(data[:end], encoding = encoding)

def read_utf16_string(gdb, address, byte_length, maximum = 1 << 20):
    """Reads a bounded UTF-16LE string with an explicit byte length."""
    if byte_length < 0 or byte_length > maximum or byte_length % 2:
        fail("invalid UTF-16 byte length")
    return binary.text(gdb.read_memory(address, byte_length), encoding = "utf16le")

def read_utf16_c_string(gdb, address, maximum = 4096):
    """Reads a bounded NUL-terminated UTF-16LE target string."""
    if maximum < 2 or maximum % 2:
        fail("UTF-16 string maximum must be a positive even byte count")
    data = gdb.read_memory(address, maximum)
    end = 0
    while end < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    if end == len(data):
        fail("target UTF-16 string exceeds configured maximum")
    return binary.text(data[:end], encoding = "utf16le")

def read_unicode_string(gdb, address, pointer_size = 4, maximum = 1 << 20):
    """Reads a Windows UNICODE_STRING from target memory."""
    header_size = 8 if pointer_size == 4 else 16
    header = gdb.read_memory(address, header_size)
    length = _uint(header[:2])
    capacity = _uint(header[2:4])
    pointer_offset = 4 if pointer_size == 4 else 8
    pointer = _uint(header[pointer_offset:pointer_offset + pointer_size])
    if length > capacity or length > maximum or length % 2:
        fail("invalid target UNICODE_STRING")
    return read_utf16_string(gdb, pointer, length, maximum = maximum)

def pointer_chain(gdb, address, offsets, pointer_size = 4):
    """Follows a pointer through a sequence of signed offsets."""
    current = address
    for offset in offsets:
        current = read_int(gdb, current, pointer_size) + offset
    return current

def stack_argument(stop, index, pointer_size = 4):
    """Returns the address of a stack argument at a stop."""
    name = "esp" if pointer_size == 4 else "rsp"
    return stop.registers[name] + pointer_size * (index + 1)

def stack_argument_value(gdb, stop, index, pointer_size = 4):
    """Reads a pointer-sized stack argument at a stop."""
    return read_int(gdb, stack_argument(stop, index, pointer_size), pointer_size)

def frame_argument_value(gdb, stop, index, pointer_size = 4):
    """Reads a pointer-sized argument from the current frame pointer."""
    name = "ebp" if pointer_size == 4 else "rbp"
    return read_int(gdb, stop.registers[name] + pointer_size * (index + 2), pointer_size)

def _stop_pc(stop):
    if hasattr(stop, "pc"):
        return stop.pc
    registers = stop.registers
    return registers["rip"] if "rip" in registers else registers["eip"]

def wait_for_pcs(gdb, addresses, timeout = 30, max_stops = 4096, resume = False):
    """Waits for one of several exact PCs while ignoring unrelated stops.

    `resume` controls whether the target is resumed before the first wait.  Each
    rejected stop is resumed automatically.  The stop budget prevents a noisy
    target from turning a diagnostic mistake into an unbounded trace.
    """
    if max_stops < 1 or max_stops > 1000000:
        fail("invalid GDB stop budget")
    accepted = {}
    for address in addresses:
        accepted[address] = True
    if not accepted:
        fail("at least one target PC is required")
    deadline = clock.monotonic() + timeout
    count = 0
    should_resume = resume
    while count < max_stops:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for a target PC")
        if should_resume:
            getattr(gdb, "continue")(timeout = remaining)
        stop = gdb.wait(timeout = remaining)
        count += 1
        pc = _stop_pc(stop)
        if pc in accepted:
            return {"address": pc, "stop": stop, "stop_count": count}
        should_resume = True
    fail("GDB stop budget exceeded while waiting for a target PC")

def wait_for_pc(gdb, address, timeout = 30, max_stops = 4096, resume = False):
    """Waits for one exact program counter while ignoring unrelated stops."""
    return wait_for_pcs(
        gdb,
        [address],
        timeout = timeout,
        max_stops = max_stops,
        resume = resume,
    )["stop"]

def continue_to(gdb, points, timeout = 30, max_stops = 4096):
    """Continues to one installed point and returns its self-consistent stop."""
    addresses = [point.address for point in points]
    return wait_for_pcs(
        gdb,
        addresses,
        timeout = timeout,
        max_stops = max_stops,
        resume = True,
    )["stop"]

def read_process_memory(gdb, process, address, size):
    """Reads memory through a checked process directory-table base."""
    if size < 0:
        fail("process-memory read size must be non-negative")
    if type(process) == "gdb_address_space":
        if process.kind != "user":
            fail("read_process_memory requires a user address space")
        return process.read_memory(address, size)
    return gdb.with_register(
        "cr3",
        process["directory_table_base"],
        lambda: gdb.read_memory(address, size),
    )

def process_address_space(gdb, process):
    """Returns a checked user address-space handle for a process record."""
    return gdb.address_space(process["directory_table_base"], kind = "user")

def kernel_address_space(gdb, page_table):
    """Returns a checked kernel address-space handle."""
    return gdb.address_space(page_table, kind = "kernel")

def breakpoints_all(gdb, addresses, kind = "hardware"):
    """Installs corresponding points on every advertised remote thread."""
    if not addresses:
        fail("breakpoints_all requires at least one address")
    threads = gdb.threads()
    if not threads:
        fail("GDB target advertises no remote threads")
    current = gdb.current_thread()
    if len(addresses) < len(threads):
        fail("breakpoints_all requires one distinct address per remote thread")
    points = []
    for index in range(len(threads)):
        thread = threads[index]
        address = addresses[index]
        gdb.select_thread(thread)
        points.append({
            "address": address,
            "point": gdb.breakpoint(address, kind = kind),
            "thread": thread,
        })
    gdb.select_thread(current)
    return points

def watchpoints_all(gdb, address, size = 1, access = "write"):
    """Installs a distinct per-thread watchpoint and restores selection.

    QEMU models hardware debug registers per vCPU. Adjacent byte addresses keep
    each remote thread's point distinct while still detecting a write to the
    watched field covered by the first `size` bytes.
    """
    if size < 1:
        fail("watchpoints_all requires a positive size")
    threads = gdb.threads()
    if not threads:
        fail("GDB target advertises no remote threads")
    current = gdb.current_thread()
    points = []
    for index in range(len(threads)):
        thread = threads[index]
        site = address + index
        gdb.select_thread(thread)
        points.append({
            "address": site,
            "point": gdb.watchpoint(site, size if len(threads) == 1 else 1, access = access),
            "thread": thread,
        })
    gdb.select_thread(current)
    return points

def remove_points_all(gdb, points):
    """Removes per-thread points and restores the selected remote thread."""
    current = gdb.current_thread()
    for item in points:
        gdb.select_thread(item["thread"])
        item["point"].remove()
    gdb.select_thread(current)

def run_to(gdb, address, kind = "hardware", timeout = 30, max_stops = 4096):
    """Continues to one temporary breakpoint, ignoring unrelated stops."""
    point = gdb.breakpoint(address, kind = kind)
    stop = wait_for_pc(gdb, address, timeout = timeout, max_stops = max_stops, resume = True)
    point.remove()
    return stop

def break_on_return(gdb, stop, pointer_size = 4, kind = "hardware"):
    """Installs a temporary breakpoint at the current stack return address."""
    name = "esp" if pointer_size == 4 else "rsp"
    target = read_int(gdb, stop.registers[name], pointer_size)
    return gdb.breakpoint(target, kind = kind)

def follow_return_pattern(gdb, stop, pattern, occurrence = 0, offset = 0, search_size = 0x400):
    """Finds a pattern near the return PC and breaks at its selected occurrence."""
    return_pc = read_u32(gdb, stop.registers["esp"])
    hits = gdb.search_memory(return_pc, search_size, pattern, limit = occurrence + 1)
    if len(hits) <= occurrence:
        fail("return pattern occurrence was not found")
    return gdb.breakpoint(hits[occurrence] + offset, kind = "hardware")

def follow_return(gdb, stop, offset = 0, pointer_size = 4, kind = "hardware"):
    """Continues to the current function's stack return address plus offset."""
    name = "esp" if pointer_size == 4 else "rsp"
    target = read_int(gdb, stop.registers[name], pointer_size) + offset
    return run_to(gdb, target, kind = kind)

def follow_caller_return(gdb, stop, offset = 0, pointer_size = 4, kind = "hardware"):
    """Continues to the return address in the current frame-pointer chain."""
    name = "ebp" if pointer_size == 4 else "rbp"
    target = read_int(gdb, stop.registers[name] + pointer_size, pointer_size) + offset
    return run_to(gdb, target, kind = kind)

def follow_register(gdb, stop, register, offset = 0, kind = "hardware"):
    """Continues to an address derived from a stopped register."""
    return run_to(gdb, stop.registers[register] + offset, kind = kind)

def follow_stack_read(gdb, stop, offset, pointer_size = 4, kind = "hardware"):
    """Reads a target relative to the stack pointer and continues to it."""
    name = "esp" if pointer_size == 4 else "rsp"
    target = read_int(gdb, stop.registers[name] + offset, pointer_size)
    return run_to(gdb, target, kind = kind)

def frame_backtrace(gdb, stop, depth = 16, pointer_size = 4):
    """Walks a bounded frame-pointer chain into address records."""
    if depth < 0 or depth > 1024:
        fail("invalid backtrace depth")
    frame_name = "ebp" if pointer_size == 4 else "rbp"
    frames = []
    frame = stop.registers[frame_name]
    index = 0
    while frame and index < depth:
        next_frame = read_int(gdb, frame, pointer_size)
        return_address = read_int(gdb, frame + pointer_size, pointer_size)
        frames.append({"index": index, "frame": frame, "return_address": return_address})
        if next_frame <= frame:
            break
        frame = next_frame
        index += 1
    return frames

def step_over(gdb, stop = None, into_call_targets = [], timeout = 30, point = None):
    """Steps one instruction, running over calls except selected direct targets."""
    if stop != None and hasattr(stop, "generation"):
        if stop.generation != gdb.generation or not stop.resumable or gdb.running:
            fail("step_over requires the current resumable GDB stop")
        if stop.thread and hasattr(gdb, "select_thread"):
            gdb.select_thread(stop.thread)
    def execute_step():
        registers = stop.registers if stop != None else gdb.registers(timeout = timeout)
        pc_name = "rip" if "rip" in registers else "eip"
        pc = registers[pc_name]
        instruction = debug.disassemble(
            gdb.read_memory(pc, 15, timeout = timeout),
            address = pc,
            architecture = gdb.architecture,
            count = 1,
        )[0]
        if instruction.flow == "call" and instruction.target not in into_call_targets:
            return_point = gdb.breakpoint(pc + instruction.length, kind = "hardware", timeout = timeout)
            getattr(gdb, "continue")(timeout = timeout)
            result = gdb.wait(timeout = timeout)
            return_point.remove(timeout = timeout)
            return result
        gdb.step(timeout = timeout)
        return gdb.wait(timeout = timeout)
    if point != None:
        return point.with_disabled(execute_step, timeout = timeout)
    return execute_step()

def step_over_many(gdb, stop, count, into_call_targets = [], predicate = None, timeout = 30):
    """Selectively steps over instructions and returns accepted stop records."""
    if count < 0 or count > 1000000:
        fail("invalid step count")
    stops = []
    current = stop
    while len(stops) < count:
        current = step_over(gdb, current, into_call_targets, timeout)
        if predicate == None or predicate(current):
            stops.append(current)
    return stops

def watch_from_argument(gdb, stop, index, size, offset = 0, access = "write", pointer_size = 4):
    """Installs a watchpoint relative to a pointer-valued entry argument."""
    address = stack_argument_value(gdb, stop, index, pointer_size) + offset
    return gdb.watchpoint(address, size, access = access)

def inspect_in_address_space(gdb, directory_table_base, callback):
    """Runs an inspection callback under a temporary CR3 value."""
    return gdb.with_register("cr3", directory_table_base, callback)

def with_address_space(gdb, register, value, callback):
    """Runs callback with a temporary address-space register and restores it."""
    return gdb.with_register(register, value, callback)

def _align_down(value, alignment):
    return value - value % alignment

def _u32_bytes(values):
    builder = binary.builder(capacity = len(values) * 4)
    for value in values:
        if value < 0 or value > 0xffffffff:
            fail("i386 call argument does not fit in 32 bits")
        builder.u32le(value)
    return builder.bytes()

def _inferior_call_i386(gdb, address, arguments, stack_size, timeout):
    if stack_size < 64 or stack_size > 16 << 20:
        fail("i386 inferior-call stack_size must be between 64 bytes and 16 MiB")
    registers = gdb.registers(timeout = timeout)
    if "esp" not in registers or "eip" not in registers:
        fail("i386 target does not expose esp and eip")
    original_sp = registers["esp"]
    if original_sp < stack_size:
        fail("i386 stack pointer is smaller than the requested stack_size")
    stack_bottom = original_sp - stack_size
    cursor = original_sp
    values = []
    scratch = []
    writes = []
    for argument in arguments:
        if type(argument) == "int":
            values.append(argument)
        elif type(argument) == "bytes":
            cursor = _align_down(cursor - len(argument), 4)
            if cursor < stack_bottom:
                fail("i386 inferior-call scratch data exceeds stack_size")
            values.append(cursor)
            scratch.append(cursor)
            writes.append((cursor, argument))
        else:
            fail("i386 inferior-call arguments must be integers or bytes")

    cursor = _align_down(cursor - 1, 4)
    trap = cursor
    frame = _u32_bytes([trap] + values)
    frame_sp = _align_down(cursor - len(frame), 4)
    if frame_sp < stack_bottom:
        fail("i386 inferior-call frame exceeds stack_size")

    preserved = []
    for name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"]:
        if name in registers:
            preserved.append(name)

    def invoke():
        for target, data in writes:
            gdb.write_memory(target, data, timeout = timeout)
        gdb.write_memory(trap, b"\xcc", timeout = timeout)
        gdb.write_memory(frame_sp, frame, timeout = timeout)
        gdb.write_register("esp", frame_sp, timeout = timeout)
        gdb.write_register("eip", address, timeout = timeout)
        getattr(gdb, "continue")(timeout = timeout)
        stop = gdb.wait(timeout = timeout)
        stopped = stop.registers
        if "eip" not in stopped or "eax" not in stopped:
            stopped = gdb.registers(timeout = timeout)
        pc = stopped["eip"]
        if pc != trap and pc != trap + 1:
            fail("inferior call stopped at {}, expected return trap {}".format(hex(pc), hex(trap)))
        scratch_data = []
        for index in range(len(writes)):
            scratch_data.append(gdb.read_memory(scratch[index], len(writes[index][1]), timeout = timeout))
        return {
            "value": stopped["eax"],
            "stop": stop,
            "scratch": scratch,
            "scratch_data": scratch_data,
        }

    return gdb.with_state(
        registers = preserved,
        memory = [(stack_bottom, stack_size)],
        callback = invoke,
        timeout = timeout + 10,
    )

def inferior_call(gdb, address, arguments = [], stack_size = 65536, timeout = 30):
    """Calls a stopped inferior function and restores its registers and stack.

    Integer arguments are passed by value. Byte arguments are copied into
    temporary target stack storage and passed by pointer. The returned mapping
    contains the integer return value, stop record, scratch addresses, and the
    scratch bytes captured before restoration.
    """
    if address < 0:
        fail("inferior-call address must not be negative")
    if gdb.architecture == "i386":
        return _inferior_call_i386(gdb, address, arguments, stack_size, timeout)
    fail("inferior calls are not implemented for architecture " + gdb.architecture)
