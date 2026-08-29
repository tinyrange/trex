"""Bounded conformance calls into Windows PE32 implementations.

This module is intentionally smaller than the Windows execution environment.
It maps target modules, installs only explicitly declared semantic imports, and
leaves every other import as the emulator's fail-on-call stub.  Callers can use
exports, ordinals, image-relative RVAs, or absolute addresses without teaching
the stable API about a particular Windows release.
"""

_DEFAULT_MAXIMUM_BUFFER = 16 << 20

def _bytes(value, maximum, field):
    view = binary.view(value)
    if len(view) > maximum:
        fail("%s exceeds the %d-byte limit" % (field, maximum))
    output = binary.builder(capacity = len(view), limit = maximum)
    output.append(view)
    return output.bytes()

def _canonical_module_name(name):
    value = name.replace("\\", "/").split("/")[-1].lower()
    return value if "." in value else value + ".dll"

def _primary_module(machine):
    for module in machine.modules:
        if module.primary:
            return module
    return None

def session(image = None, code = None, module = "target.exe", base = 0x1000, modules = {}, bindings = [], plugins = [], instruction_limit = 2000000, memory_limit = 32 << 20, stack_size = 1 << 20, call_depth_limit = 4096, trace = False, trace_limit = 4096, profile = False):
    """Creates an isolated PE32 or raw-x86 conformance session.

    `bindings` contains mappings accepted by `emulator.x86.provide_export`:
    module plus exactly one of name/ordinal and exactly one of callback/value.
    Unbound PE imports remain lazy error stubs and therefore fail only if target
    execution calls them.  Additional PE images are mapped from `modules`.
    """
    if (image == None) == (code == None):
        fail("conformance session requires exactly one of image or code")
    arguments = {
        "instruction_limit": instruction_limit,
        "memory_limit": memory_limit,
        "stack_size": stack_size,
        "call_depth_limit": call_depth_limit,
        "trace": trace,
        "trace_limit": trace_limit,
        "profile": profile,
        "image_name": module,
    }
    if image != None:
        arguments["image"] = image
    else:
        arguments["code"] = code
        arguments["base"] = base
    machine = emulator.x86(**arguments)
    loaded = {}
    primary = _primary_module(machine)
    if primary != None:
        loaded[primary.name] = primary
    for name, source in modules.items():
        mapped = machine.load_module(image = source, name = name)
        loaded[mapped.name] = mapped
    for index in range(len(bindings)):
        binding = bindings[index]
        if type(binding) != "dict" or "module" not in binding:
            fail("conformance binding %d must contain a module" % index)
        options = {
            "module": binding["module"],
            "argc": binding.get("argc", 0),
            "convention": binding.get("convention", "stdcall"),
        }
        for field in ["name", "ordinal", "callback", "value", "writable"]:
            if field in binding:
                options[field] = binding[field]
        machine.provide_export(**options)
    if plugins:
        machine.use(plugins)
    return {
        "machine": machine,
        "module": primary,
        "modules": loaded,
        "name": _canonical_module_name(module),
        "raw_base": base if code != None else None,
    }

def resolve(session, module = None, name = None, ordinal = None, rva = None, address = None):
    """Resolves exactly one absolute, RVA, named-export, or ordinal target."""
    selectors = int(address != None) + int(rva != None) + int(name != None) + int(ordinal != None)
    if selectors != 1:
        fail("conformance target requires exactly one selector")
    if address != None:
        if address < 0 or address > 0xffffffff:
            fail("conformance target address must fit in 32 bits")
        return address
    machine = session["machine"]
    module_name = _canonical_module_name(module or session["name"])
    if rva != None:
        if rva < 0 or rva > 0xffffffff:
            fail("conformance target RVA must fit in 32 bits")
        if session["raw_base"] != None and module == None:
            return session["raw_base"] + rva
        selected = session["modules"].get(module_name)
        if selected == None:
            fail("conformance module %s is not mapped" % module_name)
        if rva > 0xffffffff - selected.base:
            fail("conformance target RVA overflows its image")
        return selected.base + rva
    target = machine.resolve_export(module_name, name = name) if name != None else machine.resolve_export(module_name, ordinal = ordinal)
    if target == 0:
        fail("conformance target is not exported by %s" % module_name)
    return target

def buffer(value = b"", size = None, name = "buffer", expected = None, capture = True, maximum = _DEFAULT_MAXIMUM_BUFFER):
    """Describes one zero-initialized bounded call buffer.

    `value` is copied at offset zero.  `size` may reserve writable tail space.
    `expected`, when supplied, is compared with the complete buffer after the
    call.  Captured bytes are returned by `call` under the descriptor's key.
    """
    data = _bytes(value, maximum, "conformance buffer")
    capacity = len(data) if size == None else size
    if capacity < len(data) or capacity < 1 or capacity > maximum:
        fail("invalid conformance buffer size")
    expected_data = None if expected == None else _bytes(expected, maximum, "conformance expected buffer")
    if expected_data != None and len(expected_data) != capacity:
        fail("conformance expected buffer must match its capacity")
    return {
        "capture": capture,
        "expected": expected_data,
        "name": name,
        "size": capacity,
        "value": data,
    }

def output(size, name = "output", expected = None, capture = True, maximum = _DEFAULT_MAXIMUM_BUFFER):
    """Describes one bounded zero-initialized output buffer."""
    return buffer(size = size, name = name, expected = expected, capture = capture, maximum = maximum)

def pointer(name, offset = 0):
    """Returns an argument reference to a named call buffer and byte offset."""
    if offset < 0:
        fail("conformance buffer offset must not be negative")
    return {"kind": "pointer", "name": name, "offset": offset}

def size_of(name):
    """Returns an argument reference to a named call buffer's capacity."""
    return {"kind": "size", "name": name}

def c_memory_bindings(modules = ["msvcrt.dll"]):
    """Returns declared cdecl bindings for memcpy, memmove, and memset.

    These leaf operations are useful when validating otherwise self-contained
    target algorithms.  No allocation, I/O, locale, or process behavior is
    implied, and all other C runtime imports remain fail-on-call stubs.
    """
    def copy(event):
        if event.args[2]:
            event.machine.write(event.args[0], event.machine.read(event.args[1], event.args[2]))
        return event.args[0]
    def fill(event):
        if event.args[2]:
            value = binary.builder(capacity = event.args[2])
            value.reserve(event.args[2], fill = event.args[1] & 0xff)
            event.machine.write(event.args[0], value.bytes())
        return event.args[0]
    bindings = []
    for module in modules:
        bindings.extend([
            {"module": module, "name": "memcpy", "argc": 3, "convention": "cdecl", "callback": copy},
            {"module": module, "name": "memmove", "argc": 3, "convention": "cdecl", "callback": copy},
            {"module": module, "name": "memset", "argc": 3, "convention": "cdecl", "callback": fill},
        ])
    return bindings

def _argument(value, allocations, specifications):
    if type(value) != "dict" or "kind" not in value:
        return value
    name = value.get("name")
    if name not in allocations:
        fail("conformance argument refers to unknown buffer %s" % name)
    if value["kind"] == "size":
        return specifications[name]["size"]
    if value["kind"] == "pointer":
        offset = value.get("offset", 0)
        if offset < 0 or offset > specifications[name]["size"]:
            fail("conformance argument exceeds buffer %s" % name)
        return allocations[name] + offset
    fail("unsupported conformance argument reference %s" % value["kind"])

def _allocate(machine, buffers):
    allocations = {}
    for name, specification in buffers.items():
        if type(specification) != "dict" or specification.get("size", 0) < 1:
            fail("conformance buffer %s has an invalid descriptor" % name)
        address = machine.allocate(size = specification["size"], name = specification.get("name", name))
        allocations[name] = address
        value = specification.get("value", b"")
        if len(value):
            machine.write(address, value)
    return allocations

def _capture(machine, buffers, allocations):
    captured = {}
    for name, specification in buffers.items():
        if specification.get("capture", True) or specification.get("expected") != None:
            value = machine.read(allocations[name], specification["size"])
            if specification.get("capture", True):
                captured[name] = value
            expected = specification.get("expected")
            if expected != None and value != expected:
                fail("conformance buffer %s does not match its expected value" % name)
    return captured

def sequence(session, steps, buffers = {}, inspect = None):
    """Invokes an ordered target sequence over shared bounded buffers.

    Each step contains `target` and optional arguments, registers,
    expected_reason, and expected_return fields.  Argument references use
    `pointer` and `size_of`.  All CPU invocations are isolated while their
    explicitly allocated memory remains shared for the complete sequence.
    """
    machine = session["machine"]
    allocations = _allocate(machine, buffers)
    results = []
    for index in range(len(steps)):
        step = steps[index]
        if type(step) != "dict" or "target" not in step:
            fail("conformance step %d requires a target" % index)
        values = [_argument(value, allocations, buffers) for value in step.get("arguments", [])]
        result = machine.invoke(step["target"], args = values, registers = step.get("registers", {}))
        expected_reason = step.get("expected_reason", "return")
        if expected_reason != None and result.reason != expected_reason:
            fail("conformance step %d stopped with %s: %s" % (index, result.reason, result.detail))
        expected_return = step.get("expected_return")
        if expected_return != None and result.value != expected_return:
            fail("conformance step %d returned 0x%x, want 0x%x" % (index, result.value, expected_return))
        results.append(result)
    captured = _capture(machine, buffers, allocations)
    inspected = inspect(machine, results, allocations, buffers) if inspect != None else None
    for address in allocations.values():
        machine.free(address)
    return {
        "addresses": allocations,
        "buffers": captured,
        "inspection": inspected,
        "results": results,
    }

def call(session, target, buffers = {}, arguments = [], registers = {}, expected_return = None, expected_reason = "return", inspect = None):
    """Invokes one target with bounded named buffers and captures post-state.

    `target` is an address returned by `resolve`.  Arguments may contain raw
    integers, `pointer(name)`, or `size_of(name)` references.  `inspect`, when
    supplied, runs before allocations are released and may return additional
    caller-defined facts.  CPU state outside the invocation is preserved.
    """
    def inspect_one(machine, results, allocations, specifications):
        return inspect(machine, results[0], allocations, specifications) if inspect != None else None
    result = sequence(session, [{
        "arguments": arguments,
        "expected_reason": expected_reason,
        "expected_return": expected_return,
        "registers": registers,
        "target": target,
    }], buffers = buffers, inspect = inspect_one if inspect != None else None)
    result["result"] = result["results"][0]
    return result

def run(cases):
    """Runs named zero-argument conformance cases and returns their results."""
    results = []
    for index in range(len(cases)):
        item = cases[index]
        if type(item) != "dict" or not item.get("name") or item.get("call") == None:
            fail("conformance case %d requires name and call" % index)
        results.append({"name": item["name"], "result": item["call"]()})
    return results
