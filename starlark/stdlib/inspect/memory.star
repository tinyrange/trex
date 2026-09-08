"""Declarative, bounded structure readers over a memory image or address space.

Layouts map field names to (offset, kind, size). Kinds are uint, bytes,
cstring and unicode (a 32-bit Windows UNICODE_STRING descriptor, size 8).
Results retain only fully decoded fields/entries and an explicit fault.
Pointers are uint fields: callers choose whether and when to dereference them.
"""

def _result(value, fault = None):
    return {"value": value, "complete": fault == None, "fault": fault}

def _fault(kind, address, message):
    return {"kind": kind, "address": address, "message": message}

def _memory_fault(fault):
    return {
        "kind": fault.kind, "address": fault.address, "message": fault.message,
        "physical_address": fault.physical_address, "level": fault.level,
    }

def _uint(data):
    value = 0
    for i in range(len(data)):
        value |= binary.read_u8(data, i) << (8 * i)
    return value

def read_structure(space, address, layout, address_bits = 32):
    """Reads named fields; never fills missing bytes or follows arbitrary pointers.

    Offsets and sizes are validated before reading. unicode validates length,
    capacity and pointer bounds, then reads precisely Length bytes as UTF-16LE.
    A partial result contains preceding complete fields, not a fabricated value.
    """
    if address_bits not in (32, 64) or address < 0 or address >= 1 << address_bits:
        fail("invalid structure address width or address")
    if len(layout) > 1024:
        fail("too many structure fields")
    for name, spec in layout.items():
        if len(spec) != 3:
            fail("field must be (offset, kind, size): " + name)
        offset, kind, size = spec
        if offset < 0 or size < 0 or size > 65536 or address + offset + size > 1 << address_bits:
            fail("invalid field bounds: " + name)
        if kind not in ("uint", "bytes", "cstring", "unicode") or (kind == "uint" and size not in (1, 2, 4, 8)) or (kind == "unicode" and size != 8):
            fail("invalid field type: " + name)
    fields = {}
    for name, (offset, kind, size) in layout.items():
        probe = space.probe(address + offset, size)
        if not probe.complete:
            return _result(fields, _memory_fault(probe.fault))
        data = probe.data
        if kind == "uint":
            value = _uint(data)
        elif kind == "bytes":
            value = data
        elif kind == "cstring":
            value = str(data).split("\x00")[0]
        else:
            length = _uint(data[:2])
            capacity = _uint(data[2:4])
            pointer = _uint(data[4:8])
            if length & 1 or length > capacity or (length and not pointer) or pointer + length > 1 << 32:
                return _result(fields, _fault("invalid-structure", address + offset, "invalid UNICODE_STRING"))
            probe = space.probe(pointer, length)
            if not probe.complete:
                return _result(fields, _memory_fault(probe.fault))
            value = binary.text(probe.data, encoding = "utf16le")
        fields[name] = value
    return _result(fields)

def walk_list(space, head, link_offset = 0, pointer_size = 4, maximum = 4096):
    """Returns containing-object addresses from a circular doubly linked list.

    Checks reciprocal links, alignment, cycles and a hard entry bound. The head
    is a sentinel, not an object; link_offset locates its embedded LIST_ENTRY.
    Incomplete results are checked prefixes, never a claim of complete inventory.
    """
    if pointer_size not in (4, 8) or maximum < 1 or maximum > 65536 or link_offset < 0:
        fail("invalid list parameters")
    layout = {"next": (0, "uint", pointer_size), "previous": (pointer_size, "uint", pointer_size)}
    entries = []
    seen = {}
    current = head
    previous = None
    for step in range(maximum + 2):
        if not current or current % pointer_size or current + 2 * pointer_size > 1 << (pointer_size * 8):
            return _result(entries, _fault("invalid-structure", current, "invalid list pointer"))
        node = read_structure(space, current, layout, address_bits = pointer_size * 8)
        if not node["complete"]:
            return _result(entries, node["fault"])
        if previous != None and node["value"]["previous"] != previous:
            return _result(entries, _fault("invalid-structure", current, "nonreciprocal list link"))
        if step and current == head:
            return _result(entries)
        if current in seen or (step and current < link_offset):
            return _result(entries, _fault("invalid-structure", current, "cycle or invalid containing address"))
        if step:
            if len(entries) == maximum:
                return _result(entries, _fault("limit", current, "list entry bound reached"))
            # Check the outgoing reciprocal link before accepting this object.
            successor = node["value"]["next"]
            if not successor or successor % pointer_size or successor + 2 * pointer_size > 1 << (pointer_size * 8):
                return _result(entries, _fault("invalid-structure", successor, "invalid successor"))
            back = read_structure(space, successor, layout, address_bits = pointer_size * 8)
            if not back["complete"]:
                return _result(entries, back["fault"])
            if back["value"]["previous"] != current:
                return _result(entries, _fault("invalid-structure", successor, "nonreciprocal successor"))
            entries.append(current - link_offset)
        seen[current] = True
        previous = current
        current = node["value"]["next"]
    return _result(entries, _fault("limit", current, "list entry bound reached"))

def read_list(space, head, layout, link_offset = 0, pointer_size = 4, maximum = 4096):
    """Combines walk_list with a caller-supplied structure layout."""
    walk = walk_list(space, head, link_offset, pointer_size, maximum)
    entries = []
    for address in walk["value"]:
        item = read_structure(space, address, layout, address_bits = pointer_size * 8)
        if not item["complete"]:
            return _result(entries, item["fault"])
        entries.append({"address": address, "fields": item["value"]})
    return _result(entries, walk["fault"])
