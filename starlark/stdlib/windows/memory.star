"""Read-only NT x86 inventories with caller-supplied, build-qualified layouts.

All results use {value, complete, fault}; incomplete values are checked prefixes.
No offsets are guessed, and no absent pages are synthesized. Layouts are the
same field dictionaries used by inspect/memory.star. See docs/starlark/memory.md.
"""

load("@stdlib//inspect:memory.star", "read_structure", "read_list")

def _result(value, fault = None):
    return {"value": value, "complete": fault == None, "fault": fault}

def _bad(value, address, message, kind = "invalid-structure"):
    return _result(value, {"kind": kind, "address": address, "message": message})

def _pointer(address, size = 4):
    return address >= 0 and address % 4 == 0 and address + size <= 1 << 32

def _read(space, address, layout):
    # A corrupt target pointer is evidence, not a malformed caller layout.
    extent = max([offset + size for offset, kind, size in layout.values()] + [0])
    if address < 0 or address >= 1 << 32 or address + extent > 1 << 32:
        return _bad({}, address, "structure crosses the x86 address-space boundary")
    return read_structure(space, address, layout)

def read_vads(space, root, layout, maximum = 16384):
    """Walks an NT x86 VAD binary tree, returning half-open byte ranges.

    Required uint fields: left, right, parent, start_vpn, end_vpn. Additional
    caller fields (for example raw flags) are retained. Parent pointers must be
    untagged, the root parent zero, and VPN intervals ordered and nonoverlapping.
    This reads the XP-style tree, not later balanced-root sentinel structures.
    """
    if maximum < 1 or maximum > 65536:
        fail("invalid VAD bound")
    entries = []
    pending = [(root, 0, 0, 1 << 20)] if root else []
    seen = {}
    while pending:
        node, parent, lower, upper = pending.pop()
        if len(entries) == maximum:
            return _bad(entries, node, "VAD entry bound reached", "limit")
        if not node or not _pointer(node) or node in seen:
            return _bad(entries, node, "invalid or repeated VAD pointer")
        item = _read(space, node, layout)
        if not item["complete"]:
            return _result(entries, item["fault"])
        fields = item["value"]
        start, end = fields["start_vpn"], fields["end_vpn"] + 1
        if fields["parent"] != parent or start < lower or end > upper or start >= end:
            return _bad(entries, node, "invalid VAD parent or overlapping/out-of-order VPN range")
        seen[node] = True
        entries.append({"address": node, "start": start << 12, "end": end << 12, "fields": fields})
        if fields["right"]:
            pending.append((fields["right"], node, end, upper))
        if fields["left"]:
            pending.append((fields["left"], node, lower, start))
    return _result(entries)

def read_threads(space, head, layout, link_offset, owner_pid, expected_count = None, maximum = 4096):
    """Reads an ETHREAD list and checks owner IDs, unique TIDs and optional count.

    Required uint fields: pid, tid. Extra caller fields such as start_address,
    state or TEB are retained without interpreting build-specific enums.
    """
    walked = read_list(space, head, layout, link_offset = link_offset, maximum = maximum)
    entries = []
    seen = {}
    for item in walked["value"]:
        fields = item["fields"]
        if fields["pid"] != owner_pid or not fields["tid"] or fields["tid"] in seen:
            return _bad(entries, item["address"], "thread owner mismatch or invalid/repeated TID")
        seen[fields["tid"]] = True
        entries.append(item)
    if not walked["complete"]:
        return _result(entries, walked["fault"])
    if expected_count != None and len(entries) != expected_count:
        return _bad(entries, head, "thread count disagrees with process record")
    return _result(entries)

def read_drivers(space, head, layout, link_offset = 0, maximum = 1024, verify_pe = True):
    """Reads the kernel loader list (including kernel/HAL, not just .sys files).

    Required fields: base and size (uint). Names/paths are caller layout fields.
    By default adds per-entry pe results for resident DOS/PE32 headers and size,
    accepting exact or page-rounded loader sizes. Top-level complete describes
    the loader inventory; pe.complete separately describes header checks, not file hashes,
    signatures or module trust. A mapped image is not an on-disk PE file.
    """
    if maximum < 1 or maximum > 4096:
        fail("invalid driver bound")
    walked = read_list(space, head, layout, link_offset = link_offset, maximum = maximum)
    entries = []
    ranges = []
    for item in walked["value"]:
        base, size = item["fields"]["base"], item["fields"]["size"]
        if not base or not size or not _pointer(base) or base + size > 1 << 32:
            return _bad(entries, base, "invalid kernel module range")
        for start, end in ranges:
            if base < end and start < base + size:
                return _bad(entries, base, "overlapping kernel module ranges")
        if verify_pe:
            item["pe"] = _module_pe(space, base, size)
        ranges.append((base, base + size))
        entries.append(item)
    return _result(entries, walked["fault"])

def read_handle_table(space, table, layout, maximum = 65536):
    """Reads XP-style 0/1/2-level handle tables, preserving handle aliases.

    Required uint fields: table_code, next_handle, count. TableCode uses its low
    two bits as level, 4 KiB pages, 4-byte directory pointers and 8-byte entries.
    Handles have stride four; zero is reserved. Free entries have a zero object
    word. Object-header pointers mask the low three attribute/lock bits. This
    encoding is not the encoded handle representation of newer Windows kernels.
    maximum bounds examined slots, including free entries, not just live handles.
    """
    if maximum < 1 or maximum > 1 << 20:
        fail("invalid handle bound")
    if not table or not _pointer(table):
        return _bad([], table, "invalid handle table")
    metadata = _read(space, table, layout)
    if not metadata["complete"]:
        return _result([], metadata["fault"])
    fields = metadata["value"]
    code, end = fields["table_code"], fields["next_handle"]
    level, base = code & 3, code & ~3
    if level > 2 or not base or base % 4096 or end < 4 or end % 4 or end // 4 > 512 << (10 * level):
        return _bad([], table, "invalid handle table code or extent")
    entries = []
    pointers = {}
    for slot in range(1, min(end // 4, maximum + 1)):
        leaf = base
        indices = []
        if level == 2:
            indices.append(slot // (512 * 1024))
        if level:
            indices.append((slot // 512) % 1024)
        for index in indices:
            address = leaf + index * 4
            if address not in pointers:
                pointer = _read(space, address, {"pointer": (0,"uint",4)})
                if not pointer["complete"]:
                    return _result(entries, pointer["fault"])
                pointers[address] = pointer["value"]["pointer"]
            leaf = pointers[address]
            if not leaf or leaf % 4096:
                return _bad(entries, address, "invalid handle directory pointer")
        address = leaf + (slot % 512) * 8
        item = _read(space, address, {"object": (0,"uint",4), "access": (4,"uint",4)})
        if not item["complete"]:
            return _result(entries, item["fault"])
        raw = item["value"]["object"]
        if not raw:
            continue
        header = raw & ~7
        if not header:
            return _bad(entries, address, "invalid object-header pointer")
        entries.append({"handle": slot * 4, "entry_address": address, "object_header": header, "raw_object": raw, "access": item["value"]["access"]})
    if end // 4 - 1 > maximum:
        return _bad(entries, table, "handle slot bound reached", "limit")
    if len(entries) != fields["count"]:
        return _bad(entries, table, "live handle count disagrees with table")
    return _result(entries)

def read_file_handles(space, handles, header_layout, type_layout, file_layout, body_offset):
    """Filters handle records by object type name File before reading FILE_OBJECT.

    header_layout needs uint field type; type_layout needs unicode field name;
    file_layout needs uint field type (IO_TYPE_FILE=5), and may include name,
    device, related_file, flags and size. Names are raw FILE_OBJECT names, not
    canonical DOS paths; unnamed files and device/relative names are preserved.
    Access masks stay raw. No file contents or credential material is read.
    """
    if body_offset < 0 or body_offset > 4096:
        fail("invalid object body offset")
    entries = []
    types = {}
    for handle in handles["value"]:
        address = handle["object_header"]
        header = _read(space, address, header_layout)
        if not header["complete"]:
            return _result(entries, header["fault"])
        type_address = header["value"]["type"]
        if not type_address or not _pointer(type_address):
            return _bad(entries, type_address, "invalid object type pointer")
        if type_address not in types:
            kind = _read(space, type_address, type_layout)
            if not kind["complete"]:
                return _result(entries, kind["fault"])
            types[type_address] = kind["value"]["name"]
        if types[type_address] != "File":
            continue
        if not _pointer(address + body_offset):
            return _bad(entries, address, "invalid file body pointer")
        body = _read(space, address + body_offset, file_layout)
        if not body["complete"]:
            return _result(entries, body["fault"])
        if body["value"]["type"] != 5:
            return _bad(entries, address, "object type File disagrees with FILE_OBJECT type")
        entries.append({"handle": handle["handle"], "object_header": address, "address": address + body_offset, "access": handle["access"], "fields": body["value"]})
    return _result(entries, handles["fault"])

def _module_pe(space, base, size):
    dos = _read(space, base, {"magic": (0,"bytes",2), "pe": (0x3c,"uint",4)})
    if not dos["complete"]:
        return _result(None, dos["fault"])
    offset = dos["value"]["pe"]
    if dos["value"]["magic"] != b"MZ" or offset < 64 or offset + 84 > size:
        return _bad(None, base, "invalid DOS/PE header offset")
    pe = _read(space, base + offset, {"magic": (0,"bytes",4), "machine": (4,"uint",2), "optional_magic": (24,"uint",2), "image_size": (80,"uint",4)})
    if not pe["complete"]:
        return _result(None, pe["fault"])
    header = pe["value"]
    if header["magic"] != b"PE\x00\x00" or header["machine"] != 0x14c or header["optional_magic"] != 0x10b or not header["image_size"] or (header["image_size"] != size and (header["image_size"] + 4095) & ~4095 != size):
        return _bad(None, base, "mapped PE32 header disagrees with loader entry")
    return _result(header)
