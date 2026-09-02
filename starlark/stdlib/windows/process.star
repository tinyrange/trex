"""Offset-driven Windows process and PEB traversal for debugger scripts."""

load("@stdlib//debug:gdb.star", "inspect_in_address_space", "read_int", "read_unicode_string")

def nt61_x86_eprocess_offsets(build = 7601):
    """Returns the checked Windows 7 SP1 x86 EPROCESS layout.

    The layout is deliberately build-qualified.  Callers inspecting another
    kernel must supply offsets derived from that kernel instead of silently
    reusing this profile.
    """
    if build != 7601:
        fail("unsupported NT 6.1 x86 EPROCESS build %d" % build)
    return {
        "directory_table_base": 0x18,
        "image_name": 0x16c,
        "image_name_size": 16,
        "links": 0xb8,
        "peb": 0x1a8,
        "pid": 0xb4,
    }

def nt_x86_debugger_state(gdb, fs_base = None):
    """Reads the x86 KPCR debugger-version record from a stopped target.

    NT keeps a pointer to DBGKD_GET_VERSION64 at KPCR offset 0x34 even for an
    x86 kernel.  The record is a stable source of the ASLR kernel base and the
    two debugger-owned kernel lists; unlike an interrupted PC, it is not
    affected by which driver happened to be executing when the VM stopped.
    """
    if fs_base == None:
        fs_base = gdb.read_register("fs_base")
    if fs_base < 0 or fs_base > 0xffffffff:
        fail("invalid x86 KPCR base")
    version = _target_int(gdb, fs_base + 0x34, 4)
    if version == 0:
        fail("x86 KPCR has no debugger version block")
    machine = _target_int(gdb, version + 8, 2)
    if machine != 0x14c:
        fail("debugger version block describes machine " + hex(machine) + ", not i386")
    return {
        "debugger_data_list": _target_int(gdb, version + 32, 8) & 0xffffffff,
        "flags": _target_int(gdb, version + 6, 2),
        "kernel_base": _target_int(gdb, version + 16, 8) & 0xffffffff,
        "loaded_module_list": _target_int(gdb, version + 24, 8) & 0xffffffff,
        "machine": machine,
        "major_version": _target_int(gdb, version, 2),
        "minor_version": _target_int(gdb, version + 2, 2),
        "protocol_version": _target_int(gdb, version + 4, 1),
        "secondary_version": _target_int(gdb, version + 5, 1),
        "version_block": version,
    }

def pe_export_rva(image, name):
    """Resolves one named PE export RVA, rejecting absent or duplicate names."""
    matches = [item["rva"] for item in windows.pe(image).exports if item.get("name") == name]
    if len(matches) != 1:
        fail("PE image has %d exports named %s" % (len(matches), name))
    return matches[0]

def _uint(data):
    encoded = hex(data)
    ordered = ""
    index = len(encoded) - 2
    while index >= 0:
        ordered += encoded[index:index + 2]
        index -= 2
    return int(ordered, 16) if ordered else 0

def _virtual_bytes(target, address, size):
    if hasattr(target, "read_virtual"):
        return target.read_virtual(address, size)
    if hasattr(target, "read_memory"):
        return target.read_memory(address, size)
    fail("debug target exposes neither read_virtual nor read_memory")

def _target_int(target, address, size):
    return _uint(_virtual_bytes(target, address, size))

def _physical_int(kd, address, size):
    return _uint(kd.read_physical(address, size))

def _i386_physical_address(kd, directory_table_base, address, pae):
    if address < 0 or address > 0xffffffff:
        fail("i386 virtual address is out of range")
    if pae:
        pdpt = directory_table_base & ~0x1f
        pdpte = _physical_int(kd, pdpt + ((address >> 30) & 0x3) * 8, 8)
        if pdpte & 1 == 0:
            fail("i386 PAE page-directory-pointer entry is not present")
        directory = pdpte & 0x000ffffffffff000
        pde = _physical_int(kd, directory + ((address >> 21) & 0x1ff) * 8, 8)
        if pde & 1 == 0:
            fail("i386 PAE page-directory entry is not present")
        if pde & 0x80:
            return (pde & 0x000fffffffe00000) + (address & 0x1fffff)
        table = pde & 0x000ffffffffff000
        pte = _physical_int(kd, table + ((address >> 12) & 0x1ff) * 8, 8)
        if pte & 1 == 0:
            fail("i386 PAE page-table entry is not present")
        return (pte & 0x000ffffffffff000) + (address & 0xfff)
    directory = directory_table_base & ~0xfff
    pde = _physical_int(kd, directory + ((address >> 22) & 0x3ff) * 4, 4)
    if pde & 1 == 0:
        fail("i386 page-directory entry is not present")
    if pde & 0x80:
        return (pde & 0xffc00000) + (address & 0x3fffff)
    table = pde & 0xfffff000
    pte = _physical_int(kd, table + ((address >> 12) & 0x3ff) * 4, 4)
    if pte & 1 == 0:
        fail("i386 page-table entry is not present")
    return (pte & 0xfffff000) + (address & 0xfff)

def i386_physical_address(kd, directory_table_base, address, pae = True):
    """Translates one bounded i386 virtual address through target page tables."""
    return _i386_physical_address(kd, directory_table_base, address, pae)

def _amd64_physical_address(kd, directory_table_base, address):
    if address < 0 or address > 0xffffffffffffffff:
        fail("amd64 virtual address is out of range")
    upper = address >> 48
    if upper != 0 and upper != 0xffff:
        fail("amd64 virtual address is not canonical")
    table = directory_table_base & 0x000ffffffffff000
    if table == 0:
        fail("amd64 page-map base is NULL")
    pml4e = _physical_int(kd, table + ((address >> 39) & 0x1ff) * 8, 8)
    if pml4e & 1 == 0:
        fail("amd64 PML4 entry is not present")
    directory_pointer = pml4e & 0x000ffffffffff000
    pdpte = _physical_int(kd, directory_pointer + ((address >> 30) & 0x1ff) * 8, 8)
    if pdpte & 1 == 0:
        fail("amd64 page-directory-pointer entry is not present")
    if pdpte & 0x80:
        return (pdpte & 0x000fffffc0000000) + (address & 0x3fffffff)
    directory = pdpte & 0x000ffffffffff000
    pde = _physical_int(kd, directory + ((address >> 21) & 0x1ff) * 8, 8)
    if pde & 1 == 0:
        fail("amd64 page-directory entry is not present")
    if pde & 0x80:
        return (pde & 0x000fffffffe00000) + (address & 0x1fffff)
    table = pde & 0x000ffffffffff000
    pte = _physical_int(kd, table + ((address >> 12) & 0x1ff) * 8, 8)
    if pte & 1 == 0:
        fail("amd64 page-table entry is not present")
    return (pte & 0x000ffffffffff000) + (address & 0xfff)

def amd64_physical_address(kd, directory_table_base, address):
    """Translates one canonical amd64 address through target page tables."""
    return _amd64_physical_address(kd, directory_table_base, address)

def read_amd64_virtual(kd, directory_table_base, address, size, maximum = 64 << 20):
    """Reads one amd64 process address space through KD physical memory."""
    if size < 0 or size > maximum or address < 0 or address > 0xffffffffffffffff or size > 0x10000000000000000 - address:
        fail("invalid amd64 virtual-memory range")
    output = binary.builder(capacity = size, limit = maximum)
    consumed = 0
    while consumed < size:
        current = address + consumed
        length = min(size - consumed, 0x1000 - (current & 0xfff))
        physical = _amd64_physical_address(kd, directory_table_base, current)
        output.append(kd.read_physical(physical, length))
        consumed += length
    return output.bytes()

def write_amd64_virtual(kd, directory_table_base, address, value, maximum = 64 << 20):
    """Writes one amd64 address space through KD physical-memory operations."""
    data = binary.view(value)
    if data.size > maximum or address < 0 or address > 0xffffffffffffffff or data.size > 0x10000000000000000 - address:
        fail("invalid amd64 virtual-memory range")
    consumed = 0
    while consumed < data.size:
        current = address + consumed
        length = min(data.size - consumed, 0x1000 - (current & 0xfff))
        physical = _amd64_physical_address(kd, directory_table_base, current)
        kd.write_physical(physical, data.slice(consumed, length).bytes())
        consumed += length

def read_i386_virtual(kd, directory_table_base, address, size, pae = True, maximum = 64 << 20):
    """Reads one i386 process address space through KD physical memory."""
    if size < 0 or size > maximum or address < 0 or address + size > 1 << 32:
        fail("invalid i386 virtual-memory range")
    output = binary.builder(capacity = size, limit = maximum)
    consumed = 0
    while consumed < size:
        current = address + consumed
        length = min(size - consumed, 0x1000 - (current & 0xfff))
        physical = _i386_physical_address(kd, directory_table_base, current, pae)
        output.append(kd.read_physical(physical, length))
        consumed += length
    return output.bytes()

def write_i386_virtual(kd, directory_table_base, address, value, pae = True, maximum = 64 << 20):
    """Writes one i386 address space through KD physical-memory operations."""
    data = binary.view(value)
    if data.size > maximum or address < 0 or address + data.size > 1 << 32:
        fail("invalid i386 virtual-memory range")
    consumed = 0
    while consumed < data.size:
        current = address + consumed
        length = min(data.size - consumed, 0x1000 - (current & 0xfff))
        physical = _i386_physical_address(kd, directory_table_base, current, pae)
        kd.write_physical(physical, data.slice(consumed, length).bytes())
        consumed += length

def walk_linked_list(read_pointer, head, link_offset, maximum = 4096):
    """Walks a bounded circular LIST_ENTRY and returns containing addresses."""
    if maximum <= 0 or maximum > 1000000:
        fail("invalid linked-list limit")
    entries = []
    current = read_pointer(head)
    while current != head and len(entries) < maximum:
        if current == 0 or current < link_offset:
            fail("invalid linked-list pointer")
        entries.append(current - link_offset)
        current = read_pointer(current)
    if current != head:
        fail("linked list exceeds configured limit")
    return entries

def eprocesses(kd, list_head, offsets, pointer_size = 4, maximum = 4096):
    """Reads EPROCESS facts through KD or GDB using supplied offsets."""
    processes = []
    def pointer(address):
        return _target_int(kd, address, pointer_size)
    for address in walk_linked_list(pointer, list_head, offsets["links"], maximum):
        image = _virtual_bytes(kd, address + offsets["image_name"], offsets.get("image_name_size", 16))
        processes.append({
            "address": address,
            "pid": _target_int(kd, address + offsets["pid"], pointer_size),
            "directory_table_base": _target_int(kd, address + offsets["directory_table_base"], pointer_size),
            "peb": _target_int(kd, address + offsets["peb"], pointer_size),
            "image_name": binary.text(image, encoding = "ascii", nul = True),
        })
    return processes

def process_list_head(kd, kernel_base, ps_initial_system_process_rva, offsets, pointer_size = 4):
    """Derives PsActiveProcessHead from PsInitialSystemProcess and a layout."""
    if kernel_base < 0 or ps_initial_system_process_rva < 0:
        fail("invalid kernel image location")
    system = _target_int(kd, kernel_base + ps_initial_system_process_rva, pointer_size)
    if system == 0:
        fail("PsInitialSystemProcess is NULL")
    if _target_int(kd, system + offsets["pid"], pointer_size) != 4:
        fail("PsInitialSystemProcess does not identify PID 4")
    system_links = system + offsets["links"]
    head = _target_int(kd, system_links + pointer_size, pointer_size)
    if head == 0 or _target_int(kd, head, pointer_size) != system_links:
        fail("PsActiveProcessHead linkage is inconsistent")
    return head

def process_list_head_from_kernel(kd, kernel_base, kernel_image, offsets, pointer_size = 4):
    """Derives PsActiveProcessHead using the boot kernel's actual PE exports."""
    return process_list_head(
        kd,
        kernel_base,
        pe_export_rva(kernel_image, "PsInitialSystemProcess"),
        offsets,
        pointer_size,
    )

def find_eprocess(kd, list_head, offsets, image_name = None, pid = None, pointer_size = 4, maximum = 4096):
    """Finds one process by image name or PID in a bounded EPROCESS walk."""
    if (image_name == None) == (pid == None):
        fail("specify exactly one of image_name or pid")
    wanted = image_name.lower() if image_name != None else None
    for process in eprocesses(kd, list_head, offsets, pointer_size, maximum):
        if (wanted != None and process["image_name"].lower() == wanted) or (pid != None and process["pid"] == pid):
            return process
    return None

def wait_for_eprocess_insertion(gdb, list_head, offsets, image_name = None, pid = None, pointer_size = 4, maximum = 4096, max_stops = 4096, timeout = 30):
    """Waits for a process-list insertion and returns the selected EPROCESS.

    The active process list's tail pointer changes while a process is inserted,
    before its initial user thread can execute.  Watching that pointer avoids
    races inherent in periodically interrupting a fast whole-system target.
    """
    if max_stops < 1 or max_stops > 1000000 or timeout <= 0:
        fail("invalid process insertion wait limit")
    process = find_eprocess(gdb, list_head, offsets, image_name, pid, pointer_size, maximum)
    if process != None:
        return {"process": process, "stop": None}
    point = gdb.watchpoint(list_head + pointer_size, pointer_size, access = "write")
    deadline = clock.monotonic() + timeout
    stops = 0
    while stops < max_stops:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            point.remove()
            fail("timed out waiting for process insertion")
        getattr(gdb, "continue")(timeout = remaining)
        stop = gdb.wait(timeout = remaining)
        stops += 1
        process = find_eprocess(gdb, list_head, offsets, image_name, pid, pointer_size, maximum)
        if process != None:
            point.remove()
            return {"process": process, "stop": stop}
    point.remove()
    fail("process insertion exceeded its stop budget")

def wait_for_process_peb(gdb, process, offsets, pointer_size = 4, max_stops = 4096, timeout = 30):
    """Waits until a newly inserted EPROCESS receives a non-NULL PEB."""
    if max_stops < 1 or max_stops > 1000000 or timeout <= 0:
        fail("invalid process PEB wait limit")
    field = process["address"] + offsets["peb"]
    peb = _target_int(gdb, field, pointer_size)
    if peb:
        process["peb"] = peb
        return {"process": process, "stop": None}
    point = gdb.watchpoint(field, pointer_size, access = "write")
    deadline = clock.monotonic() + timeout
    stops = 0
    while stops < max_stops:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            point.remove()
            fail("timed out waiting for process PEB")
        getattr(gdb, "continue")(timeout = remaining)
        stop = gdb.wait(timeout = remaining)
        stops += 1
        peb = _target_int(gdb, field, pointer_size)
        if peb:
            point.remove()
            process["peb"] = peb
            return {"process": process, "stop": stop}
    point.remove()
    fail("process PEB wait exceeded its stop budget")

def process_image_base(gdb, process, pointer_size = 4):
    """Reads PEB.ImageBaseAddress in an EPROCESS address space."""
    if process["peb"] == 0:
        fail("process has no PEB")
    def inspect():
        return read_int(gdb, process["peb"] + 2 * pointer_size, pointer_size)
    return inspect_in_address_space(gdb, process["directory_table_base"], inspect)

def read_process_virtual(kd, process, address, size, pae = True, maximum = 64 << 20):
    """Reads i386 user memory using an EPROCESS-derived address space."""
    return read_i386_virtual(kd, process["directory_table_base"], address, size, pae = pae, maximum = maximum)

def write_process_virtual(kd, process, address, value, pae = True, maximum = 64 << 20):
    """Writes bounded i386 user memory using an EPROCESS address space."""
    return write_i386_virtual(kd, process["directory_table_base"], address, value, pae = pae, maximum = maximum)

def read_amd64_process_virtual(kd, process, address, size, maximum = 64 << 20):
    """Reads one amd64 process using an EPROCESS-derived page-map base."""
    return read_amd64_virtual(kd, process["directory_table_base"], address, size, maximum = maximum)

def write_amd64_process_virtual(kd, process, address, value, maximum = 64 << 20):
    """Writes one amd64 process using an EPROCESS-derived page-map base."""
    return write_amd64_virtual(kd, process["directory_table_base"], address, value, maximum = maximum)

def _read_process_int(kd, process, address, size, pae):
    return _uint(read_process_virtual(kd, process, address, size, pae = pae))

def _read_process_unicode_string(kd, process, address, pointer_size, pae, maximum):
    descriptor = read_process_virtual(kd, process, address, 4 + pointer_size, pae = pae)
    length = binary.read_u16le(descriptor)
    capacity = binary.read_u16le(descriptor, 2)
    buffer = _uint(descriptor[4:4 + pointer_size])
    if length > capacity or length & 1 or length > maximum:
        fail("process UNICODE_STRING exceeds its bound")
    if length == 0:
        return ""
    if buffer == 0:
        fail("non-empty process UNICODE_STRING has no buffer")
    return binary.text(read_process_virtual(kd, process, buffer, length, pae = pae), encoding = "utf16le")

def process_modules(kd, process, offsets, pointer_size = 4, pae = True, maximum = 1024, maximum_name_bytes = 64 << 10):
    """Reads one process's bounded PEB loader list through KD physical memory."""
    if pointer_size != 4:
        fail("KD process module traversal currently supports only i386")
    if process["peb"] == 0:
        fail("process has no PEB")
    if maximum < 1 or maximum > 65536 or maximum_name_bytes < 2 or maximum_name_bytes > 1 << 20:
        fail("invalid process module traversal bounds")
    pointer = lambda address: _read_process_int(kd, process, address, pointer_size, pae)
    ldr = pointer(process["peb"] + offsets["peb_ldr"])
    if ldr == 0:
        fail("process PEB has no loader data")
    head = ldr + offsets["ldr_list"]
    modules = []
    for address in walk_linked_list(pointer, head, offsets["entry_links"], maximum):
        modules.append({
            "address": address,
            "base": pointer(address + offsets["entry_base"]),
            "full_name": _read_process_unicode_string(kd, process, address + offsets["entry_full_name"], pointer_size, pae, maximum_name_bytes),
            "name": _read_process_unicode_string(kd, process, address + offsets["entry_name"], pointer_size, pae, maximum_name_bytes),
            "size": _read_process_int(kd, process, address + offsets["entry_size"], 4, pae),
        })
    return modules

def find_process_module(kd, process, offsets, name, pointer_size = 4, pae = True, maximum = 1024):
    """Finds one case-insensitive module name in a process PEB loader list."""
    wanted = name.lower()
    matches = [
        module
        for module in process_modules(kd, process, offsets, pointer_size = pointer_size, pae = pae, maximum = maximum)
        if module["name"].lower() == wanted
    ]
    if len(matches) > 1:
        fail("process contains duplicate module name: %s" % name)
    return matches[0] if matches else None

def _read_amd64_process_int(kd, process, address, size):
    return _uint(read_amd64_process_virtual(kd, process, address, size))

def _read_amd64_process_unicode_string(kd, process, address, maximum):
    descriptor = read_amd64_process_virtual(kd, process, address, 16)
    length = binary.read_u16le(descriptor)
    capacity = binary.read_u16le(descriptor, 2)
    buffer = binary.read_u64le(descriptor, 8)
    if length > capacity or length & 1 or length > maximum:
        fail("amd64 process UNICODE_STRING exceeds its bound")
    if length == 0:
        return ""
    if buffer == 0:
        fail("non-empty amd64 process UNICODE_STRING has no buffer")
    return binary.text(read_amd64_process_virtual(kd, process, buffer, length), encoding = "utf16le")

def process_modules_amd64(kd, process, offsets, maximum = 1024, maximum_name_bytes = 64 << 10):
    """Reads one amd64 process's bounded PEB loader list through page tables."""
    if process["peb"] == 0:
        fail("process has no PEB")
    if maximum < 1 or maximum > 65536 or maximum_name_bytes < 2 or maximum_name_bytes > 1 << 20:
        fail("invalid amd64 process module traversal bounds")
    pointer = lambda address: _read_amd64_process_int(kd, process, address, 8)
    ldr = pointer(process["peb"] + offsets["peb_ldr"])
    if ldr == 0:
        fail("amd64 process PEB has no loader data")
    head = ldr + offsets["ldr_list"]
    modules = []
    for address in walk_linked_list(pointer, head, offsets["entry_links"], maximum):
        modules.append({
            "address": address,
            "base": pointer(address + offsets["entry_base"]),
            "full_name": _read_amd64_process_unicode_string(kd, process, address + offsets["entry_full_name"], maximum_name_bytes),
            "name": _read_amd64_process_unicode_string(kd, process, address + offsets["entry_name"], maximum_name_bytes),
            "size": _read_amd64_process_int(kd, process, address + offsets["entry_size"], 4),
        })
    return modules

def find_process_module_amd64(kd, process, offsets, name, maximum = 1024):
    """Finds one case-insensitive module in an amd64 process loader list."""
    wanted = name.lower()
    matches = [
        module
        for module in process_modules_amd64(kd, process, offsets, maximum = maximum)
        if module["name"].lower() == wanted
    ]
    if len(matches) > 1:
        fail("amd64 process contains duplicate module name: %s" % name)
    return matches[0] if matches else None

def install_amd64_process_breakpoint(kd, process, address):
    """Installs one debugger-owned INT3 in a selected amd64 process."""
    original = read_amd64_process_virtual(kd, process, address, 1)
    if original == b"\xcc":
        fail("refusing to replace an existing amd64 process INT3")
    write_amd64_process_virtual(kd, process, address, b"\xcc")
    return {
        "address": address,
        "architecture": "amd64",
        "installed": True,
        "original": original,
        "process": process,
    }

def install_process_breakpoint(kd, process, address, pae = True):
    """Installs one debugger-owned INT3 in a selected i386 process."""
    original = read_process_virtual(kd, process, address, 1, pae = pae)
    if original == b"\xcc":
        fail("refusing to replace an existing process INT3")
    write_process_virtual(kd, process, address, b"\xcc", pae = pae)
    return {
        "address": address,
        "installed": True,
        "original": original,
        "pae": pae,
        "process": process,
    }

def restore_process_breakpoint(kd, breakpoint):
    """Restores a process breakpoint's original instruction byte once."""
    if breakpoint.get("installed", False):
        if breakpoint.get("architecture") == "amd64":
            write_amd64_process_virtual(
                kd,
                breakpoint["process"],
                breakpoint["address"],
                breakpoint["original"],
            )
            breakpoint["installed"] = False
            return
        write_process_virtual(
            kd,
            breakpoint["process"],
            breakpoint["address"],
            breakpoint["original"],
            pae = breakpoint["pae"],
        )
        breakpoint["installed"] = False

def rearm_process_breakpoint(kd, breakpoint):
    """Reinstalls a previously restored debugger-owned process breakpoint."""
    if not breakpoint.get("installed", False):
        if breakpoint.get("architecture") == "amd64":
            current = read_amd64_process_virtual(kd, breakpoint["process"], breakpoint["address"], 1)
            if current != breakpoint["original"]:
                fail("amd64 process breakpoint instruction changed before rearm")
            write_amd64_process_virtual(kd, breakpoint["process"], breakpoint["address"], b"\xcc")
            breakpoint["installed"] = True
            return
        current = read_process_virtual(
            kd,
            breakpoint["process"],
            breakpoint["address"],
            1,
            pae = breakpoint["pae"],
        )
        if current != breakpoint["original"]:
            fail("process breakpoint instruction changed before rearm")
        write_process_virtual(
            kd,
            breakpoint["process"],
            breakpoint["address"],
            b"\xcc",
            pae = breakpoint["pae"],
        )
        breakpoint["installed"] = True

def peb_modules(gdb, directory_table_base, peb, offsets, pointer_size = 4, maximum = 1024):
    """Reads a user PEB loader list while restoring the debugger's CR3."""
    def inspect():
        def pointer(address):
            return read_int(gdb, address, pointer_size)
        ldr = pointer(peb + offsets["peb_ldr"])
        head = ldr + offsets["ldr_list"]
        modules = []
        for address in walk_linked_list(pointer, head, offsets["entry_links"], maximum):
            modules.append({
                "address": address,
                "base": pointer(address + offsets["entry_base"]),
                "size": read_int(gdb, address + offsets["entry_size"], 4),
                "name": read_unicode_string(gdb, address + offsets["entry_name"], pointer_size),
            })
        return modules
    return inspect_in_address_space(gdb, directory_table_base, inspect)
