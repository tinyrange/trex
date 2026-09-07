"""Native-width layouts shared by Windows execution plugins."""

def pointer_array(machine, values, name = "pointer array"):
    """Allocates an array of guest pointers without host-width assumptions."""
    address = machine.allocate(size = len(values) * machine.pointer_size, name = name)
    for index, value in enumerate(values):
        machine.write_pointer(address + index * machine.pointer_size, value)
    return address

def teb_layout(pointer_size):
    """Returns the common NT_TIB and initial TEB pointer-field offsets."""
    if pointer_size not in [4, 8]:
        fail("Windows TEB requires a 4- or 8-byte pointer")
    fields = [
        "ExceptionList", "StackBase", "StackLimit", "SubSystemTib",
        "FiberData", "ArbitraryUserPointer", "Self", "EnvironmentPointer",
        "ProcessId", "ThreadId", "ActiveRpcHandle", "ThreadLocalStoragePointer", "ProcessEnvironmentBlock",
    ]
    return {
        "segment": "gs" if pointer_size == 8 else "fs",
        "fields": {name: index * pointer_size for index, name in enumerate(fields)},
    }

def _layout(pointer_size, fields):
    types = {
        "u8": (1, 1),
        "u16": (2, 2),
        "u32": (4, 4),
        "pointer": (pointer_size, pointer_size),
        "unicode": (pointer_size * 2, pointer_size),
    }
    offset = 0
    result = {}
    for name, kind in fields:
        size, alignment = types[kind]
        offset = (offset + alignment - 1) // alignment * alignment
        result[name] = offset
        offset += size
    return result

def counted_string_layout(pointer_size):
    """Returns native STRING/UNICODE_STRING field offsets and total size."""
    if pointer_size not in [4, 8]:
        fail("Windows counted strings require a 4- or 8-byte pointer")
    fields = _layout(pointer_size, [("Length", "u16"), ("MaximumLength", "u16"), ("Buffer", "pointer")])
    fields["Size"] = fields["Buffer"] + pointer_size
    return fields

def object_attributes_layout(pointer_size):
    """Returns the native OBJECT_ATTRIBUTES layout, including alignment."""
    if pointer_size not in [4, 8]:
        fail("OBJECT_ATTRIBUTES requires a 4- or 8-byte pointer")
    fields = _layout(pointer_size, [
        ("Length", "u32"), ("RootDirectory", "pointer"), ("ObjectName", "pointer"),
        ("Attributes", "u32"), ("SecurityDescriptor", "pointer"), ("SecurityQualityOfService", "pointer"),
    ])
    fields["Size"] = fields["SecurityQualityOfService"] + pointer_size
    return fields

def security_descriptor_layout(pointer_size, relative = False):
    """Returns absolute native-pointer or fixed-width self-relative SD fields."""
    if pointer_size not in [4, 8]:
        fail("Security descriptors require a 4- or 8-byte pointer")
    reference = "u32" if relative else "pointer"
    fields = _layout(pointer_size, [
        ("Revision", "u8"), ("Sbz1", "u8"), ("Control", "u16"),
        ("Owner", reference), ("Group", reference), ("Sacl", reference), ("Dacl", reference),
    ])
    fields["Size"] = fields["Dacl"] + (4 if relative else pointer_size)
    return fields

def system_info_layout(pointer_size):
    """Returns SYSTEM_INFO fields with native pointer and affinity-mask widths."""
    if pointer_size not in [4, 8]:
        fail("SYSTEM_INFO requires a 4- or 8-byte pointer")
    fields = _layout(pointer_size, [
        ("ProcessorArchitecture", "u16"), ("Reserved", "u16"), ("PageSize", "u32"),
        ("MinimumApplicationAddress", "pointer"), ("MaximumApplicationAddress", "pointer"),
        ("ActiveProcessorMask", "pointer"), ("NumberOfProcessors", "u32"),
        ("ProcessorType", "u32"), ("AllocationGranularity", "u32"),
        ("ProcessorLevel", "u16"), ("ProcessorRevision", "u16"),
    ])
    fields["Size"] = fields["ProcessorRevision"] + 2
    return fields

def process_layout(pointer_size):
    """Returns named offsets for the modeled PEB and process-parameter prefix."""
    if pointer_size not in [4, 8]:
        fail("Windows process structures require a 4- or 8-byte pointer")
    peb = _layout(pointer_size, [
        ("Flags", "u32"), ("Mutant", "pointer"), ("ImageBaseAddress", "pointer"),
        ("Ldr", "pointer"), ("ProcessParameters", "pointer"),
        ("SubSystemData", "pointer"), ("ProcessHeap", "pointer"),
    ])
    parameters = _layout(pointer_size, [
        ("MaximumLength", "u32"), ("Length", "u32"), ("Flags", "u32"), ("DebugFlags", "u32"),
        ("ConsoleHandle", "pointer"), ("ConsoleFlags", "u32"),
        ("StandardInput", "pointer"), ("StandardOutput", "pointer"), ("StandardError", "pointer"),
        ("CurrentDirectoryPath", "unicode"), ("CurrentDirectoryHandle", "pointer"),
        ("DllPath", "unicode"), ("ImagePathName", "unicode"), ("CommandLine", "unicode"),
        ("Environment", "pointer"),
    ])
    return {"peb": peb, "parameters": parameters}
