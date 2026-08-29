"""Compact, validated executable signatures and emulator transformations."""

def code_signature(anchor, size, sha256, normalize_relative = False, anchor_mask = None):
    """Describes code using a short anchor and a full-region SHA-256 digest.

    Relative call and branch operands may be normalized before hashing. This
    keeps generated-code signatures stable across allocator addresses without
    weakening validation of opcodes, registers, constants, or layout.
    """
    digest = binary.decode(sha256, encoding = "hex") if type(sha256) == "string" else sha256
    if len(anchor) == 0 or len(anchor) > 64 or size < len(anchor) or len(digest) != 32:
        fail("invalid executable signature")
    if anchor_mask != None and len(anchor_mask) != len(anchor):
        fail("executable signature mask does not match its anchor")
    return {
        "anchor": anchor,
        "anchor_mask": anchor_mask,
        "size": size,
        "digest": digest,
        "normalize_relative": normalize_relative,
    }

def _code_digest(value, normalize_relative):
    if not normalize_relative:
        return crypto.hash("sha256", value)
    output = binary.builder()
    for instruction in debug.disassemble(value):
        output.append(instruction.normalized_bytes)
    return crypto.hash("sha256", output.bytes())

def executable_signature_rva(image, file_offset, signature):
    """Validates one signature match and converts it to an image RVA."""
    pe = windows.pe(image)
    for section in pe.sections:
        start = section["raw_offset"]
        end = start + section["raw_size"]
        region_end = file_offset + signature["size"]
        if file_offset >= start and region_end <= end and section["characteristics"] & 0x20000000:
            value = binary.view(image)[file_offset:region_end]
            if crypto.constant_time_equal(
                _code_digest(value, signature["normalize_relative"]),
                signature["digest"],
            ):
                return section["virtual_address"] + file_offset - start
    return None

def unique_executable_signature_rva(image, signature):
    """Returns the RVA of exactly one validated executable match, or `None`."""
    if signature["anchor_mask"] != None:
        fail("masked anchors are only supported for runtime transformations")
    view = binary.view(image)
    cursor = 0
    match = None
    while cursor < view.size:
        offset = view.find(signature["anchor"], start = cursor)
        if offset < 0:
            break
        rva = executable_signature_rva(image, offset, signature)
        if rva != None:
            if match != None:
                return None
            match = rva
        cursor = offset + 1
    return match

def module_source(module_files, module_name):
    """Finds one module image by case-insensitive basename."""
    for name, image in module_files.items():
        if name.replace("\\", "/").split("/")[-1].lower() == module_name.lower():
            return image
    return None

def module_base(machine, module_name):
    """Finds one mapped module base by case-insensitive name."""
    for module in machine.modules:
        if module.name.lower() == module_name.lower():
            return module.base
    return 0

def _locate(machine, module_files, module_name, signature):
    source = module_source(module_files, module_name)
    base = module_base(machine, module_name)
    if source == None or not base:
        return None
    rva = unique_executable_signature_rva(source, signature)
    return None if rva == None else (base, rva)

def install_loop(machine, module_files, module_name, signature, maximum_instructions = 1 << 20):
    """Installs one digest-validated, bounded x86 loop."""
    location = _locate(machine, module_files, module_name, signature)
    if location == None:
        return None
    base, rva = location
    acceleration = machine.accelerate_loop(
        address = base + rva,
        size = signature["size"],
        digest = signature["digest"],
        normalize_relative = signature["normalize_relative"],
        maximum_instructions = maximum_instructions,
    )
    return {
        "module": module_name,
        "rva": rva,
        "size": signature["size"],
        "instructions": acceleration.instructions,
    }

def install_region(machine, module_files, module_name, signature, entry_offset = 0, maximum_instructions = 1 << 20, reenter = False):
    """Batches a digest-validated code region while preserving x86 behavior.

    Unlike a loop accelerator, a region may contain indirect internal control
    flow. Execution yields when it leaves the region or reaches its bound.
    """
    location = _locate(machine, module_files, module_name, signature)
    if location == None:
        return None
    base, rva = location
    acceleration = machine.accelerate_region(
        entry = base + rva + entry_offset,
        start = base + rva,
        size = signature["size"],
        digest = signature["digest"],
        reenter = reenter,
        maximum_instructions = maximum_instructions,
    )
    return {
        "module": module_name,
        "rva": rva,
        "entry_rva": rva + entry_offset,
        "size": signature["size"],
        "operation": "bounded execution region",
        "entry": acceleration.entry,
    }

def install_relocated_region(machine, module_files, module_name, signature, entry_offset = 0, maximum_instructions = 1 << 20, reenter = False):
    """Batches source-validated code after applying PE base relocations.

    The complete on-disk region is first identified by its declared digest.
    The emulator then validates the complete mapped region against a runtime
    digest derived from that trusted source mapping. No relocated code bytes
    are retained in Starlark or committed as an alternate payload.
    """
    location = _locate(machine, module_files, module_name, signature)
    if location == None:
        return None
    base, rva = location
    start = base + rva
    runtime_digest = crypto.hash("sha256", machine.read(start, signature["size"]))
    acceleration = machine.accelerate_region(
        entry = start + entry_offset,
        start = start,
        size = signature["size"],
        digest = runtime_digest,
        reenter = reenter,
        maximum_instructions = maximum_instructions,
    )
    return {
        "module": module_name,
        "rva": rva,
        "entry_rva": rva + entry_offset,
        "size": signature["size"],
        "operation": "relocated bounded execution region",
        "entry": acceleration.entry,
    }

def install_function(machine, module_files, module_name, signature, operation, argc, callback):
    """Hooks one uniquely located, digest-validated executable function."""
    location = _locate(machine, module_files, module_name, signature)
    if location == None:
        return None
    base, rva = location
    machine.hook(callback, module = module_name, name = operation, address = base + rva, argc = argc)
    return {
        "module": module_name,
        "rva": rva,
        "size": signature["size"],
        "operation": operation,
    }

def install_rewrite(machine, module_files, module_name, signature, operation, callback):
    """Installs one digest-validated inline rewrite."""
    location = _locate(machine, module_files, module_name, signature)
    if location == None:
        return None
    base, rva = location
    machine.rewrite(
        address = base + rva,
        size = signature["size"],
        digest = signature["digest"],
        normalize_relative = signature["normalize_relative"],
        callback = callback,
        name = operation,
    )
    return {
        "module": module_name,
        "rva": rva,
        "size": signature["size"],
        "operation": operation,
    }

def install_transform(machine, signature, operation, callback):
    """Installs a validated transformation for generated executable code."""
    transformation = machine.transform(
        anchor = signature["anchor"],
        anchor_mask = signature["anchor_mask"],
        size = signature["size"],
        digest = signature["digest"],
        normalize_relative = signature["normalize_relative"],
        callback = callback,
        name = operation,
    )
    return {
        "runtime": True,
        "id": transformation.id,
        "size": signature["size"],
        "operation": operation,
    }

def install_runtime_region(machine, signature, operation, entry_offset = 0, maximum_instructions = 1 << 20, reenter = True):
    """Batches a digest-validated region when generated code materializes."""
    acceleration = machine.accelerate_runtime_region(
        anchor = signature["anchor"],
        anchor_mask = signature["anchor_mask"],
        size = signature["size"],
        digest = signature["digest"],
        entry_offset = entry_offset,
        name = operation,
        normalize_relative = signature["normalize_relative"],
        reenter = reenter,
        maximum_instructions = maximum_instructions,
    )
    return {
        "runtime": True,
        "id": acceleration.id,
        "size": signature["size"],
        "operation": operation,
    }
