"""Static COM facts derived from generic PE, binary, and x86 primitives."""

_HEX = "0123456789abcdefABCDEF"
_NULL_GUID_HEX = "0" * 32

def _hex(value, width):
    text = hex(value)[2:].upper()
    return "0" * (width - len(text)) + text

def guid(raw):
    """Formats a 16-byte little-endian Windows GUID."""
    cursor = binary.cursor(raw)
    return "{%s-%s-%s-%s-%s}" % (
        _hex(cursor.u32le(), 8),
        _hex(cursor.u16le(), 4),
        _hex(cursor.u16le(), 4),
        hex(cursor.bytes(2)).upper(),
        hex(cursor.bytes(6)).upper(),
    )

def guid_bytes(value):
    """Encodes a canonical textual GUID as its 16-byte Windows representation."""
    if len(value) != 38 or value[0] != "{" or value[-1] != "}":
        return None
    for index in [9, 14, 19, 24]:
        if value[index] != "-":
            return None
    compact = value[1:-1].replace("-", "")
    if len(compact) != 32:
        return None
    for index in range(len(compact)):
        if compact[index] not in _HEX:
            return None
    network = binary.decode(compact, encoding = "hex")
    return binary.concat([network[0:4][::-1], network[4:6][::-1], network[6:8][::-1], network[8:]])

def _text_guids(file):
    found = {}
    for text in binary.strings(file, encoding = "ascii", minimum = 38):
        start = 0
        while start < len(text):
            left = text.find("{", start)
            if left < 0:
                break
            candidate = text[left:left + 38]
            raw = guid_bytes(candidate)
            # A null GUID is a sentinel, not a COM class identity.  Matching
            # its all-zero byte representation against a PE is otherwise
            # guaranteed to produce false positives.
            if raw != None and hex(raw) != _NULL_GUID_HEX:
                found[hex(raw)] = guid(raw)
            start = left + 1
    return found

def export_rva(pe, name):
    """Returns a named export RVA, or zero when it is absent."""
    for item in pe.exports:
        if item.get("name", "") == name:
            return item["rva"]
    return 0

def _mapped(pe, rva, size = 1):
    for section in pe.sections:
        start = section["virtual_address"]
        if rva >= start and rva + size <= start + section["raw_size"]:
            return True
    return False

def pointer_string_table(file, suffix = "", minimum = 2, maximum = 260):
    """Returns the longest aligned PE pointer table naming bounded ASCII strings.

    The suffix is a caller-owned policy filter. Pointers and strings must both
    resolve inside raw PE sections, and path-like values are rejected so a DLL
    dependency table cannot be confused with arbitrary text.
    """
    if minimum < 1 or maximum < 1:
        fail("minimum and maximum must be positive")
    longest = []
    for sequence in windows.pe(file).pointer_string_tables(suffix = suffix, minimum = minimum, maximum = maximum):
        if len(sequence) > len(longest) and not any(["\\" in value or "/" in value or ":" in value for value in sequence]):
            longest = sequence
    return longest if len(longest) >= minimum else []

def _initial_target(pe, rva):
    if not _mapped(pe, rva):
        return rva
    for instruction in pe.disasm(rva, size = 32):
        if instruction["op"] == "jmp" and instruction["operands"] and instruction["operands"][0]["kind"] == "relative":
            target = instruction["operands"][0]["target"]
            return target if _mapped(pe, target) else rva
        if instruction["op"] == "ret":
            break
    return rva

def _direct_calls(pe, rva, size):
    output = []
    seen = {}
    for instruction in pe.disasm(rva, size = size):
        operands = instruction["operands"]
        if instruction["op"] == "call" and operands and operands[0]["kind"] == "relative":
            target = operands[0]["target"]
            if target not in seen and _mapped(pe, target):
                seen[target] = True
                output.append(target)
        if instruction["op"] == "ret":
            break
    return output

def class_ids(file, pe = None):
    """Finds classes served by a 32-bit PE's DllGetClassObject implementation.

    This mirrors common compiler output without interpreting the function: the
    generic disassembler identifies direct factory calls and immediate GUID
    references, while all COM knowledge stays here.
    """
    pe = pe or windows.pe(file)
    rva = export_rva(pe, "DllGetClassObject")
    if not rva or pe.info["machine"] != 0x14c:
        return []
    image_base = pe.info["image_base"]
    rva = _initial_target(pe, rva)
    textual = _text_guids(file)
    output = []
    seen = {}
    helpers = _direct_calls(pe, rva, 256)
    for factory in helpers:
        for instruction in pe.disasm(factory, size = 256):
            operands = instruction["operands"]
            if instruction["op"] == "push" and operands and operands[0]["kind"] == "immediate":
                address = operands[0]["u32"]
                target_rva = address - image_base
                if address >= image_base and _mapped(pe, target_rva, 16):
                    raw = pe.read(target_rva, 16)
                    value = textual.get(hex(raw))
                    if hex(raw) != _NULL_GUID_HEX and value != None and value not in seen:
                        seen[value] = True
                        output.append(value)
            if instruction["op"] == "ret":
                break
    for instruction in pe.disasm(rva, size = 512):
        operands = instruction["operands"]
        if instruction["op"] == "mov" and len(operands) >= 2 and operands[0].get("name") == "edi" and operands[1]["kind"] == "immediate":
            address = operands[1]["u32"]
            target_rva = address - image_base
            if address >= image_base and _mapped(pe, target_rva, 16):
                raw = pe.read(target_rva, 16)
                value = guid(raw)
                if hex(raw) != _NULL_GUID_HEX and value not in seen:
                    seen[value] = True
                    output.append(value)
        if instruction["op"] == "ret":
            break
    return output
