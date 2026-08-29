"""Windows registry-key, SID, ACL, ACE, and security-descriptor primitives."""

_BOOT_KEY_PERMUTATION = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

def _security_byte_values(value):
    cursor = binary.cursor(value)
    output = []
    while cursor.remaining:
        output.append(cursor.u8())
    return output

def _security_bytes(values):
    output = binary.builder(capacity = len(values))
    for value in values:
        output.u8(value)
    return output.bytes()

def registry_boot_key(class_fragments):
    """Decodes the four obfuscated LSA registry classes into a boot key."""
    if len(class_fragments) != 4:
        fail("Windows boot key requires four class fragments")
    raw = _security_byte_values(binary.decode("".join(class_fragments), encoding = "hex"))
    if len(raw) != 16:
        fail("Windows boot key classes must decode to 16 bytes")
    return _security_bytes([raw[index] for index in _BOOT_KEY_PERMUTATION])

def registry_boot_key_classes(key):
    """Encodes a 16-byte boot key into its four obfuscated registry classes."""
    values = _security_byte_values(key)
    if len(values) != 16:
        fail("Windows boot key must contain 16 bytes")
    raw = [0 for unused in range(16)]
    for index in range(16):
        raw[_BOOT_KEY_PERMUTATION[index]] = values[index]
    encoded = hex(_security_bytes(raw))
    return [encoded[index * 8:index * 8 + 8] for index in range(4)]

def _odd_parity(value):
    value &= 0xfe
    bits = 0
    current = value
    while current:
        bits += current & 1
        current >>= 1
    return value | 1 if bits % 2 == 0 else value

def des_56_key(value):
    """Expands seven key bytes into a DES key with odd parity."""
    key = _security_byte_values(value)
    if len(key) != 7:
        fail("DES-56 key material must contain exactly seven bytes")
    output = [
        key[0] >> 1,
        ((key[0] & 0x01) << 6) | (key[1] >> 2),
        ((key[1] & 0x03) << 5) | (key[2] >> 3),
        ((key[2] & 0x07) << 4) | (key[3] >> 4),
        ((key[3] & 0x0f) << 3) | (key[4] >> 5),
        ((key[4] & 0x1f) << 2) | (key[5] >> 6),
        ((key[5] & 0x3f) << 1) | (key[6] >> 7),
        key[6] & 0x7f,
    ]
    return _security_bytes([_odd_parity(item << 1) for item in output])

def legacy_lsa_secret_crypt(key, data, decrypt = False):
    """Applies the legacy LSA rolling-DES transform to whole blocks."""
    if len(key) < 7 or len(data) % 8:
        fail("invalid legacy LSA secret crypt input")
    output = binary.builder(capacity = len(data))
    key_offset = 0
    for offset in range(0, len(data), 8):
        if len(key) - key_offset < 7:
            key_offset = len(key) - key_offset
        output.append(crypto.des(des_56_key(key[key_offset:key_offset + 7]), data[offset:offset + 8], decrypt = decrypt))
        key_offset += 7
    return output.bytes()

def sid(identifier_authority, subauthorities):
    """Returns a revision-1 SID."""
    if identifier_authority < 0 or identifier_authority >= (1 << 48):
        fail("SID identifier authority exceeds 48 bits")
    if len(subauthorities) > 255:
        fail("SID has too many subauthorities")
    output = binary.builder(capacity = 8 + 4 * len(subauthorities))
    output.u8(1)
    output.u8(len(subauthorities))
    for shift in [40, 32, 24, 16, 8, 0]:
        output.u8((identifier_authority >> shift) & 0xff)
    for value in subauthorities:
        output.u32le(value)
    return output.bytes()

def access_allowed_ace(principal, mask, flags = 0):
    """Returns an ACCESS_ALLOWED_ACE for principal."""
    output = binary.builder(capacity = 8 + len(principal))
    output.u8(0)
    output.u8(flags)
    output.u16le(8 + len(principal))
    output.u32le(mask)
    output.append(principal)
    return output.bytes()

def acl(aces, revision = 2, size = None):
    """Returns an ACL containing aces."""
    content_size = 8
    for ace in aces:
        content_size += len(ace)
    size = content_size if size == None else size
    if size < content_size:
        fail("ACL size is smaller than its ACE content")
    if size > 0xffff or len(aces) > 0xffff:
        fail("ACL exceeds 16-bit format limits")
    output = binary.builder(capacity = size)
    output.u8(revision)
    output.u8(0)
    output.u16le(size)
    output.u16le(len(aces))
    output.u16le(0)
    for ace in aces:
        output.append(ace)
    output.reserve(size - content_size)
    return output.bytes()

def security_descriptor(owner = None, group = None, dacl = None, sacl = None, control = 0):
    """Returns a revision-1 self-relative security descriptor."""
    control |= 0x8000
    if dacl != None:
        control |= 0x0004
    if sacl != None:
        control |= 0x0010

    components = []
    offset = 20
    offsets = {"owner": 0, "group": 0, "sacl": 0, "dacl": 0}
    # NT5 namespace descriptors place ACLs before owner and group SIDs.
    for name, value in [("dacl", dacl), ("sacl", sacl), ("owner", owner), ("group", group)]:
        if value != None:
            offsets[name] = offset
            components.append(value)
            offset += len(value)

    output = binary.builder(capacity = offset)
    output.u8(1)
    output.u8(0)
    output.u16le(control)
    output.u32le(offsets["owner"])
    output.u32le(offsets["group"])
    output.u32le(offsets["sacl"])
    output.u32le(offsets["dacl"])
    for component in components:
        output.append(component)
    return output.bytes()

_SDDL_SIDS = {
    "AC": "S-1-15-2-1",
    "AN": "S-1-5-7",
    "AO": "S-1-5-32-548",
    "AU": "S-1-5-11",
    "BA": "S-1-5-32-544",
    "BG": "S-1-5-32-546",
    "BO": "S-1-5-32-551",
    "BU": "S-1-5-32-545",
    "CG": "S-1-3-1",
    "CO": "S-1-3-0",
    "IU": "S-1-5-4",
    "LS": "S-1-5-19",
    "LU": "S-1-5-32-559",
    "MU": "S-1-5-32-558",
    "NS": "S-1-5-20",
    "NO": "S-1-5-32-556",
    "OW": "S-1-3-4",
    "PO": "S-1-5-32-550",
    "PU": "S-1-5-32-547",
    "RC": "S-1-5-12",
    "RD": "S-1-5-32-555",
    "RE": "S-1-5-32-552",
    "RU": "S-1-5-32-554",
    "SO": "S-1-5-32-549",
    "SU": "S-1-5-6",
    "SY": "S-1-5-18",
    "WD": "S-1-1-0",
}

_SDDL_RIGHTS = {
    "CC": 0x00000001, "DC": 0x00000002, "LC": 0x00000004,
    "SW": 0x00000008, "RP": 0x00000010, "WP": 0x00000020,
    "DT": 0x00000040, "LO": 0x00000080, "CR": 0x00000100,
    "FA": 0x001f01ff, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200a0,
    "KA": 0x000f003f, "KR": 0x00020019, "KW": 0x00020006, "KX": 0x00020019,
    "SD": 0x00010000, "RC": 0x00020000, "WD": 0x00040000,
    "WO": 0x00080000, "GA": 0x10000000, "GX": 0x20000000,
    "GW": 0x40000000, "GR": 0x80000000,
}

_SDDL_ACE_FLAGS = {
    "OI": 0x01, "CI": 0x02, "NP": 0x04, "IO": 0x08,
    "ID": 0x10, "SA": 0x40, "FA": 0x80,
}

def _sddl_sid(value, aliases):
    value = aliases.get(value.upper(), _SDDL_SIDS.get(value.upper(), value))
    parts = value.split("-")
    if len(parts) < 3 or parts[0].upper() != "S" or int(parts[1]) != 1:
        fail("unsupported SDDL SID " + value)
    authority = int(parts[2])
    subauthorities = [int(part) for part in parts[3:]]
    if authority < 0 or authority >= (1 << 48) or len(subauthorities) > 15:
        fail("SDDL SID is out of range " + value)
    return sid(authority, subauthorities)

def _sddl_bit_pairs(value, table, kind):
    if len(value) % 2:
        fail("invalid SDDL " + kind + " " + value)
    result = 0
    for offset in range(0, len(value), 2):
        token = value[offset:offset + 2].upper()
        if token not in table:
            fail("unsupported SDDL " + kind + " " + token)
        result |= table[token]
    return result

def _sddl_access_mask(value, generic_mapping):
    value = value.strip()
    if value.lower().startswith("0x"):
        mask = int(value[2:], 16)
    else:
        mask = _sddl_bit_pairs(value, _SDDL_RIGHTS, "right")
    if generic_mapping:
        mapped = mask & 0x0fffffff
        for bit, name in [
            (0x10000000, "all"),
            (0x20000000, "execute"),
            (0x40000000, "write"),
            (0x80000000, "read"),
        ]:
            if mask & bit:
                mapped |= generic_mapping[name]
        return mapped
    return mask

def _sddl_ace(value, aliases, generic_mapping):
    fields = value.split(";")
    if len(fields) != 6:
        fail("invalid SDDL ACE " + value)
    ace_types = {"A": 0, "D": 1, "AU": 2}
    ace_type = fields[0].upper()
    if ace_type not in ace_types:
        fail("unsupported SDDL ACE type " + fields[0])
    if fields[3] or fields[4]:
        fail("object-specific SDDL ACEs are not supported")
    principal = _sddl_sid(fields[5], aliases)
    output = binary.builder(capacity = 8 + len(principal))
    output.u8(ace_types[ace_type])
    output.u8(_sddl_bit_pairs(fields[1], _SDDL_ACE_FLAGS, "ACE flag"))
    output.u16le(8 + len(principal))
    output.u32le(_sddl_access_mask(fields[2], generic_mapping))
    output.append(principal)
    return output.bytes()

def _sddl_acl(value, sacl, aliases, generic_mapping):
    first_ace = value.find("(")
    flags = value if first_ace < 0 else value[:first_ace]
    control = 0
    while flags:
        token = flags[:2].upper() if flags.startswith("A") else flags[:1].upper()
        if token == "P":
            control |= 0x2000 if sacl else 0x1000
        elif token == "AI":
            control |= 0x0800 if sacl else 0x0400
        elif token == "AR":
            control |= 0x0200 if sacl else 0x0100
        else:
            fail("unsupported SDDL ACL flag " + token)
        flags = flags[len(token):]
    aces = []
    cursor = max(0, first_ace)
    while cursor < len(value):
        while cursor < len(value) and value[cursor] in " \t\r\n":
            cursor += 1
        if cursor == len(value):
            break
        if value[cursor] != "(":
            fail("invalid SDDL ACL " + value)
        end = value.find(")", cursor + 1)
        if end < 0:
            fail("unterminated SDDL ACE")
        aces.append(_sddl_ace(value[cursor + 1:end], aliases, generic_mapping))
        cursor = end + 1
    return acl(aces), control

def _merge_acl(parent, child):
    if parent == None:
        return child
    if child == None:
        return parent
    parent_cursor = binary.cursor(parent)
    child_cursor = binary.cursor(child)
    parent_revision = parent_cursor.u8()
    parent_cursor.u8()
    parent_size = parent_cursor.u16le()
    parent_count = parent_cursor.u16le()
    parent_cursor.u16le()
    child_revision = child_cursor.u8()
    child_cursor.u8()
    child_size = child_cursor.u16le()
    child_count = child_cursor.u16le()
    child_cursor.u16le()
    if parent_size != len(parent) or child_size != len(child):
        fail("cannot merge malformed ACL")
    output = binary.builder(capacity = parent_size + child_size - 8)
    output.u8(max(parent_revision, child_revision))
    output.u8(0)
    output.u16le(parent_size + child_size - 8)
    output.u16le(parent_count + child_count)
    output.u16le(0)
    output.append(parent[8:])
    output.append(child[8:])
    return output.bytes()

def _sddl_sections(value):
    sections = {}
    start = -1
    name = ""
    depth = 0
    for index in range(len(value)):
        character = value[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                fail("invalid SDDL parentheses")
        elif depth == 0 and index + 1 < len(value) and value[index + 1] == ":" and character.upper() in ["O", "G", "D", "S"]:
            if name:
                sections[name] = value[start:index]
            name = character.upper()
            start = index + 2
    if depth != 0:
        fail("invalid SDDL parentheses")
    if name:
        sections[name] = value[start:]
    elif value:
        fail("SDDL has no sections")
    return sections

def _security_descriptor_component(value, offset, is_acl):
    if offset == 0:
        return None
    if offset < 20 or offset >= len(value):
        fail("security descriptor component is out of range")
    if is_acl:
        if offset + 8 > len(value):
            fail("security descriptor ACL is truncated")
        size = binary.read_u16le(value, offset + 2)
    else:
        if offset + 8 > len(value):
            fail("security descriptor SID is truncated")
        size = 8 + binary.read_u8(value, offset + 1) * 4
    if size < 8 or offset + size > len(value):
        fail("security descriptor component is truncated")
    return value[offset:offset + size]

def security_descriptor_components(value):
    """Returns the components of a self-relative security descriptor."""
    if len(value) < 20:
        fail("security descriptor is truncated")
    cursor = binary.cursor(value)
    if cursor.u8() != 1:
        fail("unsupported security descriptor revision")
    cursor.u8()
    control = cursor.u16le()
    if control & 0x8000 == 0:
        fail("security descriptor is not self-relative")
    owner_offset = cursor.u32le()
    group_offset = cursor.u32le()
    sacl_offset = cursor.u32le()
    dacl_offset = cursor.u32le()
    return {
        "control": control,
        "owner": _security_descriptor_component(value, owner_offset, False),
        "group": _security_descriptor_component(value, group_offset, False),
        "dacl": _security_descriptor_component(value, dacl_offset, True),
        "sacl": _security_descriptor_component(value, sacl_offset, True),
    }

def sddl_security_descriptor(value, aliases = {}, base = None, generic_mapping = {}, inherit = False):
    """Encodes an SDDL security descriptor without host operating-system APIs."""
    sections = _sddl_sections(value)
    inherited = security_descriptor_components(base) if base != None and len(base) > 0 else {
        "control": 0,
        "owner": None,
        "group": None,
        "dacl": None,
        "sacl": None,
    }
    owner = _sddl_sid(sections["O"], aliases) if "O" in sections else inherited["owner"]
    group = _sddl_sid(sections["G"], aliases) if "G" in sections else inherited["group"]
    dacl, dacl_control = _sddl_acl(sections["D"], False, aliases, generic_mapping) if "D" in sections else (inherited["dacl"], inherited["control"] & 0x1500)
    sacl, sacl_control = _sddl_acl(sections["S"], True, aliases, generic_mapping) if "S" in sections else (inherited["sacl"], inherited["control"] & 0x2a00)
    if inherit and "D" in sections and not dacl_control & 0x1000:
        dacl = _merge_acl(inherited["dacl"], dacl)
    if inherit and "S" in sections and not sacl_control & 0x2000:
        sacl = _merge_acl(inherited["sacl"], sacl)
    control = (inherited["control"] & 0x00c0) | dacl_control | sacl_control
    if "D" in sections:
        control |= 0x0004
    elif inherited["control"] & 0x0004:
        control |= 0x0004
    if "S" in sections:
        control |= 0x0010
    elif inherited["control"] & 0x0010:
        control |= 0x0010
    # Keep the conventional owner/group/SACL/DACL order used by Win32's SDDL
    # conversion APIs. Self-relative descriptors permit any component order,
    # but stable output is useful for generated hives and registration tests.
    offset = 20
    owner_offset = offset if owner != None else 0
    offset += len(owner) if owner != None else 0
    group_offset = offset if group != None else 0
    offset += len(group) if group != None else 0
    sacl_offset = offset if sacl != None else 0
    offset += len(sacl) if sacl != None else 0
    dacl_offset = offset if dacl != None else 0
    output = binary.builder(capacity = offset + (len(dacl) if dacl != None else 0))
    output.u8(1)
    output.u8(0)
    output.u16le(control | 0x8000)
    output.u32le(owner_offset)
    output.u32le(group_offset)
    output.u32le(sacl_offset)
    output.u32le(dacl_offset)
    if owner != None:
        output.append(owner)
    if group != None:
        output.append(group)
    if sacl != None:
        output.append(sacl)
    if dacl != None:
        output.append(dacl)
    return output.bytes()
