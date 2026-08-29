"""Shared registry-patch and Windows path helpers for self-registration."""

def patch(key, name, value, data_type = "REG_SZ", hive = "SOFTWARE", if_absent = False):
    """Builds one registry patch in the format accepted by windows.hive()."""
    result = {"hive": hive, "key": key, "name": name, "type": data_type, "value": value}
    if if_absent:
        result["if_absent"] = True
    return result

def module_parts(module):
    """Returns the normalized module path, directory, basename, and stem."""
    normalized = module.replace("/", "\\")
    parts = normalized.split("\\")
    basename = parts[-1]
    directory = "\\".join(parts[:-1])
    stem = basename.rsplit(".", 1)[0] if "." in basename else basename
    return normalized, directory, basename, stem

def module_replacements(module):
    """Returns conventional registration-resource substitutions for a module."""
    normalized, directory, _, stem = module_parts(module)
    values = {
        "MOD_PATH": normalized,
        "MOD_DIR": directory,
        "MODULE": normalized,
        "THISDLL": normalized,
        "_MOD_PATH": normalized,
        "_MOD_DIR": directory,
        "_SYS_MOD_PATH": normalized,
        "_SYS_MOD_DIR": directory,
        "SYS_MOD_PATH": normalized,
        "SYS_MOD_DIR": directory,
    }
    if stem:
        values[stem.upper()] = normalized
    return values

def expand(value, replacements):
    """Expands percent-delimited registration variables to a fixed point."""
    if type(value) != "string":
        return value
    output = value
    for _ in range(4):
        previous = output
        for name, replacement in replacements.items():
            output = output.replace("%" + name.upper() + "%", replacement)
            output = output.replace("%" + name.lower() + "%", replacement)
        if output == previous:
            break
    return output

def expand_environment(value, environment):
    """Expands case-insensitive percent-delimited process environment names."""
    if type(value) != "string":
        return value
    normalized = {name.lower(): str(replacement) for name, replacement in environment.items()}
    output = ""
    offset = 0
    while offset < len(value):
        start = value.find("%", offset)
        if start < 0:
            output += value[offset:]
            break
        end = value.find("%", start + 1)
        if end < 0:
            output += value[offset:]
            break
        output += value[offset:start]
        replacement = normalized.get(value[start + 1:end].lower())
        output += value[start:end + 1] if replacement == None else replacement
        offset = end + 1
    return output

def deduplicate(patches):
    """Removes byte-for-byte equivalent registry operations while preserving order."""
    output = []
    seen = {}
    for item in patches:
        identity = "%s\x00%s\x00%s\x00%s\x00%s" % (
            item.get("hive", "SOFTWARE").upper(),
            item["key"].upper(),
            item["name"].upper(),
            item["type"],
            repr(item["value"]),
        )
        if identity not in seen:
            seen[identity] = True
            output.append(item)
    return output

def coalesce(patches):
    """Keeps only the final registry operation for each hive, key, and value."""
    final = {}
    for index, item in enumerate(patches):
        identity = "%s\x00%s\x00%s" % (
            item.get("hive", "SOFTWARE").upper(),
            item["key"].upper(),
            item["name"].upper(),
        )
        final[identity] = index
    output = []
    for index, item in enumerate(patches):
        identity = "%s\x00%s\x00%s" % (
            item.get("hive", "SOFTWARE").upper(),
            item["key"].upper(),
            item["name"].upper(),
        )
        if final[identity] == index:
            output.append(item)
    return output
