"""Static Active Scripting COM registration policy."""

load(":common.star", "module_parts", "patch")
load(":facts.star", "class_ids")

def _related(base, candidates, delta):
    first = int(base[1:9], 16) + delta
    suffix = base[9:]
    encoded = hex(first & 0xffffffff)[2:].upper()
    wanted = "{" + "0" * (8 - len(encoded)) + encoded + suffix
    for candidate in candidates:
        if candidate.upper() == wanted:
            return candidate
    return ""

def _progid_patches(name, class_id):
    key = "/Classes/" + name
    class_key = "/Classes/CLSID/" + class_id
    return [
        patch(key, "(default)", name + " Language"),
        patch(key + "/CLSID", "(default)", class_id),
        patch(key + "/OLEScript", "(default)", ""),
        patch(class_key + "/ProgID", "(default)", name),
        patch(class_key + "/OLEScript", "(default)", ""),
    ]

def script_engine_registry_patches(module, prog_id, classes, encoded_prog_id = ""):
    """Builds Active Scripting registry policy from already-derived facts."""
    if not prog_id or not classes:
        return []
    encoded_class = _related(classes[0], classes, 2)
    output = []
    for class_id in classes:
        key = "/Classes/CLSID/" + class_id
        output.extend([
            patch(key, "(default)", prog_id + " Language"),
            patch(key + "/InprocServer32", "(default)", module),
            patch(key + "/InprocServer32", "ThreadingModel", "Both"),
        ])
    output += _progid_patches(prog_id, classes[0])
    if encoded_prog_id and len(classes) > 1:
        output += _progid_patches(encoded_prog_id, encoded_class or classes[-1])
    return output

def script_engine_patches(file, module, pe = None):
    """Returns static COM registration for an Active Scripting engine PE."""
    strings = binary.strings(file, encoding = "utf16le", minimum = 4)
    if "ScriptEngine" not in strings:
        return []
    _, _, _, stem = module_parts(module)
    prog_id = ""
    encoded_prog_id = ""
    supports_encoding = False
    for value in strings:
        if value.lower() == stem.lower():
            prog_id = value
        elif value.lower() == (stem + ".Encode").lower():
            encoded_prog_id = value
        elif value == "Active Scripting Engine with Encoding":
            supports_encoding = True
    classes = class_ids(file, pe = pe)
    if not encoded_prog_id and supports_encoding and classes and _related(classes[0], classes, 2):
        encoded_prog_id = prog_id + ".Encode"
    return script_engine_registry_patches(module, prog_id, classes, encoded_prog_id)
