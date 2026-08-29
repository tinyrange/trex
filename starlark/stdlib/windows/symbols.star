"""Module tracking and PDB resolution policy for Windows debugger scripts."""

def _symbol_rva(symbol):
    return symbol["rva"]

def module_name(path):
    """Returns a lowercase basename for a Windows module path."""
    normalized = path.replace("/", "\\")
    return normalized.split("\\")[-1].lower()

def canonical_address(address):
    """Collapses a KD sign-extended 32-bit address without changing 64-bit addresses."""
    if address >> 32 == 0xffffffff:
        return address & 0xffffffff
    return address

def state(kernel_names = ["ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"]):
    """Creates mutable resolver state owned by one script/session."""
    return {
        "modules": {},
        "pdbs": {},
        "kernel_names": [name.lower() for name in kernel_names],
    }

def add_pdb(resolver, module, pdb):
    """Associates a parsed PDB with a module basename."""
    resolver["pdbs"][module_name(module)] = pdb

def add_pe(resolver, module, image, base = None):
    """Adds a loaded PE image and its exports to resolver state."""
    name = module_name(module)
    pe = windows.pe(image)
    info = pe.info
    resolver["modules"][name] = {
        "name": name,
        "path": module,
        "base": canonical_address(info["image_base"] if base == None else base),
        "size": info["image_size"],
    }
    symbols = []
    for exported in pe.exports:
        if "name" in exported and "forwarder" not in exported:
            symbols.append({
                "name": exported["name"],
                "rva": exported["rva"],
                "kind": "export",
            })
    symbols = sorted(symbols, key = _symbol_rva)
    resolver.setdefault("exports", {})[name] = symbols

def update(resolver, event):
    """Applies one KD load/unload event to resolver state."""
    if event.kind != "load_symbols":
        return False
    name = module_name(event.path)
    if event.unload:
        resolver["modules"].pop(name, None)
    else:
        resolver["modules"][name] = {
            "name": name,
            "path": event.path,
            "base": canonical_address(event.base),
            "size": event.size,
        }
    return True

def locate(resolver, address):
    """Returns module and nearest-symbol facts for a virtual address."""
    address = canonical_address(address)
    selected = None
    for module in resolver["modules"].values():
        if address >= module["base"] and address < module["base"] + module["size"]:
            selected = module
            break
    if selected == None:
        return None
    rva = address - selected["base"]
    result = {"module": selected, "rva": rva, "address": address}
    pdb = resolver["pdbs"].get(selected["name"])
    if pdb != None:
        nearest = pdb.nearest(rva)
        if nearest != None:
            result["nearest"] = nearest.symbol
            result["displacement"] = nearest.displacement
    else:
        exports = resolver.get("exports", {}).get(selected["name"], [])
        low = 0
        high = len(exports)
        while low < high:
            middle = (low + high) // 2
            if exports[middle]["rva"] <= rva:
                low = middle + 1
            else:
                high = middle
        if low:
            result["nearest"] = exports[low - 1]
            result["displacement"] = rva - exports[low - 1]["rva"]
    return result

def kernel_module(resolver):
    """Returns the first loaded preferred kernel module."""
    for name in resolver["kernel_names"]:
        module = resolver["modules"].get(name)
        if module != None:
            return module
    return None
