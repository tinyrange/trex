"""Registration policy for PE REGINST resources."""

load(":common.star", "deduplicate", "expand", "module_replacements")

def reginst_resource_patches(text, module, replacements = {}):
    """Parses one textual REGINST resource into registry operations."""
    variables = module_replacements(module)
    for name, value in replacements.items():
        variables[name.upper()] = value
    output = []
    inf = windows.inf(expand(text, variables))
    for section_name, section in inf.json.items():
        lower = section_name.lower()
        if lower == "strings" or lower.startswith("uninstall") or type(section) != "dict":
            continue
        addreg = section.get("AddReg", [])
        if type(addreg) != "list":
            addreg = [addreg]
        for row in addreg:
            names = row if type(row) == "list" else [row]
            for name in names:
                for item in inf.section_patches(name):
                    item["value"] = expand(item["value"], variables)
                    output.append(item)
    return deduplicate(output)

def reginst_registration_patches(file, module, replacements = {}, pe = None):
    """Parses install-style AddReg sections embedded in REGINST resources."""
    output = []
    pe = pe or windows.pe(file)
    for resource in pe.resources:
        if resource["type"].upper() == "REGINST":
            output += reginst_resource_patches(resource["text"], module, replacements)
    return deduplicate(output)
