"""Declarative registration for Windows Script Component (WSC) files."""

load(":common.star", "patch")

def _elements(node, name):
    lowered = name.lower()
    return [child for child in node.children if child.name.lower() == lowered]

def _attribute(node, name):
    value = node.attribute(name)
    return value.strip() if value != None else ""

def script_component_registration_patches(file, module, server):
    """Returns COM registration declared by every component in a WSC package.

    The output mirrors the script-component registrar while keeping the XML
    payload and registry construction in memory. `module` and `server` are
    absolute guest paths to the WSC file and script component runtime.
    """
    root = binary.xml(file).root
    components = [root] if root.name.lower() == "component" else _elements(root, "component")
    output = []
    for component in components:
        registrations = _elements(component, "registration")
        for registration in registrations:
            class_id = _attribute(registration, "classid")
            prog_id = _attribute(registration, "progid")
            version = _attribute(registration, "version")
            description = _attribute(registration, "description") or prog_id
            if not class_id or not prog_id:
                continue
            versioned_prog_id = prog_id + "." + version if version else prog_id
            class_key = "/Classes/CLSID/" + class_id
            output += [
                patch(class_key, "(default)", description),
                patch(class_key + "/InprocServer32", "(default)", server),
                patch(class_key + "/InprocServer32", "ThreadingModel", "Apartment"),
                patch(class_key + "/ProgID", "(default)", versioned_prog_id),
                patch(class_key + "/ScriptletURL", "(default)", "file://" + module.replace("/", "\\")),
            ]
            if version:
                output.append(patch(class_key + "/VersionIndependentProgID", "(default)", prog_id))
            output += [
                patch("/Classes/" + prog_id, "(default)", description),
                patch("/Classes/" + prog_id + "/CLSID", "(default)", class_id),
            ]
            if version:
                output += [
                    patch("/Classes/" + versioned_prog_id, "(default)", description),
                    patch("/Classes/" + versioned_prog_id + "/CLSID", "(default)", class_id),
                ]
    return output
