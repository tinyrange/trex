"""Registry policy for MSFT type libraries exposed by windows.pe()."""

load(":common.star", "module_parts", "patch")
load(":facts.star", "export_rva")

_KIND_INTERFACE = 3
_KIND_DISPATCH = 4
_KIND_COCLASS = 5
_FLAG_CAN_CREATE = 0x02
_FLAG_CONTROL = 0x20
_FLAG_DUAL = 0x40
_DISPATCH_PROXY = "{00020420-0000-0000-C000-000000000046}"
_AUTOMATION_PROXY = "{00020424-0000-0000-C000-000000000046}"

def _selected_libraries(pe, referenced):
    selected = dict(referenced or {})
    interfaces = dict(referenced or {})
    if not export_rva(pe, "DllGetClassObject") or not export_rva(pe, "DllRegisterServer"):
        return selected, interfaces
    for library in pe.typelibs:
        for info in library["types"]:
            if info["kind"] == _KIND_COCLASS and info["flags"] & _FLAG_CAN_CREATE:
                selected[library["guid"].upper()] = True
                if info["flags"] & _FLAG_CONTROL:
                    interfaces[library["guid"].upper()] = True
                break
    return selected, interfaces

def typelib_patches(libraries, module, selected, interface_libraries):
    """Builds registry operations from parsed type-library facts."""
    _, directory, _, _ = module_parts(module)
    output = []
    for library in libraries:
        library_id = library["guid"].upper()
        if library_id not in selected:
            continue
        version = "%d.%d" % (library["major"], library["minor"])
        key = "/Classes/TypeLib/%s/%s" % (library["guid"], version)
        output.extend([
            patch(key, "(default)", library.get("description", library["name"]), if_absent = True),
            patch(key + "/Flags", "(default)", hex(library["flags"])[2:], if_absent = True),
            patch(key + "/HELPDIR", "(default)", directory, if_absent = True),
            patch(key + "/%s/win32" % hex(library["lcid"])[2:], "(default)", module, if_absent = True),
        ])
        for info in library["types"]:
            if not info["guid"] or not info["name"]:
                continue
            if info["kind"] == _KIND_COCLASS:
                class_key = "/Classes/CLSID/" + info["guid"]
                output.extend([
                    patch(class_key, "(default)", info["name"], if_absent = True),
                    patch(class_key + "/InprocServer32", "(default)", module, if_absent = True),
                    patch(class_key + "/InprocServer32", "ThreadingModel", "Apartment", if_absent = True),
                    patch(class_key + "/TypeLib", "(default)", library["guid"], if_absent = True),
                    patch(class_key + "/Version", "(default)", version, if_absent = True),
                ])
                if info["flags"] & _FLAG_CONTROL:
                    output.append(patch(class_key + "/Control", "(default)", "", if_absent = True))
            elif info["kind"] in [_KIND_INTERFACE, _KIND_DISPATCH] and library_id in interface_libraries:
                interface_key = "/Classes/Interface/" + info["guid"]
                output.append(patch(interface_key, "(default)", info["name"], if_absent = True))
                if info["kind"] == _KIND_DISPATCH:
                    proxy = _AUTOMATION_PROXY if info["flags"] & _FLAG_DUAL else _DISPATCH_PROXY
                    output.append(patch(interface_key + "/ProxyStubClsid", "(default)", proxy, if_absent = True))
                    output.append(patch(interface_key + "/ProxyStubClsid32", "(default)", proxy, if_absent = True))
                output.append(patch(interface_key + "/TypeLib", "(default)", library["guid"], if_absent = True))
                output.append(patch(interface_key + "/TypeLib", "Version", version, if_absent = True))
    return output

def typelib_registration_patches(file, module, referenced = None, pe = None):
    """Registers referenced or self-registering embedded MSFT type libraries."""
    pe = pe or windows.pe(file)
    selected, interface_libraries = _selected_libraries(pe, referenced)
    return typelib_patches(pe.typelibs, module, selected, interface_libraries)
