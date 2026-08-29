"""Semantic Component Categories Manager used by setup-time registrars."""

load(":facts.star", "guid")

_CLASS = "{0002E005-0000-0000-C000-000000000046}"
_IUNKNOWN = "{00000000-0000-0000-C000-000000000046}"
_ICAT_REGISTER = "{0002E012-0000-0000-C000-000000000046}"

def _guid(machine, address):
    return guid(machine.read(address, 16)) if address else ""

def component_categories_provider(registry):
    """Returns a native ICatRegister provider backed by the live registry."""
    state = {"actions": [], "next_object": 1}

    def activate(event, activation, output):
        machine = event.machine
        requested = activation["interface"]
        if not output:
            return 0x80004003  # E_POINTER
        machine.write_u32le(output, 0)
        if requested not in [_IUNKNOWN, _ICAT_REGISTER]:
            return 0x80004002  # E_NOINTERFACE
        identifier = state["next_object"]
        state["next_object"] += 1
        references = [1]

        def query_interface(current):
            if not current.args[2]:
                return 0x80004003
            current.machine.write_u32le(current.args[2], 0)
            if _guid(current.machine, current.args[1]) not in [_IUNKNOWN, _ICAT_REGISTER]:
                return 0x80004002
            current.machine.write_u32le(current.args[2], current.args[0])
            references[0] += 1
            return 0

        def add_ref(current):
            references[0] += 1
            return references[0]

        def release(current):
            references[0] = max(0, references[0] - 1)
            return references[0]

        def register_categories(current):
            count, information = current.args[1], current.args[2]
            if count and not information:
                return 0x80070057
            for index in range(count):
                entry = information + index * 276
                category = _guid(current.machine, entry)
                locale = current.machine.read_u32le(entry + 16)
                description = current.machine.read_cstring(entry + 20, encoding = "utf16le")
                key = "/Classes/Component Categories/" + category
                registry.set_value("SOFTWARE", key, hex(locale)[2:], "REG_SZ", description)
                state["actions"].append({"kind": "register_category", "category": category, "locale": locale, "description": description})
            return 0

        def unregister_categories(current):
            count, categories = current.args[1], current.args[2]
            if count and not categories:
                return 0x80070057
            for index in range(count):
                category = _guid(current.machine, categories + index * 16)
                registry.delete_tree("SOFTWARE", "/Classes/Component Categories/" + category)
                state["actions"].append({"kind": "unregister_category", "category": category})
            return 0

        def class_categories(current, operation, branch, delete):
            class_id, count, categories = current.args[1], current.args[2], current.args[3]
            if not class_id or (count and not categories):
                return 0x80070057
            class_name = _guid(current.machine, class_id)
            for index in range(count):
                category = _guid(current.machine, categories + index * 16)
                key = "/Classes/CLSID/{}/{}/{}".format(class_name, branch, category)
                if delete:
                    registry.delete_tree("SOFTWARE", key)
                else:
                    # Empty category keys are represented by their harmless
                    # default value so the installed CREG hive preserves them.
                    registry.set_value("SOFTWARE", key, "(default)", "REG_SZ", "")
                state["actions"].append({"kind": operation, "class": class_name, "category": category})
            return 0

        def register_impl(current):
            return class_categories(current, "register_implemented", "Implemented Categories", False)
        def unregister_impl(current):
            return class_categories(current, "unregister_implemented", "Implemented Categories", True)
        def register_required(current):
            return class_categories(current, "register_required", "Required Categories", False)
        def unregister_required(current):
            return class_categories(current, "unregister_required", "Required Categories", True)

        methods = [
            ("QueryInterface", query_interface, 3),
            ("AddRef", add_ref, 1),
            ("Release", release, 1),
            ("RegisterCategories", register_categories, 3),
            ("UnRegisterCategories", unregister_categories, 3),
            ("RegisterClassImplCategories", register_impl, 4),
            ("UnRegisterClassImplCategories", unregister_impl, 4),
            ("RegisterClassReqCategories", register_required, 4),
            ("UnRegisterClassReqCategories", unregister_required, 4),
        ]
        table = binary.builder(capacity = len(methods) * 4)
        for name, callback, argc in methods:
            table.u32le(machine.provide_export(callback, module = "trex.comcat", name = name + str(identifier), argc = argc))
        vtable = machine.allocate(value = table.bytes(), name = "ICatRegister.vtable")
        value = binary.builder(capacity = 4)
        value.u32le(vtable)
        interface = machine.allocate(value = value.bytes(), name = "ICatRegister")
        machine.write_u32le(output, interface)
        return 0

    return {"classes": [_CLASS], "activate": activate, "state": state}
