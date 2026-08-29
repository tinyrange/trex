"""Performance counter registration backed by generated in-memory files."""

def _command_argument(value):
    separator = value.find(" ")
    return value[separator + 1:].strip() if separator >= 0 else value.strip()

def _path(value):
    return value.replace("/", "\\").rstrip("\\").lower()

def _symbols(data):
    output = {}
    text = binary.text(data, encoding = "ascii")
    for line in text.splitlines():
        fields = line.strip().split()
        if len(fields) == 3 and fields[0] == "#define":
            output[fields[1]] = int(fields[2], base = 0)
    return output

def _replace_pairs(values, replacements, first = -1, last = -1):
    output = []
    for index in range(0, len(values) - 1, 2):
        identifier = int(values[index])
        if first >= 0 and identifier >= first and identifier <= last:
            continue
        output += [values[index], values[index + 1]]
    for identifier, text in sorted(replacements.items()):
        output += [str(identifier), text]
    return output

def loadperf_plugin(registry, kernel):
    """Models LoadPerf registration without a host filesystem or process."""
    state = {"actions": []}
    perflib_key = "/Microsoft/Windows NT/CurrentVersion/Perflib"

    def unload(driver):
        service_key = "/ControlSet001/Services/{}/Performance".format(driver)
        first_counter = registry.get_value("SYSTEM", service_key, "First Counter", -1)
        last_counter = registry.get_value("SYSTEM", service_key, "Last Counter", -1)
        first_help = registry.get_value("SYSTEM", service_key, "First Help", -1)
        last_help = registry.get_value("SYSTEM", service_key, "Last Help", -1)
        if first_counter >= 0:
            language_key = perflib_key + "/009"
            counters = registry.get_value("SOFTWARE", language_key, "Counter", [])
            help_text = registry.get_value("SOFTWARE", language_key, "Help", [])
            registry.set_value("SOFTWARE", language_key, "Counter", "REG_MULTI_SZ", _replace_pairs(counters, {}, first_counter, last_counter))
            registry.set_value("SOFTWARE", language_key, "Help", "REG_MULTI_SZ", _replace_pairs(help_text, {}, first_help, last_help))
            for name in ["First Counter", "Last Counter", "First Help", "Last Help"]:
                registry.delete_value("SYSTEM", service_key, name)
        state["actions"].append({"operation": "unload", "driver": driver, "found": first_counter >= 0})
        return 0

    def register(command):
        filename = _path(_command_argument(command))
        entry = kernel.state["paths"].get(filename)
        if entry == None or entry.get("directory", False):
            state["actions"].append({"operation": "load", "path": filename, "error": 2})
            return 2
        inf = windows.inf(kernel.state["file_data"](filename))
        if "info" not in inf or "drivername" not in inf["info"] or "symbolfile" not in inf["info"]:
            state["actions"].append({"operation": "load", "path": filename, "error": 13})
            return 13
        driver = inf["info"]["drivername"][0]
        symbol_name = inf["info"]["symbolfile"][0]
        parent = filename[:filename.rfind("\\") + 1]
        symbol_entry = kernel.state["paths"].get(_path(parent + symbol_name))
        if symbol_entry == None:
            state["actions"].append({"operation": "load", "path": filename, "error": 2, "missing": symbol_name})
            return 2
        symbols = _symbols(kernel.state["file_data"](_path(parent + symbol_name)))
        if not symbols:
            state["actions"].append({"operation": "load", "path": filename, "error": 13, "missing": symbol_name})
            return 13

        last_counter = registry.get_value("SOFTWARE", perflib_key, "Last Counter", 0)
        last_help = registry.get_value("SOFTWARE", perflib_key, "Last Help", 1)
        first_counter = last_counter + 2
        first_help = last_help + 2
        maximum_offset = max(symbols.values())
        registry.set_value("SOFTWARE", perflib_key, "Last Counter", "REG_DWORD", first_counter + maximum_offset)
        registry.set_value("SOFTWARE", perflib_key, "Last Help", "REG_DWORD", first_help + maximum_offset)

        languages = inf["languages"] if "languages" in inf else {"009": ["English (United States)"]}
        text = inf["text"] if "text" in inf else {}
        for language in languages:
            counter_updates = {}
            help_updates = {}
            for name, values in text.items():
                name_suffix = "_{}_NAME".format(language)
                help_suffix = "_{}_HELP".format(language)
                if name.endswith(name_suffix):
                    symbol = name[:-len(name_suffix)]
                    if symbol in symbols:
                        counter_updates[first_counter + symbols[symbol]] = values[0]
                elif name.endswith(help_suffix):
                    symbol = name[:-len(help_suffix)]
                    if symbol in symbols:
                        help_updates[first_help + symbols[symbol]] = values[0]
            language_key = perflib_key + "/" + language
            counters = registry.get_value("SOFTWARE", language_key, "Counter", [])
            help_text = registry.get_value("SOFTWARE", language_key, "Help", [])
            registry.set_value("SOFTWARE", language_key, "Counter", "REG_MULTI_SZ", _replace_pairs(counters, counter_updates))
            registry.set_value("SOFTWARE", language_key, "Help", "REG_MULTI_SZ", _replace_pairs(help_text, help_updates))

        service_key = "/ControlSet001/Services/{}/Performance".format(driver)
        registry.set_value("SYSTEM", service_key, "First Counter", "REG_DWORD", first_counter)
        registry.set_value("SYSTEM", service_key, "Last Counter", "REG_DWORD", first_counter + maximum_offset)
        registry.set_value("SYSTEM", service_key, "First Help", "REG_DWORD", first_help)
        registry.set_value("SYSTEM", service_key, "Last Help", "REG_DWORD", first_help + maximum_offset)
        state["actions"].append({"operation": "load", "path": filename, "driver": driver, "symbols": len(symbols), "error": 0})
        return 0

    def callback(event):
        command = event.machine.read_cstring(event.args[0], encoding = "utf16le" if event.name.lower().endswith("w") else "ascii")
        if event.name.lower().startswith("unload"):
            return unload(_command_argument(command))
        return register(command)

    def install(machine):
        signatures = {
            "loadperfcountertextstringsa": 2,
            "loadperfcountertextstringsw": 2,
            "unloadperfcountertextstringsa": 1,
            "unloadperfcountertextstringsw": 1,
        }
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "loadperf.dll" and name in signatures:
                machine.hook(callback, address = imported.address, argc = signatures[name])
    return emulator.plugin(install, name = "windows.loadperf", state = state)
