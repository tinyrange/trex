"""Windows application-model identity semantics for unpackaged processes."""

_APPMODEL_ERROR_NO_PACKAGE = 15700
_APPMODEL_ERROR_NO_APPLICATION = 15703
_ERROR_NOT_FOUND = 1168

_SIGNATURES = {
    "apppolicygetprocessterminationmethod": 2,
    "closepackageinfo": 1,
    "getapplicationusermodelid": 3,
    "getcurrentapplicationusermodelid": 2,
    "getcurrentpackagefamilyname": 2,
    "getcurrentpackagefullname": 2,
    "getcurrentpackageid": 2,
    "getcurrentpackageinfo": 4,
    "getcurrentpackageinfo2": 5,
    "getpackageapplicationids": 4,
    "getpackagefamilyname": 3,
    "getpackagefullname": 3,
    "getpackagepathbyfullname": 3,
    "openpackageinfobyfullname": 3,
    "packagefamilynamefromfullname": 3,
    "packagefamilynamefromid": 3,
    "packagefullnamefromid": 3,
    "packageidfromfullname": 4,
    "packagenameandpublisheridfromfamilyname": 5,
}

def appmodel_plugin():
    """Reports the ordinary absence of package identity for desktop binaries."""
    state = {"queries": []}

    def zero_length(machine, address):
        if address:
            machine.write_u32le(address, 0)

    def callback(event):
        name = event.name.lower()
        args = event.args
        state["queries"].append({"api": name, "arguments": list(args)})
        if name == "apppolicygetprocessterminationmethod":
            if not args[1]:
                return 87  # ERROR_INVALID_PARAMETER
            event.machine.write_u32le(args[1], 0)  # AppPolicyProcessTerminationMethod_ExitProcess
            return 0
        if name == "closepackageinfo":
            return 0
        if name in [
            "getcurrentapplicationusermodelid",
            "getcurrentpackagefamilyname",
            "getcurrentpackagefullname",
            "getcurrentpackageid",
        ]:
            zero_length(event.machine, args[0])
            return _APPMODEL_ERROR_NO_PACKAGE
        if name == "getcurrentpackageinfo":
            zero_length(event.machine, args[1])
            zero_length(event.machine, args[3])
            return _APPMODEL_ERROR_NO_PACKAGE
        if name == "getcurrentpackageinfo2":
            zero_length(event.machine, args[2])
            zero_length(event.machine, args[4])
            return _APPMODEL_ERROR_NO_PACKAGE
        if name in ["getapplicationusermodelid", "getpackagefamilyname", "getpackagefullname"]:
            zero_length(event.machine, args[1])
            return _APPMODEL_ERROR_NO_APPLICATION
        if name == "getpackageapplicationids":
            zero_length(event.machine, args[1])
            zero_length(event.machine, args[3])
            return _ERROR_NOT_FOUND
        if name in ["getpackagepathbyfullname", "packagefamilynamefromfullname", "packagefamilynamefromid", "packagefullnamefromid"]:
            zero_length(event.machine, args[1])
            return _ERROR_NOT_FOUND
        if name == "packageidfromfullname":
            zero_length(event.machine, args[2])
            return _ERROR_NOT_FOUND
        if name == "packagenameandpublisheridfromfamilyname":
            zero_length(event.machine, args[1])
            zero_length(event.machine, args[3])
            return _ERROR_NOT_FOUND
        if name == "openpackageinfobyfullname":
            if args[2]:
                event.machine.write_u32le(args[2], 0)
            return _ERROR_NOT_FOUND
        return _ERROR_NOT_FOUND

    def install(machine):
        modules = [
            "api-ms-win-appmodel-runtime-l1-1-1.dll",
            "api-ms-win-appmodel-runtime-l1-1-2.dll",
            "kernel32.dll",
        ]
        for name, argc in _SIGNATURES.items():
            for module in modules:
                machine.provide_export(callback, module = module, name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if (imported.module.lower().startswith("api-ms-win-appmodel-runtime-") or imported.module.lower() == "kernel32.dll") and name in _SIGNATURES:
                machine.hook(callback, address = imported.address, argc = _SIGNATURES[name])

    return emulator.plugin(install, name = "windows.appmodel", state = state)
