"""ReactOS registry, hardware and offline registration policy."""
load(":media.star", "base_name", "installed_files")
load("@stdlib//windows/emulation:runner.star", selfreg_run = "run")

BOCHS_VIDEO_GUID = "{664c1c81-786f-11f1-a7cc-806e6f6e6963}"
BOCHS_ENUM_KEY = "/ControlSet001/Enum/PCI/VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02/3&609b8881&02"
QEMU_NET_GUID = "{e87b1a76-143f-42ad-a68b-7a32829362e3}"

def reactos_base_patches(identity):
    """Returns explicit boot and machine-identity policy for generated hives."""
    patches = list(identity["patches"])
    for key, name, data_type, value in [
        ("/Select", "Current", "REG_DWORD", 1),
        ("/Select", "Default", "REG_DWORD", 1),
        ("/Select", "Failed", "REG_DWORD", 0),
        ("/Select", "LastKnownGood", "REG_DWORD", 1),
        ("/Setup", "CmdLine", "REG_SZ", ""),
        ("/Setup", "OsLoaderPath", "REG_SZ", "\\"),
        ("/Setup", "SetupType", "REG_DWORD", 0),
        ("/Setup", "SystemPartition", "REG_SZ", "\\Device\\Harddisk0\\Partition1"),
        ("/Setup", "SystemPrefix", "REG_BINARY", b""),
        ("/Setup", "SystemSetupInProgress", "REG_DWORD", 0),
        ("/ControlSet001/Control", "CurrentUser", "REG_SZ", "SYSTEM"),
        ("/ControlSet001/Control", "WaitToKillServiceTimeout", "REG_SZ", "20000"),
    ]:
        patches.append({"hive": "SYSTEM", "key": key, "name": name, "type": data_type, "value": value})
    return patches


def add_txtsetup_services(patches, txtsetup, section, group, available_drivers):
    """Appends boot-driver service policy from one TXTSETUP section."""
    for service, values in txtsetup[section].items():
        driver = values[0]
        if driver.lower() not in available_drivers:
            continue
        service_key = "/ControlSet001/Services/" + service
        patches.append({"key": service_key, "name": "ErrorControl", "type": "REG_DWORD", "value": 0})
        patches.append({"key": service_key, "name": "Group", "type": "REG_SZ", "value": group})
        patches.append({"key": service_key, "name": "ImagePath", "type": "REG_EXPAND_SZ", "value": "system32\\drivers\\" + driver})
        patches.append({"key": service_key, "name": "Start", "type": "REG_DWORD", "value": 0})
        patches.append({"key": service_key, "name": "Type", "type": "REG_DWORD", "value": 1})

def txtsetup_system_patches(iso, txtsetup, setup_root = "/reactos"):
    """Derives boot services and hardware matches from the setup media."""
    available_drivers = {}
    for src in iso[setup_root + "/system32/drivers"].files:
        available_drivers[base_name(src).lower()] = True
    patches = [
        {"key": "/Setup", "name": "CmdLine", "type": "REG_SZ", "value": ""},
        {"key": "/Setup", "name": "SetupType", "type": "REG_DWORD", "value": 0},
        {"key": "/Setup", "name": "SystemSetupInProgress", "type": "REG_DWORD", "value": 0},
    ]
    add_txtsetup_services(patches, txtsetup, "BusExtenders.Load", "System Bus Extender", available_drivers)
    add_txtsetup_services(patches, txtsetup, "SCSI.Load", "SCSI Miniport", available_drivers)
    for hwid, values in txtsetup["HardwareIdsDatabase"].items():
        key = "/ControlSet001/Control/CriticalDeviceDatabase/" + hwid.replace("\\", "#")
        patches.append({"key": key, "name": "Service", "type": "REG_SZ", "value": values[0]})
    return patches

def mirror_numbered_control_sets(patches, source = 1, targets = [2]):
    """Returns patches mirrored into inactive, physically stored control sets.

    CurrentControlSet is a runtime registry symbolic link and must never be
    materialized in a SYSTEM hive. The kernel creates it from the Select key
    after mounting the selected numbered control set.
    """
    def prefix(number):
        encoded = str(number)
        if number < 0 or number > 999:
            fail("control-set number must fit three decimal digits")
        return "/ControlSet" + "0" * (3 - len(encoded)) + encoded + "/"

    mirrored = list(patches)
    source_prefix = prefix(source)
    for patch in patches:
        key = patch["key"]
        if key.startswith(source_prefix):
            for target in targets:
                copy = {}
                for k, v in patch.items():
                    copy[k] = v
                copy["key"] = prefix(target) + key[len(source_prefix):]
                mirrored.append(copy)
    return mirrored

def font_file_registry_patches(cab):
    """Registers the installed font filenames and decoded font names."""
    patches = [{
        "key": "/Microsoft/Windows NT/CurrentVersion/Fonts",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "tahoma.ttf",
    }]
    for p in cab.files:
        name = base_name(p)
        lower = name.lower()
        if lower.endswith(".ttf") or lower.endswith(".ttc"):
            suffix = " (TrueType)"
        elif lower.endswith(".fon"):
            suffix = " (FON)"
        else:
            continue
        patches.append({
            "key": "/Microsoft/Windows NT/CurrentVersion/Fonts",
            "name": name + suffix,
            "type": "REG_SZ",
            "value": name,
        })
    return patches

def software_patches(identity):
    """Returns workstation shell, autologon and standard-profile defaults."""
    winlogon = "/Microsoft/Windows NT/CurrentVersion/Winlogon"
    administrator = "/Microsoft/Windows NT/CurrentVersion/ProfileList/" + identity["sid"] + "-500"
    return [
        {"key": winlogon, "name": "AutoAdminLogon", "type": "REG_SZ", "value": "1"},
        {"key": winlogon, "name": "DefaultDomainName", "type": "REG_SZ", "value": identity["computer_name"]},
        {"key": winlogon, "name": "DefaultPassword", "type": "REG_SZ", "value": ""},
        {"key": winlogon, "name": "DefaultUserName", "type": "REG_SZ", "value": "Administrator"},
        {"key": winlogon, "name": "LogonType", "type": "REG_DWORD", "value": 1},
        {"key": winlogon, "name": "Shell", "type": "REG_SZ", "value": "explorer.exe"},
        {"key": winlogon, "name": "Userinit", "type": "REG_EXPAND_SZ", "value": "%SystemRoot%\\system32\\userinit.exe"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList", "name": "AllUsersProfile", "type": "REG_SZ", "value": "All Users"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList", "name": "DefaultUserProfile", "type": "REG_SZ", "value": "Default User"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList", "name": "ProfilesDirectory", "type": "REG_EXPAND_SZ", "value": "%SystemDrive%\\Documents and Settings"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-18", "name": "ProfileImagePath", "type": "REG_EXPAND_SZ", "value": "%systemroot%\\system32\\config\\systemprofile"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-20", "name": "Flags", "type": "REG_DWORD", "value": 1},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-20", "name": "ProfileImagePath", "type": "REG_EXPAND_SZ", "value": "%SystemDrive%\\Documents and Settings\\NetworkService"},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-20", "name": "RefCount", "type": "REG_DWORD", "value": 0},
        {"key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/S-1-5-20", "name": "State", "type": "REG_DWORD", "value": 0},
        {"key": administrator, "name": "Flags", "type": "REG_DWORD", "value": 0},
        {"key": administrator, "name": "ProfileImagePath", "type": "REG_EXPAND_SZ", "value": "%SystemDrive%\\Documents and Settings\\Administrator"},
        {"key": administrator, "name": "RefCount", "type": "REG_DWORD", "value": 0},
        {"key": administrator, "name": "State", "type": "REG_DWORD", "value": 0},
    ]

def selfreg_software_patches(cab, syssetup):
    """Applies static registration resources selected by INF registration bits."""
    patches = []
    seen = {}
    regular = []
    for section in ["EarlyRegisterDlls", "OleControlDlls"]:
        for _, values in syssetup[section].items():
            subdir = values[1]
            dll = values[2]
            module_key = (subdir + "/" + dll).lower()
            if module_key in seen:
                continue
            seen[module_key] = True
            if subdir:
                module = "C:\\ReactOS\\System32\\" + subdir + "\\" + dll
            else:
                module = "C:\\ReactOS\\System32\\" + dll
            if int(values[3]) & 1:
                regular.append([cab["/" + dll], module])
    # INF registration flags are a bit mask: bit 1 registers, bit 2 installs.
    # Do not apply DllRegisterServer resources for install-only entries.
    for item in regular:
        for patch in windows.selfreg_patches(item[0], item[1]):
            patches.append(patch)
    return patches

def setup_shell_namespace_patches():
    """Returns the desktop namespace policy needed by the ReactOS shell."""
    my_computer = "/Classes/CLSID/{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
    ie = "/Classes/CLSID/{871C5380-42A0-1069-A2EA-08002B30309D}"
    return [
        {"key": my_computer + "/ShellFolder", "name": "HideOnDesktopPerUser", "type": "REG_BINARY", "value": b"\x00\x00"},
        {"key": ie, "name": "InfoTip", "type": "REG_EXPAND_SZ", "value": "@%SystemRoot%\\system32\\ieframe.dll,-881"},
        {"key": ie, "name": "LocalizedString", "type": "REG_EXPAND_SZ", "value": "@%SystemRoot%\\system32\\ieframe.dll,-880"},
        {"key": ie + "/DefaultIcon", "name": "(default)", "type": "REG_EXPAND_SZ", "value": "%SystemRoot%\\system32\\shell32.dll,-512"},
        {"key": ie + "/Shell", "name": "(default)", "type": "REG_SZ", "value": "open"},
        {"key": ie + "/Shell/open", "name": "(default)", "type": "REG_SZ", "value": ""},
        {"key": ie + "/Shell/open/Command", "name": "(default)", "type": "REG_SZ", "value": "rundll32.exe url,OpenURL https://google.com"},
        {"key": ie + "/ShellFolder", "name": "(default)", "type": "REG_SZ", "value": "@%SystemRoot%\\system32\\shell32.dll,-512"},
        {"key": ie + "/ShellFolder", "name": "Attributes", "type": "REG_DWORD", "value": 0x24},
        {"key": ie + "/ShellFolder", "name": "HideAsDeletePerUser", "type": "REG_SZ", "value": ""},
        {"key": ie + "/ShellFolder", "name": "HideFolderVerbs", "type": "REG_SZ", "value": ""},
        {"key": ie + "/ShellFolder", "name": "HideOnDesktopPerUser", "type": "REG_SZ", "value": ""},
        {"key": ie + "/ShellFolder", "name": "WantsParseDisplayName", "type": "REG_SZ", "value": ""},
        {"key": ie + "/Shellex", "name": "(default)", "type": "REG_SZ", "value": ""},
        {"key": ie + "/Shellex/ContextMenuHandlers", "name": "(default)", "type": "REG_SZ", "value": ""},
        {"key": ie + "/Shellex/MayChangeDefaultMenu", "name": "(default)", "type": "REG_SZ", "value": ""},
    ]

def software_build_patches(cab, syssetup, identity):
    """Combines static registration, font and workstation SOFTWARE policy."""
    patches = selfreg_software_patches(cab, syssetup)
    for patch in setup_shell_namespace_patches():
        patches.append(patch)
    for patch in font_file_registry_patches(cab):
        patches.append(patch)
    for patch in software_patches(identity):
        patches.append(patch)
    for patch in patches:
        patch["hive"] = "SOFTWARE"
    return patches

def shell_registration_actions(syssetup):
    """Selects the shell registrations needed in addition to static resources."""
    shell_registration = {
        "actxprxy.dll": True,
        "atl.dll": True,
        "browseui.dll": True,
        "comcat.dll": True,
        "comctl32.dll": True,
        "fontext.dll": True,
        "ntobjshex.dll": True,
        "ole32.dll": True,
        "rpcrt4.dll": True,
        "shell32.dll": True,
        "stobject.dll": True,
        "urlmon.dll": True,
        "zipfldr.dll": True,
    }
    actions = []
    for section in ["EarlyRegisterDlls", "OleControlDlls"]:
        for _, values in syssetup[section].items():
            if values[2].lower() not in shell_registration:
                continue
            flags = int(values[3])
            module = "C:\\ReactOS\\system32\\" + (values[1] + "\\" if values[1] else "") + values[2]
            for bit, export in [(1, "DllRegisterServer"), (2, "DllInstall")]:
                if flags & bit:
                    actions.append({"dll": values[2], "module": module, "export": export, "argument": values[5] if len(values) > 5 else ""})
    return actions

def register_shell(cab, syssetup, reactos_inf, hives, root):
    """Executes media exports in-process and applies their effects before boot."""
    files = {"C:" + name.replace("/", "\\"): source for name, source in installed_files(cab, reactos_inf).items()}
    for action in shell_registration_actions(syssetup):
        values = []
        keys = []
        for hive, source in hives.items():
            values.extend([dict(p, hive = hive) for p in windows.hive_patches(source)])
            keys.extend([dict(k, hive = hive) for k in windows.hive_keys(source, metadata = True)])
        def prepare(machine):
            return [1, machine.allocate(value = binary.encode(action["argument"], encoding = "utf16le", nul = True))]
        execution = selfreg_run(
            cab["/" + action["dll"]], action["module"], export = action["export"],
            prepare = prepare if action["export"] == "DllInstall" else None,
            initialize = True, files = files, registry_values = values, registry_keys = keys,
            environment = {"SystemRoot": "C:\\ReactOS", "windir": "C:\\ReactOS", "SystemDrive": "C:"},
            version = {"major": 5, "minor": 2, "build": 3790}, instruction_limit = 1000000,
        )
        result = execution["result"]
        if result.reason != "return" or result.value & 0x80000000:
            failures = [(i["module"], i["result"].reason, i["result"].detail) for i in execution["module_initializations"] if i["result"].reason != "return" or i["result"].value == 0]
            fail("ReactOS {}!{} stopped: {} {} HRESULT={} dependencies={} loads={}".format(action["dll"], action["export"], result.reason, result.detail, hex(result.value), failures, execution["module_queries"][-4:]))
        for hive, source in hives.items():
            patches = [p for p in execution["patches"] if p["hive"] == hive]
            new_keys = [k for k in execution["registry_keys"] if k["hive"] == hive]
            if patches or new_keys:
                patched = windows.patch_hive(source, patches)
                hives[hive] = windows.hive_from_patches(hive, windows.hive_patches(patched), keys = windows.hive_keys(patched, metadata = True) + new_keys, format = source)
        for name, data in execution["generated_files"].items():
            if name[:3].lower() != "c:\\":
                fail("registration wrote outside the image volume: " + name)
            root.write("/" + name[3:].replace("\\", "/"), data)
            files[name] = data

def video_system_patches():
    """Describes the tested QEMU Bochs graphics device and driver."""
    video_key = "/ControlSet001/Control/Video/" + BOCHS_VIDEO_GUID + "/0000"
    display_class = "/ControlSet001/Control/Class/{4D36E968-E325-11CE-BFC1-08002BE10318}/0000"
    display_settings = display_class + "/Settings"
    return [
        {"key": BOCHS_ENUM_KEY, "name": "Capabilities", "type": "REG_DWORD", "value": 0},
        {"key": BOCHS_ENUM_KEY, "name": "Class", "type": "REG_SZ", "value": "Display"},
        {"key": BOCHS_ENUM_KEY, "name": "ClassGUID", "type": "REG_SZ", "value": "{4d36e968-e325-11ce-bfc1-08002be10318}"},
        {"key": BOCHS_ENUM_KEY, "name": "CompatibleIDs", "type": "REG_MULTI_SZ", "value": [
            "PCI\\VEN_1234&DEV_1111&REV_02",
            "PCI\\VEN_1234&DEV_1111",
            "PCI\\VEN_1234&CC_030000",
            "PCI\\VEN_1234&CC_0300",
            "PCI\\VEN_1234",
            "PCI\\CC_030000",
            "PCI\\CC_0300",
        ]},
        {"key": BOCHS_ENUM_KEY, "name": "ConfigFlags", "type": "REG_DWORD", "value": 0},
        {"key": BOCHS_ENUM_KEY, "name": "DeviceDesc", "type": "REG_SZ", "value": "Bochs Graphics Adapter"},
        {"key": BOCHS_ENUM_KEY, "name": "Driver", "type": "REG_SZ", "value": "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"},
        {"key": BOCHS_ENUM_KEY, "name": "HardwareID", "type": "REG_MULTI_SZ", "value": [
            "PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02",
            "PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4",
            "PCI\\VEN_1234&DEV_1111&CC_030000",
            "PCI\\VEN_1234&DEV_1111&CC_0300",
        ]},
        {"key": BOCHS_ENUM_KEY, "name": "LocationInformation", "type": "REG_SZ", "value": "PCI-Bus 0, Device 2, Function 0"},
        {"key": BOCHS_ENUM_KEY, "name": "Mfg", "type": "REG_SZ", "value": "Bochs"},
        {"key": BOCHS_ENUM_KEY, "name": "ParentIdPrefix", "type": "REG_SZ", "value": "4&c6161cbc"},
        {"key": BOCHS_ENUM_KEY, "name": "Service", "type": "REG_SZ", "value": "bochsmp"},
        {"key": BOCHS_ENUM_KEY + "/Device Parameters", "name": "VideoId", "type": "REG_SZ", "value": BOCHS_VIDEO_GUID},
        {"key": display_class, "name": "DriverDesc", "type": "REG_SZ", "value": "Bochs Graphics Adapter"},
        {"key": display_class, "name": "DriverDate", "type": "REG_SZ", "value": "10-17-2022"},
        {"key": display_class, "name": "InfPath", "type": "REG_SZ", "value": "bochsmp.inf"},
        {"key": display_class, "name": "InfSection", "type": "REG_SZ", "value": "Bochs"},
        {"key": display_class, "name": "InfSectionExt", "type": "REG_SZ", "value": ""},
        {"key": display_class, "name": "MatchingDeviceId", "type": "REG_SZ", "value": "PCI\\VEN_1234&DEV_1111"},
        {"key": display_class, "name": "ProviderName", "type": "REG_SZ", "value": "ReactOS Project"},
        {"key": display_settings, "name": "InstalledDisplayDrivers", "type": "REG_MULTI_SZ", "value": ["framebuf"]},
        {"key": display_settings, "name": "VgaCompatible", "type": "REG_DWORD", "value": 0},
        {"key": video_key, "name": "DefaultSettings.XResolution", "type": "REG_DWORD", "value": 800},
        {"key": video_key, "name": "DefaultSettings.YResolution", "type": "REG_DWORD", "value": 600},
        {"key": video_key, "name": "Device Description", "type": "REG_SZ", "value": "Bochs Graphics Adapter"},
        {"key": video_key, "name": "InstalledDisplayDrivers", "type": "REG_MULTI_SZ", "value": ["framebuf"]},
        {"key": video_key, "name": "VgaCompatible", "type": "REG_DWORD", "value": 0},
        {"key": "/ControlSet001/Services/bochsmp", "name": "Tag", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/bochsmp/Device1", "name": "Device Description", "type": "REG_SZ", "value": "Bochs Graphics Adapter"},
        {"key": "/ControlSet001/Services/bochsmp/Device1", "name": "InstalledDisplayDrivers", "type": "REG_MULTI_SZ", "value": ["framebuf"]},
        {"key": "/ControlSet001/Services/bochsmp/Device1", "name": "VgaCompatible", "type": "REG_DWORD", "value": 0},
    ]

def network_system_patches():
    """Returns the tested QEMU adapter and TCP/IP registry policy."""
    return [
        {"key": "/ControlSet001/Services/Tcpip", "name": "ErrorControl", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/Tcpip", "name": "Group", "type": "REG_SZ", "value": "PNP_TDI"},
        {"key": "/ControlSet001/Services/Tcpip", "name": "ImagePath", "type": "REG_EXPAND_SZ", "value": "System32\\drivers\\tcpip.sys"},
        {"key": "/ControlSet001/Services/Tcpip", "name": "Start", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/Tcpip", "name": "Tag", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/Tcpip", "name": "Type", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/Tcpip/Linkage", "name": "Bind", "type": "REG_MULTI_SZ", "value": ["\\Device\\" + QEMU_NET_GUID]},
        {"key": "/ControlSet001/Services/Tcpip/Linkage", "name": "Export", "type": "REG_MULTI_SZ", "value": ["\\Device\\Tcpip_" + QEMU_NET_GUID]},
        {"key": "/ControlSet001/Services/Tcpip/Linkage", "name": "Route", "type": "REG_MULTI_SZ", "value": [QEMU_NET_GUID]},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "DataBasePath", "type": "REG_EXPAND_SZ", "value": "%SystemRoot%\\System32\\drivers\\etc"},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "Domain", "type": "REG_SZ", "value": ""},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "EnableSecurityFilters", "type": "REG_DWORD", "value": 0},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "ForwardBroadcasts", "type": "REG_DWORD", "value": 0},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "Hostname", "type": "REG_SZ", "value": "REACTOS"},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "IPEnableRouter", "type": "REG_DWORD", "value": 0},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "NV Domain", "type": "REG_SZ", "value": ""},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "NV Hostname", "type": "REG_SZ", "value": "REACTOS"},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "NameServer", "type": "REG_SZ", "value": ""},
        {"key": "/ControlSet001/Services/Tcpip/Parameters", "name": "SearchList", "type": "REG_SZ", "value": ""},
        {"key": "/ControlSet001/Services/Tcpip/Parameters/Interfaces/" + QEMU_NET_GUID, "name": "EnableDHCP", "type": "REG_DWORD", "value": 1},
        {"key": "/ControlSet001/Services/Tcpip/Parameters/PersistentRoutes", "name": "(default)", "type": "REG_SZ", "value": ""},
        {"key": "/ControlSet001/Services/Winsock2/Parameters", "name": "AutodialDLL", "type": "REG_SZ", "value": "rasadhlp.dll"},
    ]
