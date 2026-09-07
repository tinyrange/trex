"""Constructs a complete ReactOS image in memory from original media."""
load("@stdlib//windows:identity.star", "machine_identity")
load(":security.star", "security_database", "workstation_security")
load(":media.star", "copy_cab_from_inf", "copy_iso_files", "reactos_media")
load(":registry.star", "reactos_base_patches", "txtsetup_system_patches", "mirror_numbered_control_sets", "software_build_patches", "register_shell", "video_system_patches", "network_system_patches")
load(":profiles.star", "add_profile_skeleton")
load(":shortcuts.star", "add_shortcuts_from_inf")

SYSTEM_ROOT = "/ReactOS"
PARTITION_LBA = 2048
FREELDR_INI = """[FREELOADER]
DefaultOS=ReactOS
TimeOut=0
Debug=/DEBUG /DEBUGPORT=COM1 /DEBUGPORT=BOCHS /BAUDRATE=115200

[Display]
TitleText=ReactOS
MinimalUI=Yes

[Operating Systems]
ReactOS="ReactOS"

[ReactOS]
BootType=Windows2003
SystemPath=multi(0)disk(0)rdisk(0)partition(1)\\ReactOS
Options=/HAL=halacpi.dll /DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200 /FASTDETECT /NOGUIBOOT /SOS
"""

def reactos_disk(source, security = None, computer_name = "TINYRANGE-ROS", workgroup = "WORKGROUP", autologon = "Administrator"):
    """Builds a lazy installed ReactOS disk from its ISO, ZIP or 7z media."""
    iso, setup_root = reactos_media(source)
    reactos_inf = windows.inf(iso[setup_root + "/reactos.inf"])
    registry_inf = windows.inf(iso[setup_root + "/registry.inf"])
    txtsetup = windows.inf(iso[setup_root + "/txtsetup.sif"])
    cab = archive.cab(iso[setup_root + "/reactos.cab"])
    font_inf = windows.inf(cab["/font.inf"])
    nettcpip_inf = windows.inf(cab["/nettcpip.inf"])
    syssetup_inf = windows.inf(cab["/syssetup.inf"])
    shortcuts_inf = windows.inf(cab["/shortcuts.inf"])
    rosapps_shortcuts_inf = windows.inf(cab["/rosapps_shortcuts.inf"]) if "/rosapps_shortcuts.inf" in cab.files else None
    setupreg_name = setup_root + "/setupreg.hiv"
    if setupreg_name not in iso:
        setupreg_name = setup_root + "/SETUPREG.HIV"
    setupreg_hive = iso[setupreg_name]
    identity = machine_identity(computer_name, workgroup=workgroup)
    specification = security if security != None else workstation_security(identity["sid"], identity["computer_name"], workgroup)
    if specification["domain_sid"] != identity["sid"] or specification["domain_name"] != identity["computer_name"]:
        fail("security domain must match generated machine identity")
    if specification.get("workgroup", "WORKGROUP") != identity["workgroup"]:
        fail("security workgroup must match generated machine identity")
    security = security_database(specification, hive_format = setupreg_hive)
    selected = [user for user in specification["users"] if user["name"].lower() == autologon.lower()]
    if len(selected) != 1 or "disabled" in selected[0]["flags"]:
        fail("autologon must select an enabled declared user")
    selected = selected[0]
    account_patches = []
    winlogon = "/Microsoft/Windows NT/CurrentVersion/Winlogon"
    for name, value in [("DefaultUserName", selected["name"]), ("DefaultPassword", selected["password"])]:
        account_patches.append({"hive": "SOFTWARE", "key": winlogon, "name": name, "type": "REG_SZ", "value": value})
    for user in specification["users"]:
        account_patches.append({"hive": "SOFTWARE", "key": "/Microsoft/Windows NT/CurrentVersion/ProfileList/" + identity["sid"] + "-" + str(user["rid"]), "name": "ProfileImagePath", "type": "REG_EXPAND_SZ", "value": "%SystemDrive%\\Documents and Settings\\" + user["name"]})
    hives = windows.hives_from_inf(
        registry_inf,
        txtsetup=txtsetup,
        extra=[
            {"inf": font_inf, "section": "Font.Reg.96"},
            {"inf": font_inf, "section": "Font.Latin.Reg"},
            {"inf": nettcpip_inf, "section": "TCPIP_AddReg_Global.NT"},
        ],
        patches=software_build_patches(cab, syssetup_inf, identity) + reactos_base_patches(identity) + account_patches,
        format=setupreg_hive,
    )
    hives["SAM"] = security["SAM"]
    hives["SECURITY"] = security["SECURITY"]
    # Winlogon's initial desktop uses .DEFAULT before any user profile loads.
    hives["DEFAULT"] = windows.patch_hive(hives["DEFAULT"], [
        {"key": "/Keyboard Layout/Preload", "name": "1", "type": "REG_SZ", "value": "00000409"},
    ])
    hives["SYSTEM"] = windows.hive_from_patches(
        "SYSTEM",
        windows.hive_patches(hives["SYSTEM"]) + security["system_patches"],
        keys=windows.hive_keys(hives["SYSTEM"], metadata=True) + security["system_keys"],
    )

    root = directory()
    root.mkdir(SYSTEM_ROOT)
    root.mkdir(path.join(SYSTEM_ROOT, "system32"))
    root.mkdir(path.join(SYSTEM_ROOT, "system32/config"))
    root.mkdir(path.join(SYSTEM_ROOT, "system32/drivers"))
    add_profile_skeleton(root, hives["DEFAULT"], users = [user["name"] for user in specification["users"]])

    copy_iso_files(root, iso, setup_root + "/system32", path.join(SYSTEM_ROOT, "system32"), {"drivers": True})
    copy_iso_files(root, iso, setup_root + "/system32/drivers", path.join(SYSTEM_ROOT, "system32/drivers"), {})
    copy_cab_from_inf(root, cab, reactos_inf, SYSTEM_ROOT)
    add_shortcuts_from_inf(root, cab, shortcuts_inf, reactos_inf, selected["name"])
    if rosapps_shortcuts_inf != None:
        add_shortcuts_from_inf(root, cab, rosapps_shortcuts_inf, reactos_inf, selected["name"])
    for name in ["reactos.inf", "registry.inf", "txtsetup.sif", "vgafonts.cab"]:
        root.write(path.join(SYSTEM_ROOT, name), iso[path.join(setup_root, name)])

    root.write("/freeldr.sys", iso["/loader/freeldr.sys"])
    # Newer FreeLoader builds split the Windows loader into a second PE stage.
    if "/loader/rosload.exe" in iso:
        root.write("/rosload.exe", iso["/loader/rosload.exe"])
    root.write("/freeldr.ini", FREELDR_INI)
    system_patches = txtsetup_system_patches(iso, txtsetup, setup_root)
    for patch in windows.inf_patches(font_inf, hive="SYSTEM", section="Font.Reg.96"):
        system_patches.append(patch)
    for patch in windows.inf_patches(nettcpip_inf, hive="SYSTEM", section="TCPIP_AddReg_Global.NT"):
        system_patches.append(patch)
    for patch in video_system_patches():
        system_patches.append(patch)
    for patch in network_system_patches():
        system_patches.append(patch)
    # hives_from_inf builds a useful SOFTWARE/DEFAULT baseline, but the boot
    # SYSTEM hive is deliberately based on setupreg.hiv. Carry the same generic
    # identity policy into that final build so the kernel, LSA, SAM, and
    # Winlogon agree on the local account domain.
    for patch in reactos_base_patches(identity):
        if patch["hive"] == "SYSTEM":
            system_patches.append(patch)
    system_patches.append({"key": "/Select", "name": "LastKnownGood", "type": "REG_DWORD", "value": 2})
    system_patches = mirror_numbered_control_sets(system_patches)
    for patch in security["system_patches"]:
        system_patches.append(patch)
    patched_system = windows.patch_hive(setupreg_hive, system_patches)
    system_hive = windows.hive_from_patches(
        "SYSTEM",
        windows.hive_patches(patched_system),
        keys=windows.hive_keys(patched_system, metadata=True) + security["system_keys"],
        format=setupreg_hive,
    )
    hives["SYSTEM"] = system_hive
    register_shell(cab, syssetup_inf, reactos_inf, hives, root)
    for name in ["SYSTEM", "SOFTWARE", "DEFAULT", "SAM", "SECURITY"]:
        hive = hives[name]
        root.write(path.join(SYSTEM_ROOT, "system32/config", name), hive)

    size = 768 * 1024 * 1024
    fs = filesystem.fat32(
        root,
        size=size,
        boot_code=iso["/loader/fat32.bin"],
        hidden_sectors=PARTITION_LBA,
        label="REACTOS",
    )
    disk = filesystem.mbr(size + PARTITION_LBA * 512).partition(fs, bootable=True, type=0x0c)
    return disk
