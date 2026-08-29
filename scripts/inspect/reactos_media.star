def main(args):
    if len(args) < 1:
        error("Usage: scripts/inspect/reactos_media.star <reactos-iso-zip> [report.json]")

    z = archive.zip(open(args[0]))
    iso = filesystem.iso9660(z.files[0])

    freeldr = iso["/freeldr.ini"].read()
    reactos_inf = windows.inf(iso["/reactos/reactos.inf"])
    registry_inf = windows.inf(iso["/reactos/registry.inf"])
    setup_hive = windows.hive(iso["/reactos/setupreg.hiv"])
    cab = archive.cab(iso["/reactos/reactos.cab"])

    report = {
        "iso_root": iso["/"].files,
        "iso_reactos": iso["/reactos"].files,
        "system32_entries": iso["/reactos/system32"].files,
        "txtsetup_sif": iso["/reactos/txtsetup.sif"].read(),
        "autorun_inf": iso["/autorun.inf"].read(),
        "bootloader": {
            "freeldr_ini": freeldr,
            "loader_files": iso["/loader"].files,
            "setup_hive_setup_values": setup_hive["/Setup"].values,
        },
        "inf": {
            "reactos_sections": reactos_inf.json.keys(),
            "reactos_directories": reactos_inf["Directories"],
            "reactos_source_files_count": len(reactos_inf["SourceFiles"]),
            "reactos_source_files_kernel_entries": {
                "ntoskrnl.exe": reactos_inf["SourceFiles"].get("ntoskrnl.exe"),
                "ntkrnlmp.exe": reactos_inf["SourceFiles"].get("ntkrnlmp.exe"),
                "hal.dll": reactos_inf["SourceFiles"].get("hal.dll"),
            },
            "registry_sections": registry_inf.json.keys(),
        },
        "cab": {
            "kernel_candidates": [
                "ntoskrnl.exe" in cab.files,
                "ntkrnlmp.exe" in cab.files,
                "hal.dll" in cab.files,
            ],
            "selected_files": [
                "ntoskrnl.exe",
                "ntkrnlmp.exe",
                "hal.dll",
                "freeldr.sys",
                "setupldr.sys",
            ],
        },
    }

    encoded = json.encode(report, indent=2)
    if len(args) >= 2:
        write(args[1], encoded)
    else:
        print(encoded)
