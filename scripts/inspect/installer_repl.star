"""Opens an installer file or an ISO member in the scoped REPL."""

load("@stdlib//windows:installer.star", "analyze", installation = "installer")
load("@stdlib//windows/emulation:runner.star", emulate = "run")
load("@stdlib//windows/selfreg:facts.star", windows_class_ids = "class_ids")
load("@stdlib//windows/selfreg:policy.star", inspect_registration = "registration_patches")

def media_files(disc, directory = "/", depth = 16):
    """Returns portable file handles keyed relative to a media directory."""
    result = {}
    pending = [directory]
    for _ in range(depth):
        next_directories = []
        for parent in pending:
            for name in disc[parent].files:
                member = disc[name]
                if type(member) == "file":
                    result[name[len(directory.rstrip("/")) + 1:]] = member
                else:
                    next_directories.append(name)
        pending = next_directories
        if not pending:
            return result
    fail("media directory depth exceeds bound")

def plan_summary(plan, limit = 12):
    """Prints bounded construction evidence without dumping payloads or keys."""
    print("format", plan.get("format"), "files", len(plan.get("files", [])), "registry", len(plan.get("definitive_registry_writes", [])), "custom actions", len(plan.get("custom_actions", [])))
    print("runtime dependencies", len(plan.get("runtime_dependencies", [])))
    gaps = plan.get("static_unresolved", plan.get("unresolved", []))
    print("unresolved", len(gaps), gaps[:limit])

def floppy_files(images):
    result = {}
    for number, file in enumerate(images):
        for name, member in media_files(filesystem.fat(file)).items():
            if not name.startswith("$metadata/"):
                result["%d/%s" % (number + 1, name)] = member
    return result

def optical_media(file):
    disc = filesystem.iso9660(file)
    members = disc["/"].files
    udf_bridge = len(members) == 1 and members[0].lower() == "/readme.txt" and disc[members[0]].size < 4096 and "UDF" in binary.text(disc[members[0]])
    if not members or udf_bridge:
        disc = filesystem.udf(file)
    return disc

def main(args):
    if len(args) not in [1, 2, 3]:
        fail("usage: installer_repl.star INSTALLER | IMAGE /INSTALLER | ARCHIVE IMAGE_MEMBER /INSTALLER")

    media_source = open(args[0])
    disk_media = None
    if args[0].lower().endswith(".7z"):
        wrapped_media = archive.sevenzip(media_source)
        images = [e for e in wrapped_media.entries if e.path.lower().endswith(".iso")]
        if len(args) == 3:
            images = [e for e in wrapped_media.entries if e.path == args[1]]
            if len(images) != 1:
                fail("archive image member not found: %s" % args[1])
            args = [args[0], args[2]]
        if not images:
            floppies = [e for e in wrapped_media.entries if e.path.lower().endswith((".img", ".ima"))]
            if not floppies:
                fail("archive does not contain ISO or floppy media")
            disk_media = floppy_files(floppies)
            images = floppies[:1]
        elif len(images) != 1:
            fail("select an individual image from the 7z archive in sevenzip.star's REPL")
        if disk_media == None and images[0].path.lower().endswith((".img", ".ima")):
            floppies = images
            disk_media = floppy_files(floppies)
        media_source = images[0]
    disc = (filesystem.fat(media_source) if disk_media != None else optical_media(media_source)) if len(args) == 2 else None
    source = disc[args[1]] if disc != None else open(args[0])
    if disc != None and args[1] == "/":
        source = media_source
    if source == None or type(source) != "file":
        fail("installer path not found: %s" % args[-1])
    msi = database.msi(source) if args[-1].lower().endswith(".msi") else None
    acme = windows.acme_table(source) if args[-1].lower().endswith(".stf") else None
    setup_inf = windows.setup_inf(source) if args[-1].lower().endswith(".inf") else None
    probe = archive.installer_probe(source) if msi == None and acme == None and setup_inf == None else {"supported": True, "format": "msi" if msi != None else ("microsoft_setup_inf" if setup_inf != None else "microsoft_acme")}
    installer = archive.installer(source) if msi == None and acme == None and setup_inf == None and probe["supported"] else None
    payload = installer.payload if installer != None else None
    script = installer.installscript if installer != None else None
    # Bind the imported helper in main's scope so the scoped REPL can use it.
    analyze_installer = analyze
    installer_modifications = installation
    run_executable = emulate
    class_ids = windows_class_ids
    registration_patches = inspect_registration

    print("disc, source, probe, installer, payload, script, analyze_installer, installer_modifications, run_executable, class_ids, and registration_patches are available")
    if disc != None and args[1] == "/":
        print("Media available as disc; media_files(disc, directory) returns portable file handles")
    elif msi != None:
        print("MSI database available as msi; use msi.plan(properties=..., media=media_files(disc, directory)); plan_summary(plan) prints bounded results")
    elif acme != None:
        print("ACME table available as acme; use windows.acme_plan(source, windows.inf(inf_file), media_files(disc))")
    elif setup_inf != None:
        print("Setup INF available as setup_inf; inspect sections or call plan(section, media, variables=..., initialize=...)")
    elif installer == None:
        print("unsupported installer:", probe)
    else:
        print("format=%s files=%d" % (installer.format, len(installer.files)))
    repl()
