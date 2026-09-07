"""Original-media discovery and installed-file destinations."""

def base_name(p):
    """Returns the final slash-separated media filename."""
    parts = p.split("/")
    return parts[len(parts) - 1]

def destination_map(inf, prefix = "/ReactOS"):
    """One authoritative INF destination map for copying and registration."""
    dir_map = {}
    for k, v in inf["Directories"].items():
        if len(v) != 1:
            error("Directory {} must have one path: {}".format(k, v))
        p = path.join(prefix, path.from_windows(v[0]))
        dir_map[k] = p
    return dir_map

def installed_files(cab, inf, prefix = "/ReactOS"):
    """Maps installed image paths to lazy CAB files using the INF destinations."""
    dir_map = destination_map(inf, prefix)
    files = {}

    for name, dirs in inf["SourceFiles"].items():
        for d in dirs:
            if d not in dir_map:
                error("Directory {} not found in inf file".format(d))
            files[path.join(dir_map[d], name)] = cab[name]
    return files

def copy_cab_from_inf(root, cab, inf, prefix):
    """Populates installed files and their declared directories from a CAB."""
    for name in destination_map(inf, prefix).values():
        root.mkdir(name)
    for name, source in installed_files(cab, inf, prefix).items():
        root.write(name, source)

def copy_iso_files(root, iso, src_dir, dst_dir, skip):
    """Copies the selected setup directory, excluding explicitly skipped names."""
    for src in iso[src_dir].files:
        name = base_name(src)
        if name in skip:
            continue
        root.write(path.join(dst_dir, name), iso[src])

def reactos_media(source):
    """Selects the unique ISO from original ZIP/7z media or accepts a raw ISO."""
    signature = source.bytes(0, min(6, source.size))
    if signature[:2] == b"PK":
        packed = archive.zip(source)
        candidates = [item for item in packed.files if item.name.lower().endswith(".iso")]
    elif signature == b"7z\xbc\xaf\x27\x1c":
        packed = archive.sevenzip(source)
        candidates = [packed[e.path] for e in packed.entries if e.entry_type == "file" and e.path.lower().endswith(".iso")]
    else:
        candidates = [source]
    if len(candidates) != 1:
        fail("ReactOS media must contain exactly one ISO; found %d" % len(candidates))
    iso = filesystem.iso9660(candidates[0])
    roots = [p for p in ["/reactos", "/i386"] if p + "/txtsetup.sif" in iso]
    if len(roots) != 1:
        fail("ReactOS media must contain exactly one setup tree")
    return iso, roots[0]
