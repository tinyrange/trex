"""Overlays Drawbridge SFP contents from an MSSQL Debian package into an output directory."""

def main(args):
    if len(args) < 2 or len(args) > 3:
        fail("usage: mssql_sfp_overlay.star MSSQL.deb OUTPUT_DIRECTORY [SKIP_SFP_PATH]")

    output = args[1]
    if output == "":
        fail("output directory must not be empty")
    skip = None
    if len(args) == 3:
        skip = path.clean(args[2])

    package = archive.ar(open(args[0]))
    data = archive.tar(archive.xz(package["data.tar.xz"]))
    sfp_paths = [name for name in data.files if name.endswith(".sfp")]

    archive_count = 0
    file_count = 0
    for sfp_path in sfp_paths:
        if sfp_path == skip:
            print("skip %s" % sfp_path)
            continue
        container = archive.sfp(data[sfp_path])
        print("overlay %s: package=%s files=%d" % (
            sfp_path,
            container.package_label,
            len(container.files),
        ))
        for entry_path in container.files:
            write(output + entry_path, container[entry_path])
            file_count += 1
        archive_count += 1

    print("overlaid %d files from %d SFP archives into %s" % (
        file_count,
        archive_count,
        output,
    ))
