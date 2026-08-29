"""Opens an MSSQL Debian package and one nested Drawbridge SFP in the REPL."""

def open_sfp(data, path):
    member = data.find(path)
    if member == None:
        fail("package path not found: " + path)
    return archive.sfp(member)

def main(args):
    if len(args) < 1 or len(args) > 2:
        fail("usage: mssql_sfp_repl.star MSSQL.deb [SFP_PATH]")

    package = archive.ar(open(args[0]))
    data = archive.tar(archive.xz(package["data.tar.xz"]))
    sfp_paths = [path for path in data.files if path.endswith(".sfp")]
    if len(sfp_paths) == 0:
        fail("package contains no .sfp files")

    selected_path = "/opt/mssql/lib/system.sfp"
    if len(args) == 2:
        selected_path = path.clean(args[1])
    if selected_path not in sfp_paths:
        fail("SFP path not found: " + selected_path)
    container = archive.sfp(data[selected_path])

    print("package, data, sfp_paths, selected_path, and container are available")
    print("Use open_sfp(data, path) to open another SFP without leaving the REPL")
    print("%s: package=%s entries=%d files=%d" % (
        selected_path,
        container.package_label,
        len(container.entries),
        len(container.files),
    ))
    repl()
