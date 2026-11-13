"""Inspects a Debian package through nested trex archive values."""

def _tar(package, section):
    xz = package.find(section + ".tar.xz")
    if xz != None:
        return archive.tar(archive.xz(xz))
    gz = package.find(section + ".tar.gz")
    if gz != None:
        return archive.tar(archive.gzip(gz))
    fail("package has no " + section + ".tar.xz or .tar.gz")

def _print_outer(package):
    print("Debian package members:")
    for member in package.entries:
        print("  %s  size=%d mode=%s" % (member.name, member.size, hex(member.mode)))

def _print_tar(contents):
    for entry in contents.entries:
        suffix = ""
        if entry.link:
            suffix = " -> " + entry.link
        print("  %s  type=%s size=%d mode=%s%s" % (
            entry.path,
            entry.entry_type,
            entry.size,
            hex(entry.mode),
            suffix,
        ))

def main(args):
    if len(args) < 1 or len(args) > 4:
        fail("usage: debian_package.star PACKAGE.deb [control|data [PATH [--text]] | --repl]")

    package = archive.ar(open(args[0]))
    _print_outer(package)
    if len(args) == 2 and args[1] == "--repl":
        control = _tar(package, "control")
        data = _tar(package, "data")
        print("package, control, and data are available in the REPL")
        repl()
        return
    if len(args) == 1:
        return

    section = args[1]
    if section != "control" and section != "data":
        fail("section must be control or data")
    contents = _tar(package, section)
    print("%s archive entries (%d):" % (section, len(contents.entries)))
    if len(args) == 2:
        _print_tar(contents)
        return

    entry = contents.find(args[2])
    if entry == None:
        fail("archive path not found: " + args[2])
    print("path=%s type=%s size=%d mode=%s uid=%d gid=%d" % (
        entry.path,
        entry.entry_type,
        entry.size,
        hex(entry.mode),
        entry.uid,
        entry.gid,
    ))
    if entry.entry_type == "file" or entry.entry_type == "hardlink":
        if len(args) == 4 and args[3] == "--text":
            print(str(entry.bytes()))
        else:
            print(entry.hex(size = min(entry.size, 64)))
