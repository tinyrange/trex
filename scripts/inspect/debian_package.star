"""Inspects a Debian package through nested trex archive values."""

def _tar(package, section):
    member_name = section + ".tar.xz"
    member = package.find(member_name)
    if member == None:
        fail("package has no " + member_name)
    return archive.tar(archive.xz(member))

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
    if len(args) < 1 or len(args) > 3:
        fail("usage: debian_package.star PACKAGE.deb [control|data [PATH]]")

    package = archive.ar(open(args[0]))
    _print_outer(package)
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
        print(entry.hex(size = min(entry.size, 64)))
