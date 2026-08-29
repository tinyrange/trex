"""Opens a Debian package's nested archives in the scoped trex REPL."""

def main(args):
    if len(args) != 1:
        fail("usage: debian_package_repl.star PACKAGE.deb")

    package = archive.ar(open(args[0]))
    control = archive.tar(archive.xz(package["control.tar.xz"]))
    data = archive.tar(archive.xz(package["data.tar.xz"]))
    print("package, control, and data are available in the REPL")
    repl()
