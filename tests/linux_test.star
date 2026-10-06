"""Offline Linux image construction, metadata, framing and policy tests."""

load("//tests:testing.star", "case", "equal", "raises", "suite", "true")
load("@stdlib//unix:alpine.star", "install_plan", "merge", "parse_index", "read_package", "select", "validate_dependencies")
load("@stdlib//unix:initramfs.star", initramfs = "build")
load("@stdlib//unix:kernel.star", "modules", "x86_header")

def _file(text):
    return binary.concat([text])

def _digits(value, base, width):
    alphabet = "0123456789abcdef"
    out = ""
    for _ in range(width):
        out = alphabet[value % base] + out
        value //= base
    true(value == 0)
    return out

def _le(value, count):
    return binary.decode("".join([_digits((value >> (8 * i)) & 255, 16, 2) for i in range(count)]), "hex")

def _tar(name, text, mode = 0o644):
    # Independent minimal ustar fixture, not a production archive builder.
    prefix = name + "\x00" * (100 - len(name)) + "".join([_digits(value, 8, width) + "\x00" for value, width in [(mode, 7), (0, 7), (0, 7), (len(text), 11), (123, 11)]])
    suffix = "0" + "\x00" * 100 + "ustar\x0000" + "\x00" * (512 - 265)
    blank = prefix + " " * 8 + suffix
    checksum = 0
    for i in range(len(blank)):
        checksum += ord(blank[i])
    header = prefix + _digits(checksum, 8, 6) + "\x00 " + suffix
    return header + text + "\x00" * ((-len(text)) % 512)

def _gzip(text):
    # A single stored DEFLATE block with independently computed IEEE CRC32.
    crc = 0xffffffff
    for i in range(len(text)):
        crc ^= ord(text[i])
        for _ in range(8):
            crc = (crc >> 1) ^ (0xedb88320 if crc & 1 else 0)
    return binary.concat([b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01", _le(len(text), 2), _le(65535 - len(text), 2), text, _le(crc ^ 0xffffffff, 4), _le(len(text), 4)])

def test_apk_framing_and_metadata():
    data = _gzip(_tar("usr/bin/demo", "payload", 0o755) + "\x00" * 1024)
    info = "pkgname = demo\npkgver = 1-r0\narch = x86_64\ndatahash = " + binary.hex(digest(data)) + "\ndepend = libc\nprovides = cmd:demo=1-r0\ntriggers = /usr/bin/* /lib/*\n"
    control = _gzip(_tar(".PKGINFO", info) + _tar(".post-install", "#!/bin/sh\nexit 0\n", 0o755) + _tar(".trigger", "trigger", 0o755) + "\x00" * 1024)
    signature = _gzip(_tar(".SIGN.RSA.untrusted", "not a trusted signature") + "\x00" * 1024)
    source = binary.concat([signature, control, data])
    expected = {"name": "demo", "version": "1-r0", "arch": "x86_64", "size": source.size, "checksum": "Q1" + binary.base64(crypto.hash("sha1", control))}
    package = read_package(source, binary.hex(digest(source)), expected)
    equal(package["entries"][0]["path"], "usr/bin/demo")
    equal(package["entries"][0]["mode"], 0o100755)
    equal(package["entries"][0]["data"].read(), "payload")
    equal(package["metadata"]["depend"], ["libc"])
    true(package["signatures"] != None)
    raises(read_package, [source, "0" * 64], message = "SHA-256 mismatch")
    raises(read_package, [source, binary.hex(digest(source)), dict(expected, version = "2-r0")], message = "identity")
    raises(read_package, [source, binary.hex(digest(source)), dict(expected, checksum = "Q1wrong")], message = "control checksum")
    wrong_info = info.replace(binary.hex(digest(data)), "0" * 64)
    corrupt = binary.concat([_gzip(_tar(".PKGINFO", wrong_info) + "\x00" * 1024), data])
    raises(read_package, [corrupt, binary.hex(digest(corrupt))], message = "datahash mismatch")
    raises(merge, [[package]], message = "effects")
    plan = install_plan([package], external = ["libc"])
    equal([e["phase"] for e in plan["effects"]], ["post-install", "trigger"])
    equal(plan["effects"][1]["trigger_patterns"], ["/usr/bin/*", "/lib/*"])
    equal(plan["effects"][1]["script"].read(), "trigger")

def _package(name, depends = [], provides = []):
    return {"name": name, "version": "1-r0", "depends": depends, "provides": provides, "entries": [], "effects": {}, "metadata": {}}

def test_pinned_dependency_plans():
    index = parse_index("P:demo\nV:1-r0\nA:x86_64\nS:10\nC:Q1test\nD:libc\np:cmd:demo=1-r0\n\nP:demo\nV:2-r0\nA:x86_64\nS:20\nC:Q1other\n")
    equal(select(index, {"demo": "1-r0"})[0]["size"], 10)
    raises(select, [index, {"demo": "absent"}], message = "absent")
    app = _package("app", ["so:libc=1", "!forbidden"])
    libc = _package("musl", provides = ["so:libc=1"])
    equal([p["name"] for p in install_plan([app, libc])["packages"]], ["musl", "app"])
    raises(validate_dependencies, [[app]], message = "missing")
    raises(validate_dependencies, [[app, libc, _package("forbidden")]], message = "conflict")
    raises(validate_dependencies, [[app, libc, _package("other", provides = ["so:libc=1"])]], message = "ambiguous")
    raises(validate_dependencies, [[_package("app", ["musl>=1"]), libc]], message = "range constraint")
    raises(install_plan, [[_package("a", ["b"]), _package("b", ["a"])]], message = "cycle")

def test_initramfs_and_ext4():
    entries = [{"path": "bin/demo", "mode": 0o100755, "uid": 123456, "gid": 54321, "mtime": 42, "data": "payload"}, {"path": "bin/sh", "mode": 0o120777, "target": "demo"}]
    archive_file = initramfs(entries, init = "#!/bin/sh\nexec /bin/demo\n")
    records = {e["path"]: e for e in archive.cpio(archive_file)}
    equal(records["init"]["data"].read(), "#!/bin/sh\nexec /bin/demo\n")
    equal(records["dev/console"]["rdev"], 5)
    equal(records["dev/console"]["rdev_minor"], 1)
    equal(records["bin/demo"]["uid"], 123456)
    equal(records["bin/sh"]["target"], "demo")
    raises(initramfs, [entries], message = "executable regular init")
    image = filesystem.ext4_build(entries, size = 8 << 20, label = "linux", uuid = "00112233445566778899aabbccddeeff")
    volume = filesystem.ext4(image)
    equal(volume.label, "linux")
    nodes = {e.path: e for e in volume.entries}
    equal(nodes["bin/demo"].data.read(), "payload")
    equal(nodes["bin/demo"].uid, 123456)
    equal(nodes["bin/sh"].target, "demo")
    equal(auto(image).find("bin/demo").file.read(), "payload")

def _entry(path, text):
    return {"path": "lib/modules/1-virt/" + path, "mode": 0o100644, "data": _file(text)}

def test_kernel_header_and_module_closure():
    header = binary.concat(["\x00" * 0x1f1, b"\x04", b"\x00" * 2, _le(4, 4), b"\x00" * 6, b"\x55\xaa", b"\x00" * 2, "HdrS", _le(0x020f, 2), "\x00" * (2560 - 0x208), "\x00" * 64])
    equal(x86_header(header)["protected_offset"], 2560)
    equal(x86_header(header)["payload_size"], 64)
    raises(x86_header, [_file("bad")], message = "not a Linux")
    kernel = {"release": "1-virt", "entries": [_entry("modules.dep", "kernel/a.ko: kernel/b.ko\nkernel/b.ko:\nkernel/c.ko:\n"), _entry("modules.builtin", "kernel/built_in.ko\n"), _entry("modules.softdep", "softdep a post: c\nsoftdep a pre: b_alias\nsoftdep unselected malformed\n"), _entry("kernel/a.ko", "a"), _entry("kernel/b.ko", "b"), _entry("kernel/c.ko", "c")]}
    equal([e["data"].read() for e in modules(kernel, ["a", "built-in"], aliases = {"b_alias": "b"})], ["b", "a", "c"])
    raises(modules, [kernel, ["unknown"]], message = "unknown requested module")
    cycle = dict(kernel, entries = [_entry("modules.dep", "kernel/a.ko: kernel/b.ko\nkernel/b.ko: kernel/a.ko\n"), _entry("kernel/a.ko", "a"), _entry("kernel/b.ko", "b")])
    raises(modules, [cycle, ["a"]], message = "cycle")

TEST_SUITE = suite("linux", [case("apk-framing-and-metadata", test_apk_framing_and_metadata), case("pinned-dependency-plans", test_pinned_dependency_plans), case("initramfs-and-ext4", test_initramfs_and_ext4), case("kernel-header-and-module-closure", test_kernel_header_and_module_closure)])
