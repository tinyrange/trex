"""Compile both NE variants and validate loader-sensitive structure without media."""
load("//tests:testing.star", "equal", "true")
load("//scripts/guest/windows_extension:build.star", "compile_win16")

def check_image(image, windows3):
    equal(image[:2], b"MZ")
    ne = binary.read_u32le(image, 0x3c)
    equal(image[ne:ne + 2], b"NE")
    equal(binary.read_u16le(image, ne + 0x1c), 2, "separate code and automatic data segments")
    equal(binary.read_u16le(image, ne + 0x0e), 2)
    equal(binary.read_u16le(image, ne + 0x1a), 2, "stack belongs to automatic data")
    equal(binary.read_u16le(image, ne + 0x16), 1)
    equal(binary.read_u16le(image, ne + 0x3e), 0x300 if windows3 else 0)
    if windows3:
        true(ord(image[ne + 2]) >= 5, "linker-4 images trigger Windows 3 compatibility UI")
        equal(binary.read_u16le(image, ne + 0x0c) & 0x300, 0x300)
    names = ne + binary.read_u16le(image, ne + 0x2a)
    refs = ne + binary.read_u16le(image, ne + 0x28)
    equal(binary.read_u16le(image, ne + 0x1e), 2)
    for i, name in enumerate([b"KERNEL", b"USER"]):
        offset = binary.read_u16le(image, refs + i * 2)
        true(offset > 0, "offset zero resolves to SELF in the Windows 1 loader")
        at = names + offset
        equal(image[at + 1:at + 1 + ord(image[at])], name)
    segments = ne + binary.read_u16le(image, ne + 0x22)
    shift = binary.read_u16le(image, ne + 0x32)
    code_at = binary.read_u16le(image, segments) << shift
    code_size = binary.read_u16le(image, segments + 2)
    entry = binary.read_u16le(image, ne + 0x14)
    true(0 < entry and entry < code_size)
    true(binary.read_u16le(image, segments + 4) & 0x100, "code segment carries import relocations")
    relocs = code_at + code_size
    count = binary.read_u16le(image, relocs)
    true(count > 3, "native startup plus filesystem and USER calls must be linked")
    imported = {}
    for i in range(count):
        at = relocs + 2 + i * 8
        equal(image[at:at + 2], b"\x03\x01", "far-pointer ordinal import")
        source = binary.read_u16le(image, at + 2)
        true(0 < source and source + 4 <= code_size)
        equal(ord(image[code_at + source - 1]), 0x9a, "far native call")
        equal(binary.read_u16le(image, code_at + source), 0xffff, "terminated relocation chain")
        module = binary.read_u16le(image, at + 4)
        ordinal = binary.read_u16le(image, at + 6)
        true(module in [1, 2] and ordinal > 0)
        imported[(module, ordinal)] = True
    # InitTask, LoadModule, native file read/write, COM open/read/write, message pump.
    for symbol in [(1, 91), (1, 45), (1, 82), (1, 86), (2, 200), (2, 204), (2, 205), (2, 109)]:
        true(symbol in imported, "missing native import " + str(symbol))
    data_at = binary.read_u16le(image, segments + 8) << shift
    data_size = binary.read_u16le(image, segments + 10)
    memory = binary.read_u16le(image, segments + 14)
    true(data_at >= relocs + 2 + count * 8 and data_at + data_size <= len(image))
    true(data_size <= memory)
    true(memory + binary.read_u16le(image, ne + 0x10) + binary.read_u16le(image, ne + 0x12) <= 0xfffe)
    equal(image[data_at:data_at + 16], b"\x00" * 16, "reserved Windows instance header")

def main(args):
    root = args[0] if args else "."
    for windows3 in [False, True]:
        check_image(compile_win16(root, windows3 = windows3), windows3)
        print("PASS Win16 native image", "3.x" if windows3 else "1.x/2.x")
