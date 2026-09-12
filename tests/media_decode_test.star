"""Portable nested-container decoding tests; no proprietary media required."""

load("//tests:testing.star", "case", "equal", "raises", "suite", "true")
load("//scripts/inspect:media_repl.star", "archive_layers", "compression_layers", "describe", "inspect_outer", "irix_image_names", "members")

def test_bzip2_layer():
    compressed = binary.concat([binary.decode("425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0", "hex")])
    decoded = inspect_outer(compressed)
    equal(decoded.read(), "hello world\n")
    equal(describe(decoded)["size"], 12)
    raises(archive.bzip2, [compressed], {"maximum_bytes": 11}, "maximum_bytes")

def test_aws_record_boundaries():
    tape = binary.concat([b"\x03\x00\x00\x00\x80\x00abc\x02\x00\x03\x00\x20\x00de\x00\x00\x02\x00\x40\x00"])
    decoded = archive.aws(tape)
    equal(len(decoded.records), 2)
    equal(decoded.records[0].data.read(), "abcde")
    equal(decoded.records[0].blocks, 2)
    true(decoded.records[1].tape_mark)
    equal(decoded.records[1].data, None)
    raises(archive.aws, [tape.slice(0, tape.size - 1)])

def test_irix_indexed_image():
    image = binary.concat([b"im001V630P00\x00\x00\x01a\x1f\x9d\x90\x41\x00"])
    index = binary.concat([b"f 0755 root sys a source/a main.sw.bin sum(65) size(1) off(13) cmpsize(5)\n"])
    result = archive.irix_image(image, index, "main.sw")
    item = archive.irix_idb(index).items[0]
    equal(item.path, "a")
    equal(item.kind, "f")
    equal(item.source, "source/a")
    true("main.sw.bin" in item.attributes)
    equal(irix_image_names(archive.irix_idb(index), "sw"), ["main.sw"])
    equal(members(result)["count"], 1)
    entry = result.entries[0]
    equal(entry.path, "a")
    equal(entry.read(), "A")
    equal(entry.mode, 0o755)
    equal(entry.owner, "root")
    raises(archive.irix_image, [image, index, "missing.sw"], message = "unindexed")
    equal(archive.irix_image(image.slice(0, 13), index, "missing.man").entries, [])

def test_pack_layer():
    data = binary.concat([b"\x1f\x1e\x00\x00\x00\x04\x02\x01\x00AB\x85"])
    equal(inspect_outer(data).read(), "ABBA")
    layers = compression_layers(data)
    equal(layers["data"].read(), "ABBA")
    equal(len(layers["layers"]), 1)
    tree = archive_layers(data, "manual.z")
    equal(tree[0]["path"], ["manual.z"])
    equal(tree[0]["compression"][0]["size"], 4)
    raises(archive_layers, [data], {"maximum_entries": 0})
    raises(compression_layers, [data], {"maximum_layers": 0}, "maximum_layers")
    raises(archive.pack, [data], {"maximum_bytes": 3})
    # A corrupt inner compression stream keeps the selected source identity.
    broken = binary.concat([b"\x1f\x1e"])
    raises(archive_layers, [broken, "disc/package/manual.z"], message = "disc/package/manual.z")

def test_irix_standalone_tape():
    image = binary.concat([
        b"\xac\xed\x12\x34\xdf\xb1\x7a\x5f", b"\x00" * 24,
        b"sash", b"\x00" * 12, b"\x00\x00\x00\x01\x00\x00\x00\x04",
        b"\x00" * (512 - 56), b"data",
    ])
    entry = archive.irix_tape(image).entries[0]
    equal(entry.path, "sash")
    equal(entry.offset, 512)
    equal(entry.data.read(), "data")
    raises(archive.irix_tape, [image.slice(0, image.size - 1)])

def test_mac_resource():
    # One unnamed TEST/-2 resource. Data and map occupy separate ranges.
    fork = binary.concat([
        binary.decode("00000100000001070000000700000032", "hex"),
        b"\x00" * 240, b"\x00\x00\x00\x03abc",
        b"\x00" * 24,
        binary.decode("001c00320000544553540000000afffeffff0000000000000000", "hex"),
    ])
    entry = archive.mac_resource(fork).entries[0]
    equal(entry.resource_type, b"TEST")
    equal(entry.id, -2)
    equal(entry.name, None)
    equal(entry.path, "54455354/-2")
    equal(entry.data.read(), "abc")
    equal(entry.compressed, False)
    equal(entry.stored_data.read(), "abc")
    raises(archive.mac_resource, [fork.slice(0, fork.size - 1)])

def test_mac_resource_compressed():
    # A dcmp1 byte literal inside one unnamed TEST/-2 resource.
    fork = binary.concat([
        binary.decode("000001000000011b0000001b00000032", "hex"),
        b"\x00" * 240,
        binary.decode("00000017a89f65720012080100000003000000010000", "hex"),
        b"\x02ABC\xff", b"\x00" * 24,
        binary.decode("001c00320000544553540000000afffeffff0100000000000000", "hex"),
    ])
    entry = archive.mac_resource(fork).entries[0]
    equal(entry.compressed, True)
    equal(entry.size, 3)
    equal(entry.stored_size, 23)
    equal(entry.data.read(), "ABC")
    equal(entry.stored_data.bytes(0, 4), b"\xa8\x9f\x65\x72")
    raises(archive.mac_resource, [fork], {"maximum_decoded_bytes": 2})

def test_compactpro_nested():
    # Two synthetic RLE-only catalogs; outer data is another CompactPro archive.
    data = binary.decode("010100000000004d010100000000000b414243ee9872000001000568656c6c6f01000000080000000000000000000000000000000000005c7cfcb7000000000000000000030000000000000003096fad6800010009696e6e65722e73656101000000080000000000000000000000000000000000009c4e783f000000000000000000450000000000000045", "hex")
    data = binary.concat([data])
    outer = archive.compactpro(data)
    equal(outer.entries[0].path, "/inner.sea")
    equal(outer.entries[0].resource_size, 0)
    inner = archive.compactpro(outer.entries[0].data)
    equal(inner.entries[0].data.read(), "ABC")
    layers = archive_layers(data, "outer.cpt")
    equal(len(layers), 2)
    equal(layers[1]["path"], ["outer.cpt", "/inner.sea"])
    raises(archive_layers, [data, "outer.cpt"], {"maximum_depth": 0}, "maximum_depth")
    raises(archive.compactpro, [data], {"maximum_decoded_bytes": 1})

def test_stuffit():
    data = binary.concat([binary.decode("53495421000100000089724c61750200000000000000000001460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000030000452100000000000050a7414243", "hex")])
    archive_value = archive.stuffit(data)
    equal(archive_value.version, 2)
    entry = archive_value.entries[0]
    equal(entry.path, "/F")
    equal(entry.data.read(), "ABC")
    equal(entry.resource_size, 0)
    equal(len(archive_layers(data, "example.sea")), 1)
    raises(archive.stuffit, [data.slice(0, data.size-1)])
    raises(archive.stuffit, [data], {"maximum_decoded_bytes": 2})
    # Easy Open kind resources start with the file type SIT!, not an archive.
    descriptor = binary.concat([b"SIT!\x00\x00\x00\x00\x00\x03apnm\x07StuffIt"])
    equal(archive_layers(descriptor, "6b696e64/11000"), [])
    raises(archive_layers, [descriptor, "bad.sit"], message = "bad.sit")

def test_nested_error_context():
    # A valid ar container around a deliberately incomplete UNIX pack stream.
    data = binary.concat([
        b"!<arch>\n", b"bad.z/          ", b"0           ",
        b"0     ", b"0     ", b"100644  ", b"2         ", b"`\n",
        b"\x1f\x1e",
    ])
    equal(len(archive.ar(data).entries), 1)
    raises(archive_layers, [data, "outer.a"], message = "outer.a")
    raises(archive_layers, [data, "outer.a"], message = "bad.z")
    raises(archive_layers, [data], {"maximum_entries": 1}, "maximum_entries")
    raises(archive_layers, [data], {"maximum_depth": 0}, "maximum_depth")
    # A resource-map read alone must not hide a second compression wrapper.
    wrapped_resource = binary.concat([
        b"!<arch>\n", b"code/           ", b"0           ",
        b"0     ", b"0     ", b"100644  ", b"8         ", b"`\n",
        b"ADCR\x03\x00\x00\x01",
    ])
    raises(archive_layers, [wrapped_resource, "resources.a"], message = "ADCR")
    raises(archive_layers, [wrapped_resource, "resources.a"], message = "code")

def test_tome():
    # One ID-qualified Tome record with a compressed one-byte data fork.
    file = binary.concat([
        binary.decode("6b630001", "hex"), b"\x00" * 12, b"\x00\x01", b"\x00" * 8, b"\x00\x01",
        binary.decode("0000000100000000", "hex"),
        binary.decode("00000000000703612f62", "hex"), b"\x00" * 50,
        binary.decode("00000001000000a400000006ffffffbe", "hex"),
        b"\x00" * 52,
        binary.decode("000100000820", "hex"),
    ])
    result = archive.tome(file)
    entry = result.entries[0]
    equal(result.checksums_verified, True)
    equal(entry.id, 7)
    equal(entry.path, "/7/a%2Fb")
    equal(entry.data.read(), "A")
    equal(entry.resource_size, 0)
    equal(entry.stored_data.size, 6)
    raises(archive.tome, [file], {"maximum_decoded_bytes": 5})
    raises(archive.tome, [file.slice(0, file.size - 1)])
    layers = archive_layers(file, "sample Tome")
    equal(len(layers), 1)
    equal(layers[0]["children"][0]["header"], "41")
    # Kind2 catalogs contain individual resources, not file resource forks.
    resource = binary.concat([
        file.slice(0,16), b"\x00\x02", file.slice(18,18),
        b"\x00" * 4, b"\x00\x07\xff\xfeTEST", b"\x00" * 66,
        binary.decode("00000001000000a400000006ffffffbe", "hex"),
        b"\x00" * 34, file.slice(164,6),
    ])
    resource_archive = archive.tome(resource)
    equal(resource_archive.catalog_kind, 2)
    r = resource_archive.entries[0]
    equal(r.resource_type, b"TEST")
    equal(r.resource_id, -2)
    equal(r.name, b"")
    equal(r.path, "/7/54455354/-2")
    equal(r.data.read(), "A")
    equal(r.resource.size, 0)
    equal(hasattr(r, "file_type"), False)

def test_apm():
    image = binary.concat([
        binary.decode("45520800", "hex"), b"\x00" * 508,
        binary.decode("504d0000000000010000000200000001", "hex"),
        b"HFS", b"\x00" * 29, b"Apple_HFS", b"\x00" * 455,
        b"DATA", b"\x00" * 508,
    ])
    result = filesystem.apm(image)
    equal(result.block_size, 512)
    equal(result.device_block_size, 2048)
    equal(result.partitions[0].partition_type, b"Apple_HFS")
    equal(result.partitions[0].block_size, 512)
    equal(result.partitions[0].data.bytes(0, 4), b"DATA")
    equal(result.partitions[0].complete, True)
    raises(filesystem.apm, [image.slice(0, image.size - 1)])

def test_adcr():
    # ADCR03 with a sole literal A code, no dictionary references.
    image = binary.concat([
        b"ADCR\x03\x00\x00\x01\x01\x05",
        b"\xee" * 32, b"\x0e", b"\xee" * 113,
        b"\x05\x00\x00",
    ])
    equal(archive.adcr(image).read(), "A")
    raises(archive.adcr, [image], {"maximum_decoded_bytes": 0})
    raises(archive.adcr, [image.slice(0, image.size - 1)])

def test_ultrix_label():
    image = binary.concat([
        b"\x00" * 16312,
        b"\x57\x29\x03\x00\x01\x00\x00\x00",
        b"\x01\x00\x00\x00\x20\x00\x00\x00",
        b"\x00" * 8,
        b"\x21\x00\x00\x00\x00\x00\x00\x00",
        b"\x00" * 40,
        b"\x00" * 512,
    ])
    label = filesystem.ultrix_label(image)
    equal(label.block_size, 512)
    equal(len(label.partitions), 8)
    equal(label.partitions[0].name, "a")
    equal(label.partitions[0].data.size, 512)
    equal(label.partitions[1].data, None)
    equal(label.partitions[2].data.size, image.size)
    raises(filesystem.ultrix_label, [image.slice(0, 16383)])

def test_lha():
    file = binary.concat([binary.decode("1ad72d6c68302d03000000030000000000000000000466696c65389761626300", "hex")])
    decoded = archive.lha(file)
    equal(decoded.files, ["/file"])
    equal(decoded.find("file").data.read(), "abc")
    equal(decoded.find("missing"), None)
    equal(decoded.entries[0].method, "-lh0-")
    equal(len(archive_layers(file, "archive.lha")), 1)
    raises(archive.lha, [file], {"maximum_decoded_bytes": 2})
    raises(archive.lha, [file.slice(0, file.size - 1)])

def test_hunk_objects():
    file = binary.concat([binary.decode("000003e700000000000003e90000000141424344000003f2", "hex")])
    result = archive.hunk_objects(file)
    equal(len(result.units), 1)
    equal(result.units[0].raw.size, file.size)
    equal(result.units[0].records[1].payload.read(), "ABCD")
    equal(result.entries[0].data.read(), "ABCD")
    equal(len(archive_layers(file, "objects.lib")), 1)
    raises(archive.hunk_objects, [file.slice(0, file.size - 4)])
    raises(archive.hunk_objects, [file], {"maximum_records": 1})
    ppc = binary.concat([binary.decode("000003e700000000000004e90000000148000001000003ef e5000001666f6f00000000010000000000000000000003f2".replace(" ", ""), "hex")])
    decoded = archive.hunk_objects(ppc)
    equal(decoded.units[0].records[2].symbols[0].kind, 229)
    equal(len(decoded.entries), 1)
    equal(decoded.entries[0].data.size, 4)
    equal(len(archive_layers(ppc, "ppc.lib")), 1)

def test_hunk_load():
    file = binary.concat([binary.decode("000003f30000000000000001000000000000000000000001000003e90000000141424344000003f2", "hex")])
    result = archive.hunk_load(file)
    equal(result.header.sizes, [4])
    equal(result.header.table_size, 1)
    equal(result.entries[0].data.read(), "ABCD")
    equal(len(archive_layers(file, "program")), 1)
    raises(archive.hunk_load, [file.slice(0, file.size - 4)])

def test_aix_small_ar():
    def decimals(values):
        return "".join([str(value) + " " * (12 - len(str(value))) for value in values])

    first = binary.concat([decimals([3, 166, 0, 0, 0, 0]), "644         ", "3   ", b"one\x00`\nabc\x00"])
    table = binary.concat([decimals([28, 0, 68, 0, 0, 0]), "0           ", "0   ", b"`\n", decimals([1, 68]), b"one\x00"])
    file = binary.concat([b"<aiaff>\n", decimals([166, 0, 68, 68, 0]), first, table])
    result = archive.ar(file)
    equal(result.files, ["one"])
    equal(result.find("one").read(), "abc")
    equal(auto(file).find("one").file.read(), "abc")
    equal(len(archive_layers(file, "library")), 1)
    raises(archive.ar, [file], {"maximum_metadata": 20})
    raises(archive.ar, [file.slice(0, file.size - 1)])

def test_bff():
    def seal(parts):
        header = binary.concat(parts)
        checksum = 0
        for i, value in enumerate(header.bytes().elems()):
            if i not in [4, 5]:
                checksum += value << (value & 7)
        return binary.concat([header.slice(0, 4), binary.u16le(checksum & 65535), header.slice(6, header.size - 6)])

    volume = seal([b"\x09\x00", binary.u16le(60011), b"\x00\x00", binary.u16le(1), b"\x00" * 60, binary.u16le(100), b"\x00\x00"])
    member = seal([b"\x09\x0b", binary.u16le(60012), b"\x00\x00", binary.u16le(1), binary.u32le(42), binary.u32le(0o100644), b"\x00" * 8, binary.u32le(4), b"\x00" * 28, binary.u32le(6), b"\x00" * 4, b"file\x00\x00\x00\x00"])
    security = binary.concat([binary.u32le(2), binary.u32le(2), binary.u32le(16), b"\x00" * 12, binary.u32le(16), b"\x00" * 12])
    end = seal([b"\x01\x07", binary.u16le(60011), b"\x00" * 4])
    file = binary.concat([volume, member, security, b"\x02\x01\x00AB\x85\x00\x00", end])
    result = archive.bff(file)
    equal(len(result.entries), 1)
    equal(result.entries[0].data.read(), "ABBA")
    equal(result.entries[0].acl.size, 16)
    true(result.entries[0].packed)
    equal(auto(file).find("file").file.read(), "ABBA")
    raises(archive.bff, [file], {"maximum_decoded_bytes": 3})

TEST_SUITE = suite("media_decode", [
    case("bff", test_bff),
    case("aix_small_ar", test_aix_small_ar),
    case("hunk_load", test_hunk_load),
    case("hunk_objects", test_hunk_objects),
    case("lha", test_lha),
    case("ultrix_label", test_ultrix_label),
    case("adcr", test_adcr),
    case("apm", test_apm),
    case("tome", test_tome),
    case("nested_error_context", test_nested_error_context),
    case("compactpro_nested", test_compactpro_nested),
    case("stuffit", test_stuffit),
    case("mac_resource", test_mac_resource),
    case("mac_resource_compressed", test_mac_resource_compressed),
    case("bzip2_layer", test_bzip2_layer),
    case("aws_record_boundaries", test_aws_record_boundaries),
    case("irix_indexed_image", test_irix_indexed_image),
    case("pack_layer", test_pack_layer),
    case("irix_standalone_tape", test_irix_standalone_tape),
])
