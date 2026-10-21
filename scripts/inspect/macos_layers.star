"""Inspect Intel macOS installer layers without mounting or extracted intermediates.

Usage: trex scripts/inspect/macos_layers.star MEDIA.dmg REPORT.json
All byte sources remain native borrowed file views. Reports are final outputs.
This validates content and format checksums, not signatures or boot/install behavior.
"""

def fingerprint(file):
    return hex(digest(file))

def decode_payload(file):
    header = file.bytes(0, min(6, file.size))
    if header[:4] == b"pbzx":
        return "pbzx/xz", archive.pbzx(file)
    if header[:3] == b"BZh":
        return "bzip2", archive.bzip2(file)
    if header[:2] == b"\x1f\x8b":
        return "gzip", archive.gzip(file)
    if header in [b"070707", b"070701", b"070702"]:
        return "stored", file
    fail("unknown installer payload header: " + hex(header))

def add_container(queue, path, file, depth):
    if depth > 16:
        fail("nested installer depth exceeded: " + path)
    if file.size >= 4 and file.bytes(0, 4) == b"xar!":
        queue.append((path, "xar", file, depth))
    elif file.size >= 512 and file.bytes(file.size - 512, 4) == b"koly":
        queue.append((path, "udif", file, depth))
    elif b"IM4P" in file.bytes(0,min(32,file.size)):
        queue.append((path, "im4p", file, depth))
    else:
        fail("unrecognized installer container: " + path)

def inspect_partitions(disk):
    if disk.bytes(512, 8) == b"EFI PART":
        table = filesystem.gpt(disk)
        return "gpt", [{"name": p["name"], "offset": p["offset"], "size": p["file"].size,
                        "type": p["type_guid"], "data": p["file"]} for p in table.partitions]
    for block in [512, 1024, 2048]:
        if disk.bytes(block, 2) == b"PM":
            table = filesystem.apm(disk, block_size=block)
            return "apm", [{"name": str(p.name), "offset": p.start_block * p.block_size,
                            "size": p.data.size if p.data != None else 0,
                            "type": str(p.partition_type), "data": p.data} for p in table.partitions]
    # Some embedded firmware DMGs contain a filesystem with no partition map.
    if disk.bytes(1024, 2) in [b"H+", b"HX", b"BD"]:
        return "unpartitioned", [{"name": "filesystem", "offset": 0, "size": disk.size, "type": "hfs", "data": disk}]
    fail("unknown disk partition layout")

def inspect_volume(path, file, queue, depth):
    print("HFS", path)
    volume = filesystem.hfs(file)
    kinds = {}
    hashes = []
    byte_count = 0
    attributes = 0
    resources = 0
    aliases = 0
    compressed = {}
    for e in volume.entries:
        kinds[e.entry_type] = kinds.get(e.entry_type, 0) + 1
        if e.compression_type:
            compressed[str(e.compression_type)] = compressed.get(str(e.compression_type),0) + 1
        if e.finder_info[:8] == b"hlnkhfs+":
            aliases += 1
        forks = []
        for label, source in [("data", e.data), ("resource", e.resource),
                              ("raw_data", e.raw_data), ("raw_resource", e.raw_resource)]:
            if source != None:
                forks.append((label, source.size, fingerprint(source)))
                byte_count += source.size
                if label == "resource" and source.size:
                    resources += 1
        for label, source in sorted(e.xattrs.items()):
            forks.append(("xattr:" + label, source.size, fingerprint(source)))
            byte_count += source.size
            attributes += 1
        hashes.append((e.path, e.mode, e.uid, e.gid, e.target, forks))
        if e.entry_type == "file" and e.data != None and (e.path.endswith(".dmg") or e.path.endswith(".pkg")):
            add_container(queue, path + ":" + e.path, e.data, depth + 1)
    return {"layer": "hfs", "path": path, "name": str(volume.name), "entries": len(volume.entries),
            "kinds": kinds, "fork_bytes_read": byte_count, "extended_attributes": attributes,
            "nonempty_resource_forks": resources, "hardlink_aliases": aliases, "compressed_files": compressed,
            "inventory_sha256": fingerprint(json.encode(hashes)), "all_forks_read": True}

def inspect_cpio(path, file, queue, depth):
    print("PAYLOAD", path)
    encoding, decoded = decode_payload(file)
    size = decoded.size
    sha256 = fingerprint(decoded)  # Sequential scan forces all codec checksums.
    entries = archive.cpio(decoded, maximum_entries=1000000)
    kinds = {}
    for e in entries:
        kind = e["kind"]
        kinds[kind] = kinds.get(kind, 0) + 1
        source = e.get("data")
        if kind == "file" and source != None and (e["path"].endswith(".dmg") or e["path"].endswith(".pkg")):
            add_container(queue, path + ":" + e["path"], source, depth + 1)
    return {"layer": "cpio", "path": path, "encoding": encoding, "decoded_bytes": size,
            "sha256": sha256, "entries": len(entries), "kinds": kinds, "complete_stream_read": True}

def inspect_xar(path, file, queue, depth):
    print("XAR", path)
    package = archive.xar(file)
    payloads = []
    inventories = []
    for e in package.entries:
        e.verify()
        if e.data == None:
            continue
        if e.path.endswith("Payload") or e.path.endswith("Scripts"):
            payloads.append(inspect_cpio(path + ":" + e.path, e.data, queue, depth + 1))
        elif e.path.endswith(".dmg") or e.path.endswith(".pkg"):
            add_container(queue, path + ":" + e.path, e.data, depth + 1)
        elif e.data.size >= 8 and e.data.bytes(0, 8) == b"BOMStore":
            inventories.append({"path": e.path, "entries": len(archive.bom(e.data))})
    return {"layer": "xar", "path": path, "entries": len(package.entries),
            "members_verified": True, "toc_sha256": fingerprint(package.toc),
            "payloads": payloads, "bom_inventories": inventories}

def inspect_fat(path, file):
    volume = filesystem.fat(file)
    hashes = []
    directories = [volume["/"]]
    for unused in range(1000000):
        if not directories:
            break
        directory = directories.pop()
        for name in directory.files:
            child = volume[name]
            if type(child) == "file":
                hashes.append((name,child.size,fingerprint(child)))
            else:
                directories.append(child)
    if directories:
        fail("FAT directory count exceeded")
    return {"layer":"fat", "path":path, "files":len(hashes),"all_files_read":True,
            "inventory_sha256":fingerprint(json.encode(hashes))}

def inspect_media(file, name):
    queue = [(name, "udif", file, 0)]
    layers = []
    for unused in range(100000):
        if not queue:
            break
        path, kind, source, depth = queue.pop(0)
        if kind == "xar":
            layers.append(inspect_xar(path, source, queue, depth))
            continue
        if kind == "im4p":
            print("IM4P",path)
            envelope = archive.im4p(source)
            payload = envelope.payload
            encoding = "stored"
            if payload.bytes(0,min(4,payload.size)) in [b"bvx1",b"bvx2",b"bvxn",b"bvx-"]:
                payload = archive.lzfse(payload)
                encoding = "lzfse"
            if envelope.expected_size and payload.size != envelope.expected_size:
                fail("IM4P decoded length mismatch: " + path)
            layers.append({"layer":"im4p","path":path,"payload_type":envelope.payload_type,
                           "encoding":encoding,"decoded_bytes":payload.size,"sha256":fingerprint(payload),
                           "extras_sha256":[fingerprint(e) for e in envelope.extras]})
            layers.append(inspect_volume(path + ":payload",payload,queue,depth))
            continue
        print("UDIF", path)
        image = archive.udif(source)
        image.verify()
        layout, partitions = inspect_partitions(image.disk)
        inventory = []
        for p in partitions:
            record = {k: v for k, v in p.items() if k != "data"}
            partition = p["data"]
            if partition != None and partition.size >= 1026 and partition.bytes(1024, 2) in [b"H+", b"HX", b"BD"]:
                layers.append(inspect_volume(path + ":" + p["name"], partition, queue, depth))
                record["filesystem"] = "hfs"
            elif p["type"].upper().strip("{}") == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":
                layers.append(inspect_fat(path + ":" + p["name"],partition))
                record["filesystem"] = "fat"
            else:
                record["filesystem"] = None
            inventory.append(record)
        layers.append({"layer": "udif", "path": path, "logical_bytes": image.disk.size,
                       "layout": layout, "block_maps": len(image.tables), "partitions": inventory,
                       "declared_checksums_verified": True})
    if queue:
        fail("container count exceeded")
    return {"media": name, "stored_bytes": file.size, "complete": True, "layers": layers,
            "scope": "All discovered DMG/XAR/CPIO/IM4P layers and HFS data/resource/xattr forks read; declared format checksums checked. No Apple signature authentication, boot or installation proof."}

def main(args):
    if len(args) != 2:
        fail("usage: macos_layers.star MEDIA.dmg REPORT.json")
    report = inspect_media(open(args[0]), args[0])
    write(args[1], json.encode(report, indent="  "))
    print("VERIFIED", args[0], "layers", len(report["layers"]), "report", args[1])
