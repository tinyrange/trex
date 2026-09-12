"""Inspect original media and nested file views without extracting or booting.

Use describe(file), members(container), and signatures(file) in the REPL.
Opening a layer is explicit: retain its container and select a member for the
next probe. Unknown signatures are evidence, not a claim of decoded contents.
"""

def describe(file):
    return {"size": file.size, "header": file.hex(0, min(32, file.size))}

def signatures(file):
    return {offset: file.hex(offset, min(16, file.size - offset))
            for offset in [0, 512, 1024, 8192, 9564, 32768, 65536]
            if offset < file.size}

def members(container, limit = 20):
    entries = container.entries
    return {"count": len(entries), "entries": [
        {"path": entry.path, "kind": entry.entry_type, "size": entry.size}
        for entry in entries[:limit]
    ]}

def inspect_outer(file):
    """Decode an outer wrapper, returning its live file/container and evidence."""
    header = file.bytes(0, min(6, file.size))
    if header == b"7z\xbc\xaf\x27\x1c":
        return archive.sevenzip(file)
    if header[:3] == b"BZh":
        return archive.bzip2(file)
    if header[:2] == b"\x1f\x8b":
        return archive.gzip(file)
    if header[:2] == b"\x1f\x9d":
        return archive.compress(file)
    if header[:2] == b"\x1f\x1e":
        return archive.pack(file)
    return file

def inventory_originals(root):
    """Return source names only; filesystem.host is the native input backend."""
    source = filesystem.host(root)
    return [name for name in source.files if type(source.find(name)) == "file"]

def verify_entries(container):
    """Read every regular file fully and retain hashes, sizes and small headers.

    A successful read validates only this layer, not every possible nested
    format. Use the returned headers and names to choose the next probes.
    """
    result = []
    for entry in container.entries:
        if getattr(entry, "entry_type", "file") != "file":
            continue
        file = getattr(entry, "data", entry)
        if hasattr(file, "verify"):
            file.verify()
        result.append({"path": getattr(entry, "path", getattr(entry, "name", "")), "size": file.size,
                       "sha256": hex(digest(file)),
                       "header": binary.hex(file.bytes(0, min(16, file.size)))})
    return result

def verify_hfs_forks(volume):
    """Read both HFS forks, including resource-only files; do not decode payloads."""
    result = []
    for entry in volume.entries:
        if entry.entry_type != "file":
            continue
        forks = []
        for name, file in [("data", entry.data), ("resource", entry.resource)]:
            forks.append({"fork": name, "size": file.size,
                          "sha256": hex(digest(file)),
                          "header": binary.hex(file.bytes(0, min(16, file.size)))})
        record = {"path": entry.path, "forks": forks}
        if hasattr(entry, "occurrence"):
            record["occurrence"] = entry.occurrence
        result.append(record)
    return result

def verify_mac_resources(file):
    """Decode a resource map and read each payload, retaining stored/decoded evidence."""
    fork = archive.mac_resource(file)
    result = []
    for entry in fork.entries:
        result.append({
            "type": binary.hex(entry.resource_type), "id": entry.id,
            "path": entry.path, "occurrence": entry.occurrence,
            "compressed": entry.compressed,
            "stored_size": entry.stored_size, "size": entry.size,
            "stored_sha256": hex(digest(entry.stored_data)),
            "sha256": hex(digest(entry.data)),
            "header": binary.hex(entry.data.bytes(0, min(16, entry.size))),
        })
    return result

def hfs_resource_layers(volume, dictionaries = {}):
    """Follow archive payloads in every outer HFS resource fork.

    Data-fork scans miss resource-only files and Tome part resources.
    dictionaries maps an explicitly inspected file path to its ADCR history
    view; there is no loader-code execution or guessed default dictionary.
    Unknown leaves still need their recorded resource headers inspected.
    """
    result = []
    for file in volume.entries:
        if file.entry_type != "file" or not file.resource.size:
            continue
        resource_map = _layer_call(archive.mac_resource, [file.resource], [file.path, "resource fork"])
        for entry in resource_map.entries:
            data = entry.data
            if data.size >= 4 and data.bytes(0, 4) == b"ADCR":
                data = _layer_call(archive.adcr, [data, dictionaries.get(file.path)],
                                   [file.path, "resource " + entry.path, "ADCR"])
            layers = archive_layers(data, file.path + " resource " + entry.path)
            if layers:
                result.append({"path": file.path, "resource": entry.path, "layers": layers})
    return result

def compression_layers(file, maximum_layers = 8):
    """Read successive known compression layers, retaining the final live view.

    The returned headers are evidence for the next explicit container probe,
    not a claim that the final view contains no further format.
    """
    if maximum_layers < 0:
        fail("maximum_layers must not be negative")
    layers = []
    for _ in range(maximum_layers + 1):
        header = file.bytes(0, min(3, file.size))
        if header[:2] not in [b"\x1f\x1e", b"\x1f\x9d", b"\x1f\x8b"] and header != b"BZh":
            return {"data": file, "layers": layers}
        if len(layers) == maximum_layers:
            fail("compression nesting exceeds maximum_layers")
        file = inspect_outer(file)
        layers.append({"size": file.size, "sha256": hex(digest(file)),
                       "header": binary.hex(file.bytes(0, min(16, file.size)))})

def _archive_container(file, name):
    header = file.bytes(0, min(8, file.size))
    if header == b"StuffIt ":
        return archive.stuffit(file)
    if header[:4] == b"\x00\x00\x03\xe7":
        return archive.hunk_objects(file)
    if header[:4] == b"\x00\x00\x03\xf3":
        return archive.hunk_load(file)
    if header[:4] == b"ADCR":
        fail("ADCR requires explicit dictionary selection; decode with archive.adcr before following this payload")
    if header[:4] in [b"PK\x03\x04", b"PK\x05\x06"]:
        return archive.zip(file)
    if header == b"!<arch>\n":
        return archive.ar(file)
    if header[:6] == b"7z\xbc\xaf\x27\x1c":
        return archive.sevenzip(file)
    if header[2:7] in [b"-lh0-", b"-lh5-"]:
        return archive.lha(file)
    if header[:4] == b"kc\x00\x01":
        return archive.tome(file)
    if header[:4] in [b"SIT!", b"ST46", b"ST50", b"ST60", b"ST65", b"STin", b"STi2", b"STi3", b"STi4"] and (
        (file.size >= 14 and file.bytes(10, 4) == b"rLau") or
        any([name.lower().endswith(suffix) for suffix in [".sit", ".sea"]])):
        return archive.stuffit(file)
    if header[:2] == b"\x01\x01" and any([name.lower().endswith(suffix) for suffix in [".cpt", ".sea"]]):
        return archive.compactpro(file)
    if file.size >= 512 and (file.bytes(257, 5) == b"ustar" or
          any([name.lower().endswith(suffix) for suffix in [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.z"]])):
        return archive.tar(file)
    return None

def _layer_call(function, args, ancestry):
    result = testing.attempt(function, args = args)
    if not result.ok:
        fail("nested media", ancestry, result.error)
    return result.value

def archive_layers(file, name = "", maximum_entries = 200000, maximum_depth = 12):
    """Follow known archive/compression layers and return per-layer evidence.

    This bounded probe handles ZIP/JAR, ar, 7z, tar, CompactPro, StuffIt and Tome. Unknown leaves retain
    their signatures for manual inspection; no inference of complete format
    coverage is made. Macintosh archive members have both forks inspected,
    including resource maps and their payloads. Filesystem opening is explicit.
    """
    if maximum_entries < 1 or maximum_depth < 0:
        fail("invalid archive traversal limits")
    queue = [(file, [name])]
    result = []
    for index in range(maximum_entries):
        if index == len(queue):
            return result
        current, ancestry = queue[index]
        if len(ancestry) - 1 > maximum_depth:
            fail("archive nesting exceeds maximum_depth")
        decoded = _layer_call(compression_layers, [current], ancestry)
        current = decoded["data"]
        container = _layer_call(_archive_container, [current, ancestry[-1]], ancestry)
        if container != None:
            children = _layer_call(verify_entries, [container], ancestry)
            layer = {"path": ancestry, "compression": decoded["layers"], "children": children}
            result.append(layer)
            for entry in container.entries:
                if getattr(entry, "entry_type", "file") != "file":
                    continue
                if len(queue) >= maximum_entries:
                    fail("archive traversal exceeds maximum_entries")
                queue.append((getattr(entry, "data", entry), ancestry + [getattr(entry, "path", getattr(entry, "name", ""))]))
                if hasattr(entry, "resource") and entry.resource.size:
                    resource_path = ancestry + [entry.path, "resource"]
                    resource_map = _layer_call(archive.mac_resource, [entry.resource], resource_path)
                    if "resource_forks" not in layer:
                        layer["resource_forks"] = []
                    layer["resource_forks"].append({"path": entry.path,
                        "size": entry.resource.size, "sha256": hex(digest(entry.resource)),
                        "resources": _layer_call(verify_entries, [resource_map], resource_path)})
                    for payload in resource_map.entries:
                        if len(queue) >= maximum_entries:
                            fail("archive traversal exceeds maximum_entries")
                        queue.append((payload.data, resource_path + [payload.path]))
        elif decoded["layers"]:
            result.append({"path": ancestry, "compression": decoded["layers"]})
    return result

def irix_image_names(index, suffix = None):
    """List logical image names from native-parsed IDB subsystem attributes.

    This returns candidates, not an installation selection. A renamed overlay
    can supply its physical suffix (sw/man/books/etc.) to narrow the list.
    """
    result = {}
    for item in index.items:
        for attribute in item.attributes:
            if "(" in attribute:
                continue
            parts = attribute.split(".")
            if len(parts) >= 2 and (suffix == None or parts[1] == suffix):
                result[".".join(parts[:2])] = True
    return sorted(result.keys())

def verify_irix_image(volume, path, image_name = None, index_path = None):
    """Verify an explicitly selected EFS inst image, its compression and ar files.

    Decoding and index validation remain native. image_name is the logical
    IDB image name, which can differ from an overlay's physical filename.
    Defaults suit unsuffixed distributions; callers can select either input
    explicitly without renaming files or changing indexes.
    """
    if index_path == None:
        index_path = path.rsplit(".", 1)[0] + ".idb"
    if image_name == None:
        image_name = path.rsplit("/", 1)[-1]
    image = archive.irix_image(volume.find(path).data, volume.find(index_path).data, image_name)
    files = verify_entries(image)
    nested = []
    for entry in image.entries:
        decoded = compression_layers(entry)
        file = decoded["data"]
        children = verify_entries(archive.ar(file)) if file.size >= 8 and file.bytes(0, 8) == b"!<arch>\n" else []
        if decoded["layers"] or children:
            nested.append({"path": entry.path, "layers": decoded["layers"], "ar": children})
    return {"files": files, "nested": nested}

def verify_irix_volume(volume):
    """Read an EFS distribution and follow each headered inst image's archives.

    Physical overlay names are matched to logical names from the sibling IDB.
    Ambiguity or missing metadata stops the probe; it never selects installation
    variants. Direct-file headers remain available for non-inst layer review.
    Older headerless tape distributions require explicit image selection.
    """
    direct = verify_entries(volume)
    direct_nested = [record for entry in volume.entries if entry.entry_type == "file"
                     for record in archive_layers(entry.data, entry.path)]
    images = []
    for entry in volume.entries:
        if entry.entry_type != "file" or entry.size < 5 or entry.data.bytes(0, 5) != b"im001":
            continue
        index_path = entry.path.rsplit(".", 1)[0] + ".idb"
        index_entry = volume.find(index_path)
        if index_entry == None:
            fail("missing IDB for", entry.path)
        names = irix_image_names(archive.irix_idb(index_entry.data), entry.path.rsplit(".", 1)[-1])
        # A header-only image can intentionally have no rows for its suffix.
        # Let the native reader validate its complete header and empty body;
        # this must not become a fallback for an unindexed nonempty image.
        if not names and entry.size == 13:
            names = [entry.path.rsplit("/", 1)[-1]]
        if len(names) != 1:
            fail("ambiguous logical image name", entry.path, names)
        image = archive.irix_image(entry.data, index_entry.data, names[0])
        files = verify_entries(image)
        nested = [record for member in image.entries for record in archive_layers(member, member.path)]
        images.append({"path": entry.path, "image_name": names[0], "files": files, "nested": nested})
        print(entry.path, len(files), "files,", len(nested), "nested records")
    return {"direct": direct, "direct_nested": direct_nested, "images": images}

def outer_inventory(paths):
    """Inspect every member of each outer wrapper; retain compact evidence only.

    This is deliberately not a recursive-decoding success report. Each member
    still needs its inner filesystem/archive identified and decoded separately.
    """
    result = []
    for name in paths:
        source = open(name)
        decoded = inspect_outer(source)
        entries = decoded.entries if hasattr(decoded, "entries") else [decoded]
        evidence = []
        for entry in entries:
            if getattr(entry, "entry_type", "file") != "file":
                continue
            evidence.append({
                "name": getattr(entry, "path", "decoded"),
                "size": entry.size,
                "signatures": {offset: binary.hex(entry.bytes(offset, 8))
                               for offset in [0, 512, 1024, 9564, 32768]
                               if offset + 8 <= entry.size},
            })
        result.append({"source": name, "members": evidence})
        print(name, "members inspected:", len(evidence))
    return result

def main(args):
    if len(args) != 1:
        fail("usage: media_repl.star ORIGINAL_MEDIA")
    source = open(args[0])
    describe_file = describe
    inspect_signatures = signatures
    list_members = members
    unwrap = inspect_outer
    original_files = inventory_originals
    survey = outer_inventory
    verify_files = verify_entries
    print(describe_file(source))
    print("source, describe_file, inspect_signatures and list_members are available; open layers with archive/filesystem APIs")
    repl()
