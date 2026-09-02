"""Bounded filesystem and registry snapshots for focused comparisons."""

def _normalize_prefix(prefix):
    return "/" + prefix.replace("\\", "/").strip("/").lower()

def file_snapshot(volume, prefixes, maximum_files = 200000):
    """Returns path and size facts for files below selected volume prefixes."""
    if maximum_files < 1:
        fail("file snapshot limit must be positive")
    normalized = [_normalize_prefix(prefix) for prefix in prefixes]
    output = {}
    for path in volume.files:
        lowered = path.lower()
        if not any([lowered == prefix or lowered.startswith(prefix + "/") for prefix in normalized]):
            continue
        value = volume.find(path)
        if type(value) != "file":
            continue
        if len(output) >= maximum_files:
            fail("file snapshot exceeds its configured limit")
        output[lowered] = {"path": path, "size": value.size}
    return output

def registry_snapshot(
        volume,
        hive_path,
        roots,
        maximum_keys = 65536,
        maximum_values = 262144,
        maximum_value_bytes = 64 << 20):
    """Returns bounded raw registry state below selected roots in one hive."""
    if maximum_keys < 1 or maximum_values < 1 or maximum_value_bytes < 1:
        fail("registry snapshot limits must be positive")
    hive = windows.hive(volume[hive_path])
    pending = []
    for root in roots:
        key = hive.find(root)
        if key != None:
            pending.append(key)
    keys = {}
    values = {}
    total_bytes = 0
    while pending:
        key = pending.pop()
        path = "/" + "/".join(key.path_parts)
        normalized_path = path.lower()
        if normalized_path in keys:
            continue
        if len(keys) >= maximum_keys:
            fail("registry snapshot exceeds its key limit")
        keys[normalized_path] = path
        for name, record in key.value_records.items():
            if len(values) >= maximum_values:
                fail("registry snapshot exceeds its value limit")
            total_bytes += len(record.raw)
            if total_bytes > maximum_value_bytes:
                fail("registry snapshot exceeds its byte limit")
            values[normalized_path + "\x00" + name.lower()] = {
                "key": path,
                "name": name,
                "raw": record.raw,
                "type": record.type,
            }
        pending.extend(key.children)
    return {"keys": keys, "values": values, "value_bytes": total_bytes}

def snapshot_delta(before, after):
    """Returns sorted added, changed, and removed values from keyed snapshots."""
    added = []
    changed = []
    removed = []
    for name, value in after.items():
        previous = before.get(name)
        if previous == None:
            added.append(value)
        elif previous != value:
            changed.append({"after": value, "before": previous})
    for name, value in before.items():
        if name not in after:
            removed.append(value)
    key = lambda item: item.get("key", item.get("path", "")) + "\x00" + item.get("name", "")
    return {
        "added": sorted(added, key = key),
        "changed": sorted(changed, key = lambda item: key(item["after"])),
        "removed": sorted(removed, key = key),
    }
