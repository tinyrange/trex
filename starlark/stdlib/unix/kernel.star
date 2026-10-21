"""Distribution kernel selection and initramfs module policy; no host modprobe."""

load(":initramfs.star", initramfs = "build")

def x86_header(file):
    """Inspect Linux x86 boot protocol 2.04+; return the borrowed kernel."""
    if file.size < 0x268 or binary.read_u16le(file, 0x1fe) != 0xaa55 or file.slice(0x202, 4).read() != "HdrS":
        fail("kernel: not a Linux x86 boot image")
    protocol = binary.read_u16le(file, 0x206)
    if protocol < 0x0204:
        fail("kernel: unsupported x86 boot protocol")
    setup_sects = binary.read_u8(file, 0x1f1) or 4
    protected_offset = (setup_sects + 1) * 512
    if protected_offset >= file.size:
        fail("kernel: truncated protected-mode payload")
    payload_size = binary.read_u32le(file, 0x1f4) * 16
    if payload_size > file.size - protected_offset:
        fail("kernel: truncated syssize payload")
    return {"file": file, "protocol": protocol, "setup_sects": setup_sects, "protected_offset": protected_offset, "payload_size": payload_size, "loadflags": binary.read_u8(file, 0x211), "xloadflags": binary.read_u16le(file, 0x236) if protocol >= 0x020c else 0, "initrd_addr_max": binary.read_u32le(file, 0x22c) if protocol >= 0x0203 else 0x37ffffff, "cmdline_size": binary.read_u32le(file, 0x238) if protocol >= 0x0206 else 255}

def select(entries, flavor = "virt"):
    """Select one Alpine vmlinuz and its exact lib/modules release directory."""
    by_path = {e["path"]: e for e in entries}
    name = "boot/vmlinuz-" + flavor
    if name not in by_path or by_path[name]["mode"] & 0o170000 != 0o100000:
        fail("kernel: missing " + name)
    releases = {}
    for path in by_path:
        if path.startswith("lib/modules/"):
            components = path.split("/")
            if len(components) >= 3 and components[2].endswith("-" + flavor):
                releases[components[2]] = True
    if len(releases) != 1:
        fail("kernel: missing or ambiguous module release for " + flavor)
    result = x86_header(by_path[name]["data"])
    result["release"] = sorted(releases)[0]
    result["entries"] = entries
    return result

def _module_name(path):
    name = path.rsplit("/", 1)[-1]
    for suffix in [".gz", ".xz", ".zst"]:
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    if not name.endswith(".ko"):
        fail("kernel: invalid module path " + path)
    return name[:-3].replace("-", "_")

def _resolve(name, deps, names, builtin, aliases):
    key = name.replace("-", "_")
    key = aliases.get(key, key).replace("-", "_")
    if key in builtin:
        return None
    path = name if name in deps else names.get(key)
    if path == None:
        fail("kernel: unknown requested module or dependency " + name)
    return path

def modules(kernel, requested, aliases = {}):
    """Resolve modules.dep and softdep in dependency-before-dependent order.

    Only selected softdeps are interpreted; malformed records for selected
    modules fail. Repeated softdep records accumulate. Builtins need no payload.
    Crypto/device aliases are not guessed: aliases pins alias -> module name
    (e.g. crc32c -> crc32c_generic), avoiding hardware-dependent provider choice.
    Unknown dependencies and cycles fail; this does not execute modprobe.
    """
    prefix = "lib/modules/" + kernel["release"] + "/"
    files = {e["path"][len(prefix):]: e for e in kernel["entries"] if e["path"].startswith(prefix)}
    deps, names, builtin = {}, {}, {}
    if "modules.builtin" in files:
        for path in files["modules.builtin"]["data"].read().splitlines():
            if path:
                builtin[_module_name(path)] = True
    if "modules.dep" in files:
        for line in files["modules.dep"]["data"].read().splitlines():
            if not line.strip():
                continue
            pair = line.split(":", 1)
            if len(pair) != 2 or pair[0] not in files or pair[0] in deps:
                fail("kernel: invalid modules.dep record")
            path = pair[0]
            name = _module_name(path)
            if name in names:
                fail("kernel: ambiguous module name " + name)
            names[name] = path
            deps[path] = pair[1].split()
    soft, invalid = {}, {}
    if "modules.softdep" in files:
        for line in files["modules.softdep"]["data"].read().splitlines():
            words = line.split("#", 1)[0].split()
            if not words:
                continue
            if len(words) < 2 or words[0] != "softdep":
                fail("kernel: invalid modules.softdep record")
            key = words[1].replace("-", "_")
            if key not in soft:
                soft[key] = {"pre:": [], "post:": []}
            section = ""
            for word in words[2:]:
                if word in ["pre:", "post:"]:
                    section = word
                elif section:
                    soft[key][section].append(word.replace("-", "_"))
                else:
                    invalid[key] = True
    pending = []
    for name in requested:
        path = _resolve(name, deps, names, builtin, aliases)
        if path != None:
            pending.append(path)
    selected, graph, post_edges = {}, {}, []
    for _ in range(len(deps) + 1):
        if not pending:
            break
        next_pending = []
        for path in pending:
            if path in selected:
                continue
            if path not in deps:
                fail("kernel: missing module dependency " + path)
            selected[path] = True
            key = _module_name(path)
            if key in invalid:
                fail("kernel: invalid soft dependency section for " + key)
            graph[path] = list(deps[path])
            for name in soft.get(key, {}).get("pre:", []):
                target = _resolve(name, deps, names, builtin, aliases)
                if target != None:
                    graph[path].append(target)
            next_pending.extend(graph[path])
            for name in soft.get(key, {}).get("post:", []):
                target = _resolve(name, deps, names, builtin, aliases)
                if target != None:
                    next_pending.append(target)
                    post_edges.append((target, path))
        pending = next_pending
    if pending:
        fail("kernel: module closure bound exceeded")
    for target, path in post_edges:
        graph[target].append(path)
    ordered, emitted = [], {}
    for _ in range(len(selected) + 1):
        progress = False
        for path in sorted(selected):
            if path not in emitted and all([dep in emitted for dep in graph[path]]):
                ordered.append(files[path])
                emitted[path] = True
                progress = True
        if len(emitted) == len(selected):
            return ordered
        if not progress:
            fail("kernel: module dependency cycle")
    fail("kernel: module closure bound exceeded")

def build_initramfs(kernel, userspace, init, requested = [], module_aliases = {}):
    """Build a caller-defined initramfs with a validated module closure.

    Firmware, decompression/insmod, and init policy remain explicit caller
    inputs; resolving dependencies does not execute or autoload the modules.
    """
    chosen = modules(kernel, requested, aliases = module_aliases) if requested else []
    return initramfs(userspace + chosen, init = init)
