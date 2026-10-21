"""In-memory Unix build policy. The engine supplies mechanisms, not a tool image."""

_UTILITIES = ["sh", "cat", "mkdir", "rm", "rmdir", "basename", "dirname", "expr", "ls", "sed", "grep", "egrep", "fgrep", "cp", "mv", "sleep", "diff", "tr", "sort", "touch", "chmod", "awk", "uniq", "wc", "make"]

def mkdirs(files, path, known):
    """Create parents once while constructing a fresh tree."""
    parent = ""
    for part in path.strip("/").split("/"):
        if not part:
            continue
        parent += "/" + part
        if parent not in known:
            files.mkdir(parent)
            known[parent] = True

def install(files, epoch, target = "linux/amd64", arena_size = 32 << 20):
    """Install a selected tool set; return its inspectable path -> action table.

    No hidden marker interpretation: only this table binds executable paths to
    native capabilities. Files remain in the caller-owned Unix namespace.
    """
    files.mkdir("/bin")
    files.mkdir("/tmp")
    commands = {
        "/bin/cc": renvo.compiler(target = target, arena_size = arena_size),
        "/bin/ld": renvo.linker(target = target, arena_size = arena_size),
        "/bin/ar": renvo.archiver(),
        "/bin/ranlib": renvo.archiver(index = True),
        "/bin/date": emulator.shell.date(epoch = epoch),
        "/bin/uname": emulator.shell.uname(),
    }
    for path in commands:
        files.write(path, "# portable command capability\n", mode = 0o755)
    for name in _UTILITIES:
        files.write("/bin/" + name, "#!/bin/sh\nexec " + name + " \"$@\"\n", mode = 0o755)
    headers = renvo.headers()
    known = {}
    for path in headers.files:
        mkdirs(files, path.rsplit("/", 1)[0], known)
        files.write(path, headers.find(path), mode = 0o444)
    return commands

def unpack(files, source):
    """Populate tar entries through portable files, preserving regular-file modes and times."""
    known = {}
    for entry in source.entries:
        if entry.name.startswith("/") or ".." in entry.name.split("/"):
            fail("unsafe archive path: " + entry.name)
        path = entry.path.rstrip("/")
        if entry.entry_type == "directory":
            mkdirs(files, path, known)
        elif entry.entry_type == "file":
            mkdirs(files, path.rsplit("/", 1)[0], known)
            files.write(path, entry, mode = entry.mode & 0o777, mtime = entry.mtime)
        else:
            fail("unsupported archive entry: " + entry.name + " (" + entry.entry_type + ")")

def run(files, commands, source, dir = "/", args = [], name = "build", max_steps = 2000000):
    """Run a build step with an explicit Linux action and C-locale environment."""
    return emulator.shell.run(
        files = files,
        source = source,
        dir = dir,
        args = args,
        name = name,
        env = {"PATH": "/bin:/usr/bin", "SHELL": "/bin/sh", "LC_ALL": "C"},
        commands = commands,
        executable = emulator.linux(max_instructions = 10000000),
        max_steps = max_steps,
        timeout = 120,
    )

def check(result):
    """Require a successful command status and retain bounded failure output."""
    if result.status != 0:
        fail("shell exit " + str(result.status) + "\n" + result.stdout[-4000:] + "\n" + result.stderr[-4000:])
    return result
