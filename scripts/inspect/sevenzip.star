"""Lists a 7z archive through the native reader and optionally opens a REPL."""

def main(args):
    if len(args) < 1 or len(args) > 2 or (len(args) == 2 and args[1] not in ["repl", "verify"]):
        error("Usage: scripts/inspect/sevenzip.star <archive.7z> [verify|repl]")
    source = open(args[0])
    sevenzip = archive.sevenzip(source)
    for entry in sevenzip.entries:
        print(entry.entry_type, entry.size, entry.path)
        if len(args) == 2 and args[1] == "verify" and entry.entry_type == "file":
            print("  sha256", hex(digest(entry)))
    if len(args) == 2 and args[1] == "repl":
        print("Live values include 'source' and 'sevenzip'. End input to leave the REPL.")
        repl()
    return sevenzip
