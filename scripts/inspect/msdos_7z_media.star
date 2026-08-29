"""Inventories MS-DOS floppy images contained in a 7z archive."""

def main(args):
    if len(args) < 1 or len(args) > 2 or (len(args) == 2 and args[1] != "repl"):
        error("Usage: scripts/inspect/msdos_7z_media.star <media.7z> [repl]")
    source = open(args[0])
    sevenzip = archive.sevenzip(source)
    volumes = []
    for entry in sevenzip.entries:
        if entry.entry_type != "file" or not entry.path.lower().endswith(".img"):
            continue
        volume = filesystem.fat(entry)
        volumes.append((entry, volume))
        print("IMAGE", entry.path, entry.size)
        for member in volume["/"].files:
            if member != "/$metadata":
                print(" ", volume[member].size, member)
    if len(args) == 2:
        print("Live values include 'source', 'sevenzip', and 'volumes'. End input to leave the REPL.")
        repl()
    return volumes
