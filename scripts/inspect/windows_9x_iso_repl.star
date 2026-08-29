"""Opens Windows 9x ISO and CAB media through trex byte channels."""

def main(args):
    if len(args) < 2:
        fail("usage: scripts/inspect/windows_9x_iso_repl.star IMAGE.iso MEDIA-DIRECTORY [CAB ...]")
    iso = filesystem.iso9660(open(args[0]))
    media_directory = args[1].lower()
    if not media_directory.startswith("/"):
        media_directory = "/" + media_directory
    cabinets = [iso[media_directory + "/" + name.lower()] for name in args[2:]]
    cabinet = archive.cab_set(cabinets) if cabinets else None
    print("iso, media_directory, cabinets, and cabinet are available")
    repl()
