"""Builds an independently useful ReactOS raw disk from caller-supplied media."""
load("@stdlib//windows/reactos:image.star", "reactos_disk")

def main(args):
    if len(args) != 2:
        fail("Usage: scripts/images/reactos.star <ISO/ZIP/7z> <output.raw>")
    disk = reactos_disk(open(args[0]))
    write(args[1], disk)
    return disk
