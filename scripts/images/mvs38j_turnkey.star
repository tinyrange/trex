"""Pinned MVS 3.8j Turnkey 3 media (public domain MVS, ibiblio mirror).

The zip holds one deflated ISO 9660 image. It is inflated once into memory so
the CKD volumes on it can be read at random; nothing is extracted to the host.
"""

URL = "https://www.ibiblio.org/jmaynard/turnkey-mvs-3.zip"
SIZE = 512052746
SHA256 = "0f2666c43430fe8d67d363d8caf2ad68faa239f48215733b38dd1acc0972074b"

def iso(cache = "local/media-cache", zip_file = None):
    """Returns the Turnkey ISO 9660 filesystem."""
    z = zip_file
    if z == None:
        z = mirror_file([URL], cache = cache, key = "turnkey-mvs-3.zip", sha256 = SHA256, size = SIZE, maximum = 600 << 20, timeout = 1800, retries = 2)
    image = archive.zip(z).files[0]
    return filesystem.iso9660(binary.view(image.bytes()))
