"""Builds and reads a TAR entirely in memory; no input media is required."""

def main(args):
    if args:
        fail("usage: archive_roundtrip.star")
    source = directory()
    source.write("/hello.txt", b"Hello from trex!\n")
    packed = archive.tar(source)
    encoded = binary.builder(capacity = len(packed))
    encoded.append(packed)
    restored = archive.tar(encoded.file())
    content = restored["/hello.txt"].read()
    if content != "Hello from trex!\n":
        fail("archive round trip changed the payload")
    print(content)
