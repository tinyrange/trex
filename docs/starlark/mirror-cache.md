# Mirror-backed files

`mirror_file` downloads one immutable file from interchangeable HTTP(S)
mirrors into a configured local cache and returns the verified cache object as
a normal random-access trex file.

```starlark
package = mirror_file(
    ["https://primary.example/releases/package.bin",
     "https://backup.example/releases/package.bin"],
    cache="/var/cache/trex",
    key="releases/package.bin",
    sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    size=123456,
    maximum=256 * 1024 * 1024,
)
```

`key` is opaque and is hashed before forming a cache path. `sha256` and `size`
are optional verification facts, although immutable release indexes should
provide both when possible. `size=-1` means unknown. `maximum` is always
required to remain positive and bounds both cached and downloaded content.

Downloads resume from a retained partial file when a server supports byte
ranges. Mirrors are tried in order, responses are requested without content
encoding, completed files are checked and atomically renamed into the object
store, and existing objects are revalidated before reuse. The cache backend is
native because it owns HTTP and host paths; returned objects implement the same
portable random-access file interface as `open`.
