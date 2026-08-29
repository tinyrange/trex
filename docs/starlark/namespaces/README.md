# Generated namespace reference

Run `trex -stdlib-docs` to render the complete embedded Starlark module,
native namespace, and value-method reference from the same metadata used by
`help()`.

The generated reference covers `archive`, `binary`, `block`, `clock`, `crypto`,
`debug`, `emulator`, `filesystem`, `firmware`, `json`, `path`, `qemu`, `runtime`, `testing`,
`vmm`, and `windows`, plus top-level runtime operations. CI parses every
embedded module, requires module and public-function docstrings, and verifies
representative native signatures and capability-bearing value methods.

Task-oriented contracts and ownership rules live in the adjacent quickstart,
binary, type, archive, debugging, web, and migration guides.
