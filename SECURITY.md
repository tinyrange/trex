# Security

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's private
vulnerability reporting feature for the repository. Include the affected
component, a minimal reproduction, the impact, and any suggested mitigation.
Do not include secrets, licensed software, installation media, or personal
data in a report.

Please allow the maintainers time to investigate and publish a fix before
disclosing an unpatched vulnerability publicly.

## Research and debugging functionality

trex contains binary inspection, emulation, filesystem, registry, and debugging
functionality intended for interoperability, preservation, testing, and
authorized security research. Use these capabilities only on systems and data
you own or are authorized to examine. Reports of unsafe defaults, unintended
data exposure, or resource-exhaustion paths are welcome through the same
private channel.

## SCS repositories and remote Git

Clone URLs grant network authority, including access to services reachable by
this process. Treat repository bytes, refs, paths and source code as untrusted.
Transport/storage quotas are not a total memory/CPU bound or a process sandbox;
apply external isolation/resource policy when needed. Symlinks and gitlinks do
not automatically grant host path access or recursive network cloning. Only
network Git transports are exposed by the native SCS adapter.

Repository close does not publish live edits. Corrupt or failed-sync stores
require explicit close/reopen/recovery decisions. The append-only format can
retain old, orphaned or unpublished data: deleting a path is not secure erasure,
and exporting a repository file can expose that history. Do not store secrets
in a file intended for distribution. See [SCS limits and recovery](docs/scs.md).
