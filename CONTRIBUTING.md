# Contributing to trex

Contributions are welcome through the `tinyrange/trex` issue tracker and pull
request workflow.

By submitting a contribution, you agree that it is licensed under the Apache
License 2.0 and that you have the right to submit it. Preserve third-party
copyright and licence notices and identify any external material used to
derive an implementation or test fixture.

Changes must keep format handling inside trex. Do not add production wrappers
around host parsing, mounting, extraction, conversion, debugger, or image
building tools. QEMU may be launched only as the emulator or debugging target.
Core APIs must remain independent of host paths, processes, and sockets.

Before opening a pull request, run:

```sh
go test ./...
go vet ./...
go run ./cmd/trex test.star
```
